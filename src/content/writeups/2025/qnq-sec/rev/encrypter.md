---
title: "encrypter"
description: "AES-256-CBC with the key produced by embedded shellcode. Break on EVP_EncryptInit_ex at runtime, read the key/IV out of registers, decrypt offline."
event: "QnQSec"
year: 2025
category: rev
tags: ["aes", "openssl", "gdb", "shellcode"]
difficulty: medium
date: "2025-09-20"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "QnQSec/Rev/Encrypter"
featured: false
flagsHidden: false
---

> Reversing + Crypto · Difficulty: Medium

## Given

- `encrypter` — ELF 64-bit, not stripped.
- `flag.enc` — encrypted blob.

```
$ strings encrypter | grep flag
flag.enc
flag.txt
Encrypted -> flag.enc
```

So the binary reads `flag.txt`, encrypts, writes `flag.enc`.

## Static: what does it do?

`main` (reconstructed):

```c
char local_48[16];
undefined8 local_38; undefined8 local_30; undefined8 local_28; undefined8 local_20;

memset(local_48, 0, 16);
strncpy(local_48, "1337", 0x10);

memset(&local_38, 0, 0x20);
iVar1 = call_embedded_shellcode(&local_38, 0x20);

if (iVar1 == 0) { /* fail */ }
else if (strcmp(argv[1], "encrypt") == 0) {
    encrypt_file("flag.txt", "flag.enc", &local_38, local_48);
}
```

- IV = `"1337"` zero-padded to 16 bytes.
- 32-byte key is generated at runtime by `call_embedded_shellcode` — the shellcode is copied to an RWX `mmap` region and invoked.
- `do_crypto` uses `EVP_aes_256_cbc()`. Standard OpenSSL AES-256-CBC.

Rebuilding the shellcode logic would be tedious. Much cleaner: let the program run, catch the key right before it goes into OpenSSL.

## Dynamic: extract key and IV at runtime

Argument ABI for `EVP_EncryptInit_ex(ctx, cipher, engine, key, iv)`:

- 4th arg → `rcx` → key pointer
- 5th arg → `r8`  → iv pointer

The program only proceeds if it can open `flag.txt`:

```
echo -n "x" > flag.txt
```

Then in gdb:

```bash
gdb -q ./encrypter
set breakpoint pending on
set stop-on-solib-events 1
set disable-randomization on
break EVP_EncryptInit_ex
run encrypt
```

Step into the real function (past the PLT stub) and dump:

```bash
x/32xb $rcx    # key
x/16xb $r8     # iv
```

Result:

```
key: 74 68 31 5f 31 5f 73 5f 74 68 33 5f 76 61 6c 75
     33 5f 30 66 5f 6b 33 79 00 00 00 00 00 00 00 00
  → "th1_1s_th3_valu3_0f_k3y" + zero padding

iv:  31 33 33 37 00 00 00 00 00 00 00 00 00 00 00 00
  → "1337" + zero padding
```

## Decrypt

OpenSSL CLI:

```bash
KEYHEX="7468315f315f735f7468335f76616c75335f30665f6b3379000000000000000000000000000000"
IVHEX="31333337000000000000000000000000"

openssl enc -aes-256-cbc -d \
  -in flag.enc -out flag.txt \
  -K "$KEYHEX" -iv "$IVHEX"
```

Or Python:

```python
from Crypto.Cipher import AES
from pathlib import Path

key = b"th1_1s_th3_valu3_0f_k3y" + b"\x00" * (32 - len("th1_1s_th3_valu3_0f_k3y"))
iv  = b"1337" + b"\x00" * 12

ct = Path("flag.enc").read_bytes()
pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

n = pt[-1]
if 1 <= n <= 16 and pt.endswith(bytes([n]) * n):
    pt = pt[:-n]

print(pt.decode("utf-8", errors="replace"))
```

## Flag

```text
QnQSec{a_s1mpl3_fil3_3ncrypt3d_r3v3rs3}
```
