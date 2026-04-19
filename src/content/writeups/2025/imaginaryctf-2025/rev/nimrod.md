---
title: "nimrod"
description: "Stripped Nim binary that XORs input with a keystream derived from a hard seed. Extract the keystream at runtime with gdb and XOR out the flag."
event: "ImaginaryCTF 2025"
year: 2025
category: rev
tags: ["nim", "xor", "gdb", "keystream"]
difficulty: easy
date: "2025-07-05"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "ImaginaryCTF_2025/Rev/nimrod"
featured: true
flagsHidden: false
---

> Category: Reversing · Difficulty: Easy · Author: Eth007
>
> *"And Cush begat Nimrod: he began to be a mighty one in the earth."*

## Recon

```text
nimrod: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
        for GNU/Linux 3.2.0, not stripped
```

A Nim-compiled ELF. Running it:

```
$ ./nimrod
Enter the flag:
```

Any random input prints `Incorrect.`.

## Finding the check

In Ghidra, `main` boils down to:

```c
uVar1 = xorEncrypt__nimrod_46(userInput, 0x13371337);
cVar2 = eqeq___nimrod_69(uVar1, encryptedFlag__nimrod_10);
if (cVar2 == '\0') echoBinSafe(..., "Incorrect.");
else              echoBinSafe(..., "Correct!");
```

- Input is XOR-encrypted with seed `0x13371337`.
- Result is compared against a global `encryptedFlag__nimrod_10` in `.rodata`.

Inspecting the global:

```text
0x116e0: len=0x22   cap=...
0x116f0: 28 f8 3e e6 3e 2f 43 0c ...
```

Ciphertext is `0x22` = **34** bytes.

`xorEncrypt__nimrod_46` calls `keystream__nimrod_20(0x13371337, len)` and XORs the result with the input.

## Strategy

No need to re-implement `keystream`. Just let the program run, break at that function, and read the produced keystream straight out of memory — then XOR with the ciphertext.

Nim `seq` layout: `header` at the returned pointer, `data` at `header + 0x10`.

## GDB

```text
$ gdb ./nimrod
(gdb) b keystream__nimrod_20
(gdb) run
Enter the flag:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa        # 34 chars, matches ciphertext
(gdb) p/x $rsi                            # length arg
$1 = 0x22
(gdb) finish                              # $rax = returned seq header
```

Now dump both the global ciphertext and the keystream, XOR them together:

```python
(gdb) python
import gdb
inf = gdb.selected_inferior()
N = 0x22

enc_ptr = int(gdb.parse_and_eval("&encryptedFlag__nimrod_10"))
enc_hdr = int.from_bytes(inf.read_memory(enc_ptr, 8).tobytes(), "little")
enc = inf.read_memory(enc_hdr + 0x10, N).tobytes()

ks_hdr = int(gdb.parse_and_eval("$rax"))
ks = inf.read_memory(ks_hdr + 0x10, N).tobytes()

flag = bytes([e ^ k for e, k in zip(enc, ks)])
print(flag.decode())
end
```

## Flag

```text
ictf{a_mighty_hunter_bfc16cce9dc8}
```
