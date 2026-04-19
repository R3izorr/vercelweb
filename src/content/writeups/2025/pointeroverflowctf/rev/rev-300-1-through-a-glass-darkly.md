---
title: "POCTF — Through a Glass Darkly (rev300-1) — Write-up"
description: "Goal: recover the correct flag string."
event: "Pointeroverflowctf"
year: 2025
category: rev
tags: ["rev"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "pointeroverflowctf/rev/Rev 300-1 Through a Glass Darkly"
featured: false
flagsHidden: false
---

> Imported from [pointeroverflowctf/rev/Rev 300-1 Through a Glass Darkly](https://github.com/R3izorr/CTF_writeup/tree/main/pointeroverflowctf/rev/Rev%20300-1%20Through%20a%20Glass%20Darkly).

# POCTF — Through a Glass Darkly (rev300-1) — Write-up

## Challenge
You’re given a webpage that asks for a flag. The page loads `verify.js` and a `verifier.wasm`. There are **no network requests**; all verification happens client-side inside the WebAssembly module.

Goal: recover the correct flag string.

---

## Recon

- `verify.js` is a standard **Emscripten** wrapper. The interesting export is mapped to a function we’ll call `verify` (in exports list it appears as `"c"`).
- Disassembling the wasm (`wasm2wat verifier.wasm -o verifier.wat`) reveals two data segments and an exported function `c` that checks the input.

### Data segments (from WAT)

```wat
(data (i32.const 1024) "through_a_glass_darkly")
(data (i32.const 1056) "CU\84$\f7\5c\90\e9\a8\cd&\bc\07J\0e\a8\e5ZH\e2\baw}n\11\86\be")
At 0x400 (1024): ASCII "through_a_glass_darkly" (length 22).

At 0x420 (1056): a 27-byte blob (escaped in WAT). Decoded bytes:

mathematica
Sao chép mã
43 55 84 24 F7 5C 90 E9 A8 CD 26 BC 07 4A 0E A8 E5 5A 48 E2 BA 77 7D 6E 11 86 BE
Verify function analysis
The exported function (export "c") validates exactly 27 bytes of input. For each index i ∈ [0..26], it computes a target byte and compares against the user input:

Key operations (simplified from the WAT):

It reads blob[i] from the data segment at 1056.

It uses a value from the "through_a_glass_darkly" phrase, wrapped every 22 chars:

phrase[i % 22]

It combines them with a linear term and a keyed rotation:

Derived formula
Let:

phrase = b"through_a_glass_darkly" (22 bytes)

blob = bytes at 1056 (27 bytes, hex above)

All ops are byte-wise (& 0xFF).

Then for each i:

makefile
Sao chép mã
A  = (blob[i] - 17*i + 123) & 0xFF
P  = phrase[i % 22]
v2 = P ^ ((73*i + 19) & 0xFF)

# 8-bit rotate defined via shifts (from the WAT):
r      = i % 7
left   = (r + 1) & 7
right  = (r ^ 7) & 7
R      = ((v2 << left) & 0xFF) | ((v2 & 0xFF) >> right)

expected[i] = A ^ R
The verify function returns success iff input[i] == expected[i] for all 27 bytes.

Solver (Python)
python
Sao chép mã
phrase = b"through_a_glass_darkly"
blob = bytes.fromhex(
    "43 55 84 24 F7 5C 90 E9 A8 CD 26 BC 07 4A 0E A8 E5 5A 48 E2 BA 77 7D 6E 11 86 BE"
)

def solve():
    out = []
    for i in range(27):
        A  = (blob[i] + (-17)*i + 123) & 0xFF
        P  = phrase[i if i < 22 else i-22]
        v2 = P ^ ((73*i + 19) & 0xFF)
        r  = i % 7
        left  = (r + 1) & 7
        right = (r ^ 7) & 7
        R = ((v2 << left) & 0xFF) | ((v2 & 0xFF) >> right)  # rotate 8-bit
        out.append(A ^ R)
    return bytes(out)

print(solve().decode())
Output

Sao chép mã
poctf{uwsp_715_0nly_4_64m3}
Flag
poctf{uwsp_715_0nly_4_64m3}

Notes
The first 22 characters of the "phrase" cycle through the input, providing a short repeating key.

The bit rotation is index-dependent (i % 7) and implemented via shifts and OR, not a built-in rotate.

No brute force or dynamic hooking is required; static analysis of the WAT is sufficient.
