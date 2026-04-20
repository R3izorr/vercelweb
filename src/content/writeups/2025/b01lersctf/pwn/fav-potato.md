---
title: "Favorite Potato — REV CTF Writeup"
description: "**Flag:** `bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}`"
event: "B01lersctf"
year: 2025
category: pwn
tags: ["pwn","crypto"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "b01lersctf/pwn/fav_potato"
featured: false
flagsHidden: false
---

> Imported from [b01lersctf/pwn/fav_potato](https://github.com/R3izorr/CTF_writeup/tree/main/b01lersctf/pwn/fav_potato).

# Favorite Potato — REV CTF Writeup

```
$ ncat --ssl favorite-potato.opus4-7.b01le.rs 8443
```

**Flag:** `bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}`

---

## 1. Challenge files

| File | Purpose |
|------|---------|
| [favorite_potato.py](favorite_potato.py) | Server harness (random (A,X,Y), run binary, print result) |
| [test.bin](test.bin) | 9-byte warm-up binary — confirms the I/O contract |
| [code-10k.bin](code-10k.bin) | The real ~5.82 MB 6502 program we must invert |
| [screenshot.png](screenshot.png) | A C64 BASIC listing of the test harness |

The server harness in plain English:

```
> R
for i in 1..20:
    pick random (A0, X0, Y0) ∈ [0,255]³
    (A, X, Y) = run_c64(code.bin, A0, X0, Y0)
    print  "Final output #i: A=.. X=.. Y=.."
for i in 1..20:
    read  guess_A, guess_X, guess_Y   # must equal (A0, X0, Y0)
if all correct: print flag
```

So given 20 outputs we must **invert** the binary and recover the inputs.

---

## 2. Reading the hints

The author left several hints:

> *"Yay, at last — I managed to upgrade my old potato. Now I can run suuuuper
> loooong binaries that nobody can reverse (RAM is still 64k but I only need a
> minimal amount)."*

Three signals jump out:

1. **"super long binary"** — code-10k.bin is 5.82 MB. A stock C64 can't even load that
   (64 KB total RAM). So `run_c64` is a *custom* 6502 emulator where the code
   lives in an extended code space; data RAM stays a normal 64 KB.
2. **"RAM still 64k but I only need a minimal amount"** — the code barely touches
   memory. It must operate almost entirely on registers + stack.
3. **Screenshot of the BASIC harness** — shows `POKE 780,A / POKE 781,X /
   POKE 782,Y / SYS <addr> / A=PEEK(780) / ...` — the standard "pass A/X/Y
   through zero-page mirrors of the CPU registers on KERNAL SYS" idiom. So the
   binary is a pure function `(A,X,Y) → (A',X',Y')` over 24 bits.
4. **The flag itself** (found afterwards): *"Never understood why we need TSX
   and TXS until now"* — a giant hint that the program uses the stack-pointer
   transfer instructions as a clever trick for swaps / "peek without pop".

From these it's a strong bet that the 5.82 MB is a **macro-compiled sequence
of reversible 6502 primitives** on (A,X,Y). If every primitive is individually
invertible, we invert the whole program by reversing the list and inverting
each step — no 2²⁴ brute force needed.

---

## 3. Confirming the I/O contract with `test.bin`

`test.bin` is 9 bytes: `08 18 69 2A CA C8 C8 28 60`

Disassembled:

```
PHP            ; save flags
CLC
ADC #$2A       ; A += 0x2A (42)
DEX            ; X -= 1
INY ; INY      ; Y += 2
PLP            ; restore flags
RTS
```

So `(A',X',Y') = (A+42, X-1, Y+2) mod 256`. The PHP/PLP wrapper preserves the
flags across the body — a recurring pattern throughout `code-10k.bin`.

---

## 4. First look at `code-10k.bin`

Writing a tiny 6502 disassembler over the first 200 bytes reveals *highly
regular* sequences. Example — bytes `0x00..0x1C`:

```
; "A += 0xa3"                         5 bytes
00:  PHP ; CLC ; ADC #$a3 ; PLP

; "swap A ↔ X"                        14 bytes   (uses TSX/INX/TXS trick)
05:  PHP ; PHA ; TXA ; PHA
     TSX ; INX ; TXS              ; S += 1: "peek then skip"
     PLA                          ; A = second-from-top pushed value (= A₀)
     DEX ; TXS                    ; unwind
     TAX ; PLA ; PLP ; PLP        ; restore X, A, flags

; "X += A"                            10 bytes
13:  PHP ; PHA
     .loop: INX ; SEC ; SBC #$01 ; BNE .loop
     PLA ; PLP
```

After tracing every sub-block, every single pattern turned out to **preserve
all registers it isn't explicitly modifying** and to be **invertible**.

### 4.1 The TSX/INX/TXS trick

6502 has no `A ↔ X` exchange. The classic way costs an extra scratch
byte. The author does it with a stack-pointer dance:

```
PHA          ; push A₀   (top = A₀)
TXA ; PHA    ; push X₀   (top = X₀, below = A₀)
TSX ; INX ; TXS   ; S += 1   → top is "what was below" (= A₀) without clobbering slots
PLA          ; A ← A₀      ← reads below-top because of the +1
DEX ; TXS    ; S -= 1   → top is X₀ again
TAX          ; X ← A (= A₀)
PLA          ; A ← top (= X₀)
```

This is *exactly* what the flag is about: **`TSX` followed by `TXS` lets you
peek under the stack top without losing it**.

---

## 5. Macro catalog

After exhaustive tracing, the binary is composed of exactly **nine** macro
types. Each has a unique, fixed byte signature — parameters (`k`, `N`) appear
at fixed offsets inside a macro.

| Macro | Bytes | Signature (hex) | Effect on (A,X,Y,flags) |
|-------|:-----:|-----------------|-------------------------|
| `A_ADD(k)`   | 5  | `08 18 69 kk 28` | A = (A + k) mod 256 |
| `A_XOR(k)`   | 4  | `08 49 kk 28` | A = A ⊕ k |
| `SWAP_AX`    | 14 | `08 48 8A 48 BA E8 9A 68 CA 9A AA 68 28 28` | A ↔ X |
| `SWAP_AY`    | 20 | `08 48 98 48 8A 48 BA E8 E8 9A 68 A8 CA CA 9A 68 AA 68 28 28` | A ↔ Y |
| `SWAP_XY`    | 10 | `08 48 8A 48 98 AA 68 A8 68 28` | X ↔ Y |
| `X_ADD_A`    | 10 | `08 48 E8 38 E9 01 D0 FA 68 28` | X = (X + A) mod 256 |
| `Y_ADD_A`    | 10 | `08 48 C8 38 E9 01 D0 FA 68 28` | Y = (Y + A) mod 256 |
| `ROR_A_N(N)` | 26 | `08 48 8A 48 BA E8 9A 68 A2 NN 4A 90 02 09 80 CA D0 F8 48 BA CA 9A 68 AA 68 28` | A = ror8(A, N mod 8) |
| `A_XOR_Y`    | 90 | unrolled 8-bit XOR (see below) | A ^= Y, **Y preserved** |

Plus a terminating `60` (RTS) at the very end.

### 5.1 `A_XOR_Y` in detail

The pattern swaps A↔Y on entry, runs an 8-iteration unrolled loop of:

```
LSR A              ; bit i of original A into C
BCC +6             ; skip if 0
TAY ; PLA ; EOR #(1<<i) ; PHA ; TYA
```

which XORs the bit back into the *stack slot* holding the swapped-away value,
then swaps back. Net effect: `A = A ⊕ Y`, with Y and X untouched.

### 5.2 Op-count census (from `scan.py`)

```
SWAP_AY  : 60000
SWAP_AX  : 30000
SWAP_XY  : 30000
A_XOR_Y  : 30000
A_XOR    : 30000
ROR_A_N  : 30000
A_ADD    : 20000
X_ADD_A  : 10000
Y_ADD_A  : 10000
──────── total: 250 000 macros
```

Those round numbers tell you the server-side challenge was generator-produced.

---

## 6. Solve strategy

All 9 macros are individually invertible:

| Forward     | Inverse                |
|-------------|------------------------|
| `A_ADD(k)`  | `A_SUB(k)`             |
| `A_XOR(k)`  | `A_XOR(k)` (self)      |
| `SWAP_AX`   | self                   |
| `SWAP_AY`   | self                   |
| `SWAP_XY`   | self                   |
| `X_ADD_A`   | `X_SUB_A`              |
| `Y_ADD_A`   | `Y_SUB_A`              |
| `ROR_A_N(N)`| `ROL_A_N(N)`           |
| `A_XOR_Y`   | self (Y is preserved)  |

So the full inverse program is simply the **reversed** list of forward ops
with each op inverted. One run through the inverse on each of the 20 server
outputs yields the 20 corresponding random inputs. No search required.

Pipeline:

```
code-10k.bin ──▶ scan.py  ──▶  [250k (op, param) tuples]
                                 │
                                 ├──▶ hl.py :: forward()  ← verified vs. 6502 emu
                                 │
                                 └──▶ solve_local.py :: INVERSE_PROG
                                                         │
                                                         ▼
server outputs ──▶ solve.py ──▶ inverted inputs ──▶ FLAG
```

Timings:
- Python 6502 emulation of one call: ~13 s (32 M cycles)
- Macro-reduced forward evaluator: ~20 ms
- Inverse applied to 20 server outputs: **instant**

---

## 7. Scripts

Four files live in `/tmp/potato/`. They import each other; run `solve.py` last.

### 7.1 `emu.py` — minimal 6502 emulator (used only for verification)

Covers every opcode the binary actually uses. Runs `test.bin` correctly, and
produces the same (A',X',Y') as `code-10k.bin` for all inputs. Key details:
extend memory past 64 KB for the large code image, and push a sentinel return
address so the program's final `RTS` returns to a known "end" PC.

### 7.2 `scan.py` — pattern recognizer

```python
import re
data = open('code-10k.bin','rb').read()

MACROS = [
    (rb'\x08\x18\x69(.)\x28',                                          'A_ADD',   lambda m: m.group(1)[0]),
    (rb'\x08\x49(.)\x28',                                              'A_XOR',   lambda m: m.group(1)[0]),
    (rb'\x08\x48\x8A\x48\xBA\xE8\x9A\x68\xCA\x9A\xAA\x68\x28\x28',     'SWAP_AX', lambda m: 0),
    (rb'\x08\x48\x98\x48\x8A\x48\xBA\xE8\xE8\x9A\x68\xA8\xCA\xCA\x9A\x68\xAA\x68\x28\x28',
                                                                       'SWAP_AY', lambda m: 0),
    (rb'\x08\x48\x8A\x48\x98\xAA\x68\xA8\x68\x28',                     'SWAP_XY', lambda m: 0),
    (rb'\x08\x48\xE8\x38\xE9\x01\xD0\xFA\x68\x28',                     'X_ADD_A', lambda m: 0),
    (rb'\x08\x48\xC8\x38\xE9\x01\xD0\xFA\x68\x28',                     'Y_ADD_A', lambda m: 0),
    (rb'\x08\x48\x8A\x48\xBA\xE8\x9A\x68\xA2(.)\x4A\x90\x02\x09\x80'
     rb'\xCA\xD0\xF8\x48\xBA\xCA\x9A\x68\xAA\x68\x28',                 'ROR_A_N', lambda m: m.group(1)[0]),
    (rb'\x08\x48\x98\x48\x8A\x48\xBA\xE8\x9A\x68'
     rb'\x4A\x90\x06\xA8\x68\x49\x01\x48\x98'
     rb'\x4A\x90\x06\xA8\x68\x49\x02\x48\x98'
     rb'\x4A\x90\x06\xA8\x68\x49\x04\x48\x98'
     rb'\x4A\x90\x06\xA8\x68\x49\x08\x48\x98'
     rb'\x4A\x90\x06\xA8\x68\x49\x10\x48\x98'
     rb'\x4A\x90\x06\xA8\x68\x49\x20\x48\x98'
     rb'\x4A\x90\x06\xA8\x68\x49\x40\x48\x98'
     rb'\x4A\x90\x06\xA8\x68\x49\x80\x48\x98'
     rb'\xCA\x9A\x68\xAA\x68\xA8\x68\x28',                             'A_XOR_Y', lambda m: 0),
]
COMPILED = [(re.compile(p, re.DOTALL), n, e) for p,n,e in MACROS]
# re.DOTALL is essential: parameter byte 0x0A would otherwise not match '.'

def scan(data):
    pos, ops = 0, []
    while pos < len(data):
        for pat, name, ext in COMPILED:
            m = pat.match(data, pos)
            if m:
                ops.append((name, ext(m)))
                pos = m.end(); break
        else:
            break   # stop at first unrecognized byte (the final RTS)
    return ops, pos
```

Running it on `code-10k.bin` consumes all 5 820 000 bytes of macros and stops
on the final `0x60` (RTS). 250 000 ops total.

### 7.3 `hl.py` — high-level forward evaluator

```python
def rot_right(v, n): n &= 7; return ((v>>n)|(v<<(8-n)))&0xFF if n else v
def rot_left (v, n): n &= 7; return ((v<<n)|(v>>(8-n)))&0xFF if n else v

def forward(A, X, Y, prog):
    for name, p in prog:
        if   name=='A_ADD':   A = (A + p) & 0xFF
        elif name=='A_SUB':   A = (A - p) & 0xFF
        elif name=='A_XOR':   A ^= p
        elif name=='SWAP_AX': A, X = X, A
        elif name=='SWAP_AY': A, Y = Y, A
        elif name=='SWAP_XY': X, Y = Y, X
        elif name=='X_ADD_A': X = (X + A) & 0xFF
        elif name=='X_SUB_A': X = (X - A) & 0xFF
        elif name=='Y_ADD_A': Y = (Y + A) & 0xFF
        elif name=='Y_SUB_A': Y = (Y - A) & 0xFF
        elif name=='ROR_A_N': A = rot_right(A, p)
        elif name=='ROL_A_N': A = rot_left (A, p)
        elif name=='A_XOR_Y': A ^= Y
    return A, X, Y
```

Validated against the full 6502 emulator on six random inputs: all matched.

### 7.4 `solve_local.py` — build & verify the inverse

```python
import random
INVERT = {
    'A_ADD':'A_SUB','A_SUB':'A_ADD', 'A_XOR':'A_XOR',
    'SWAP_AX':'SWAP_AX','SWAP_AY':'SWAP_AY','SWAP_XY':'SWAP_XY',
    'X_ADD_A':'X_SUB_A','X_SUB_A':'X_ADD_A',
    'Y_ADD_A':'Y_SUB_A','Y_SUB_A':'Y_ADD_A',
    'ROR_A_N':'ROL_A_N','ROL_A_N':'ROR_A_N',
    'A_XOR_Y':'A_XOR_Y',
}
INVERSE_PROG = [(INVERT[n], p) for (n, p) in reversed(PROG)]

# round-trip sanity check
random.seed(42)
for _ in range(100):
    a,x,y = [random.randint(0,255) for _ in range(3)]
    fa,fx,fy = forward(a,x,y, PROG)
    ra,rx,ry = forward(fa,fx,fy, INVERSE_PROG)
    assert (a,x,y) == (ra,rx,ry)
```

100/100 round-trips: ✓

### 7.5 `solve.py` — end-to-end network solve

```python
import socket, ssl, re, sys, time
from solve_local import INVERSE_PROG
from hl       import forward

HOST, PORT = "favorite-potato.opus4-7.b01le.rs", 8443

def invert(A,X,Y): return forward(A, X, Y, INVERSE_PROG)

def recv_until(s, needle, buf, timeout=30):
    s.settimeout(3); deadline = time.time()+timeout
    while needle not in buf:
        if time.time() > deadline: raise TimeoutError
        try: chunk = s.recv(65536)
        except socket.timeout: continue
        if not chunk: break
        buf += chunk; sys.stdout.write(chunk.decode('latin-1','replace')); sys.stdout.flush()
    return buf

ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
ss  = ctx.wrap_socket(socket.create_connection((HOST,PORT)), server_hostname=HOST)

buf = recv_until(ss, b"> ", b"")
ss.sendall(b"R\n")
buf = recv_until(ss, b"Now tell me all 20 inputs:", buf)

outputs = [(int(m[1]), int(m[2]), int(m[3]), int(m[4]))
           for m in re.finditer(rb"Final output #(\d+): A=(\d+) X=(\d+) Y=(\d+)", buf)]
assert len(outputs) == 20

payload = b""
for i, A, X, Y in outputs:
    a, x, y = invert(A, X, Y)
    payload += f"{a},{x},{y}\n".encode()
ss.sendall(payload)

ss.settimeout(10)
while True:
    try: chunk = ss.recv(65536)
    except socket.timeout: break
    if not chunk: break
    sys.stdout.write(chunk.decode('latin-1','replace')); sys.stdout.flush()
```

---

## 8. Running the solve

```
$ cd /tmp/potato
$ python3 solve.py
... (banner)
> Here are the results of 20 evaluations:
Final output  #1: A=249 X=242 Y=63
...
Now tell me all 20 inputs:
Input #1  - A,X,Y: ... Input #20 - A,X,Y:
Correct!
Here is your flag: bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}
```

---

## 9. Takeaways

- **File size ≠ difficulty.** 5.82 MB of 6502 collapses to 250 k reversible
  primitives, which collapse to a one-liner inverse.
- **Recognize the shape, not the bytes.** A 20 ms `forward()` is enough if you
  can identify the macros. Full emulation (~13 s) is only needed to validate
  that forward.
- **Each `PHP … PLP` pair is a flag-safe scope.** In this challenge every macro
  is wrapped in exactly one. That alone is a huge structural hint.
- **`TSX / TXS` aren't just for OS code.** Used as a "peek under the top of
  stack" trick, they turn 6502 register swaps into tidy balanced snippets —
  exactly the insight the flag is celebrating.

