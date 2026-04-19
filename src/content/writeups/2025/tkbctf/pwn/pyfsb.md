---
title: "Very Simple FSB Writeup"
description: "- Name: `Very Simple FSB` - Category: `pwn` - Remote: `35.194.108.145:13840`"
event: "TKB CTF"
year: 2025
category: pwn
tags: ["pwn","format-string"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "tkbctf/pyfsb/pyfsb"
featured: false
flagsHidden: false
---

> Imported from [tkbctf/pyfsb/pyfsb](https://github.com/R3izorr/CTF_writeup/tree/main/tkbctf/pyfsb/pyfsb).

# Very Simple FSB Writeup

## Challenge

- Name: `Very Simple FSB`
- Category: `pwn`
- Remote: `35.194.108.145:13840`

## Files

- `fsb.c`
- `fsb.cpython-312-x86_64-linux-gnu.so`
- `server.py`
- `solve.py`

## Root Cause

The bug is not a normal `printf`-style format string bug. The vulnerable code is:

```c
static PyObject *pwn(PyObject *self, PyObject *args) {
  char request[0x100];
  if (fgets(request, 0x100, stdin) == NULL)
    return NULL;
  request[strcspn(request, "\n")] = 0;

  return Py_BuildValue(request);
}
```

`Py_BuildValue()` expects a format string plus matching variadic arguments. Here, the attacker fully controls the format string, but the function is called with no extra arguments at all:

```c
Py_BuildValue(request);
```

So every format unit after the first parameter makes `Py_BuildValue()` read fake arguments out of whatever register and stack state already exists.

## Important Observation

On amd64 SysV:

- the first 5 fake variadic arguments come from `rsi`, `rdx`, `rcx`, `r8`, and `r9`
- after that, `Py_BuildValue()` starts reading 8-byte values from the caller stack

At the call site, the request buffer itself lives on the stack. That means after consuming the register-backed fake args, later fake args come directly from attacker-controlled bytes inside `request`.

This gives us:

- a stack leak primitive with integer format units like `K`
- a controlled call primitive with `O&`

## Leak Stage

Sending:

```python
b"(" + b"K" * 40 + b")\\n"
```

prints a tuple of 64-bit values.

Some of those leaked values are stack pointers inside the current frame. In the shipped environment, these all recover the same request-buffer address:

- `slot18 - 0xc8`
- `slot26 - 0xe0`
- `slot34 - 0x130`

The solver uses all three as a sanity check.

## Code Execution Stage

The nicest format unit here is `O&`.

`Py_BuildValue("O&", converter, arg)` calls:

```c
converter(arg)
```

and expects the return value to be a `PyObject *`.

We abuse that by calling `PyRun_SimpleString`, which is present in the main Python binary and is at a fixed address because `/usr/bin/python3` is not PIE in this environment:

```python
PYRUN_SIMPLESTRING = 0x4B5892
```

Its prototype is:

```c
int PyRun_SimpleString(const char *command);
```

That return type is wrong for `O&`, but it is still good enough for exploitation:

- our Python code executes
- it prints the flag
- the service then errors because the `int` return value is treated like a `PyObject *`

That final crash is expected and harmless.

## Final Payload Layout

We first consume 7 fake args safely with `K`, then use `O&` so the converter pointer and its argument come from controlled stack slots:

```python
EXEC_FMT = b"KKKKKKKO&      " + b"\\x00"
```

Payload layout in memory:

```text
[ format string ][ p64(PyRun_SimpleString) ][ p64(command_addr) ][ command ][ NUL ][ newline ]
```

The command used is:

```python
b"import glob;print(open(glob.glob('/app/flag-*')[0]).read())"
```

## Exploit Flow

1. Connect to the service.
2. Send the `K` leak payload.
3. Parse the tuple and recover the current `request` stack address.
4. Send the `O&` payload with:
   - converter = `PyRun_SimpleString`
   - argument = pointer to our Python command string inside `request`
5. Read the flag from stdout.

## Solver

Run:

```bash
python3 solve.py
```

The included solver:

- leaks stack values
- reconstructs the request-buffer address
- builds the final binary payload
- prints the remote response

## Flag

```text
tkbctf{n3w_463_0f_f5b-805a5dd8f03016053bf77528ec56265b7c593e6612d54a458258e5e2eba51ab0}
```

