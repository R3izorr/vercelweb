---
title: "stacked"
description: "Return oriented programming is one of the paradigms of all time. The garbled output is `94 7 d4 64 7 54 63 24 ad 98 45 72 35`"
event: "ImaginaryCTF"
year: 2025
category: rev
tags: ["rev","crypto"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "ImaginaryCTF_2025/Rev/stacked"
featured: false
flagsHidden: false
---

> Imported from [ImaginaryCTF_2025/Rev/stacked](https://github.com/R3izorr/CTF_writeup/tree/main/ImaginaryCTF_2025/Rev/stacked).

# stacked
**Category:** Reversing
**Difficulty:** Hard
**Author:** Minerva-007.

## Description

Return oriented programming is one of the paradigms of all time. The garbled output is `94 7 d4 64 7 54 63 24 ad 98 45 72 35`

## Distribution

- `chal.out`

## Solution
### 1 Understand the program
To understand how the flag was scrambled, we analyze the decompiled main function of the program. The analysis reveals that the program processes the flag one byte at a time using a global variable as an index.

The function uses three core byte operations to transform the data:

off(x): Adds 0x0F to the byte.

eor(x): XORs the byte with 0x69.

rtr(x): Rotates the bits of the byte one position to the right.
```python
byte eor(uchar param_1)

{
  return param_1 ^ 0x69;
}

char inc(uchar param_1)

{
  flag[(int)globalvar] = param_1;
  globalvar = globalvar + '\x01';
  return flag[(int)globalvar];
}

int off(uchar param_1)

{
  return param_1 + 0xf;
}

uint rtr(uchar param_1)

{
  return (uint)param_1 << 7 | (uint)(param_1 >> 1);
}

```

Crucially, after a sequence of these operations is applied to a byte, a function called inc() is called. This function writes the modified byte back into the flag's memory location and advances the index to the next byte. This means the inc() function acts as a delimiter, separating the transformation logic for each individual byte.

### 2 The Exploit Strategy

The key to solving this is recognizing that each of the 13 output bytes is the result of its own unique "pipeline" of operations. Since inc() separates the logic for each byte, we can attack the problem one byte at a time.

The exploit strategy is to:

1. Isolate the Pipelines: Split the program's entire operation chain at each inc() call. This gives us 13 distinct sequences of operations, one for each output byte.

2. Reverse the Logic: To find the original byte, we must undo its transformation pipeline. This is done by applying the inverse of each operation in the reverse order.

### 3 Executing the Exploit
First, we define the inverse for each operation:

off(x) is reversed by subtracting 0x0F.

eor(x) is its own inverse (XORing twice returns the original value).

rtr(x) (rotate right) is reversed by a rotate left operation.

We then apply this logic. For each of the 13 garbled bytes, we take its corresponding pipeline, reverse the order of operations, and replace each operation with its inverse. Applying this new inverse pipeline to the garbled byte reveals the original byte.

## Exploit – Python Script

```python
garbled = bytes.fromhex("94 07 d4 64 07 54 63 24 ad 98 45 72 35")

def eor(x): return x ^ 0x69
def off(x): return (x + 0x0F) & 0xFF
def rtr(x): return ((x >> 1) | ((x & 1) << 7)) & 0xFF
def rol(x): return ((x << 1) | (x >> 7)) & 0xFF
def off_inv(x): return (x - 0x0F) & 0xFF

pipelines = [
    ["off","eor","rtr"],
    ["eor"],
    ["rtr"],
    ["rtr","rtr","eor"],
    ["eor"],
    ["rtr","off","rtr"],
    ["rtr","eor","rtr"],
    ["rtr","rtr","eor"],
    ["rtr","off","eor"],
    ["eor","rtr"],
    ["off","off","rtr"],
    ["rtr","rtr","eor"],
    ["eor","off","rtr"],
]

op  = {"eor":eor, "off":off, "rtr":rtr}
inv = {"eor":eor, "off":off_inv, "rtr":rol}

# Invert each pipeline
orig = bytearray()
for b, pipe in zip(garbled, pipelines):
    x = b
    for step in reversed(pipe):
        x = inv[step](x)
    orig.append(x)

print("orig hex:", orig.hex())
print("orig txt:", orig.decode('latin1'))
```
```
orig hex: 316e35346e33af356b316c6c32
orig txt: 1n54n3¯5k1ll2
```

### The output is: ictf{1n54n3_5k1ll2}



