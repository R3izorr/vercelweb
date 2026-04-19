---
title: "weird-app"
description: "Android APK that applies a position-dependent substitution over letters/digits/specials. Invert it in Python."
event: "ImaginaryCTF 2025"
year: 2025
category: rev
tags: ["android", "apk", "jadx", "substitution"]
difficulty: easy
points: 40
date: "2025-07-05"
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "ImaginaryCTF_2025/Rev/weird_app"
featured: false
flagsHidden: false
---

> Category: Reversing · Difficulty: 4/10 · Author: cleverbear57

## Problem

The APK applies a position-dependent substitution to every character of the input flag:

- letters `a-z`: shift `+i (mod 26)`
- digits `0-9`: shift `+2*i (mod 10)`
- specials `!@#$%^&*()_+{}[]|`: shift `+i*i (mod 18)`

The activity displays the transformed result. Goal: invert the transform.

## Tools

- `jadx-gui` for the APK.
- Python 3.

## Finding the transform

In `MainActivityKt.transformFlag`:

```kotlin
public static final String transformFlag(String flag) {
    String res = "";
    int length = flag.length();
    for (int i = 0; i < length; i++) {
        for (int c = 0; c < 26; c++)
            if ("abcdefghijklmnopqrstuvwxyz".charAt(c) == flag.charAt(i))
                res += "abcdefghijklmnopqrstuvwxyz".charAt((c + i) % 26);
        for (int c = 0; c < 10; c++)
            if ("0123456789".charAt(c) == flag.charAt(i))
                res += "0123456789".charAt(((i * 2) + c) % 10);
        for (int c = 0; c < 18; c++)
            if ("!@#$%^&*()_+{}[]|".charAt(c) == flag.charAt(i))
                res += "!@#$%^&*()_+{}[]|".charAt(((i * i) + c) % 18);
    }
    return res;
}
```

Transformed flag from a string constant in the same class:

```
idvi+1{s6e3{)arg2zv[moqa905+
```

## Inverting

```python
abc = "abcdefghijklmnopqrstuvwxyz"
dig = "0123456789"
spec = "!@#$%^&*()_+{}[]|"

out = "idvi+1{s6e3{)arg2zv[moqa905+"
res = []

for i, ch in enumerate(out):
    if ch in abc:
        res.append(abc[(abc.index(ch) - i) % 26])
    elif ch in dig:
        res.append(dig[(dig.index(ch) - 2 * i) % 10])
    elif ch in spec:
        res.append(spec[(spec.index(ch) - i * i) % len(spec)])

print("".join(res))
```

## Flag

```text
ictf{1_l0v3_@ndr0id_stud103}
```
