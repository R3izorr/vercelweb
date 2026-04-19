---
title: "Challenge Overview"
description: "**Name:** rev200-1.apk **Category:** Reverse Engineering **Platform:** Android (Kotlin / Java)"
event: "Pointeroverflowctf"
year: 2025
category: rev
tags: ["rev","android","crypto"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "pointeroverflowctf/rev/Reverse 200-1 On Hinge and Pin"
featured: false
flagsHidden: false
---

> Imported from [pointeroverflowctf/rev/Reverse 200-1 On Hinge and Pin](https://github.com/R3izorr/CTF_writeup/tree/main/pointeroverflowctf/rev/Reverse%20200-1%20On%20Hinge%20and%20Pin).

## Challenge Overview

**Name:** rev200-1.apk  
**Category:** Reverse Engineering  
**Platform:** Android (Kotlin / Java)

---

## Analysis

The APK contains two main classes of interest:
1. **MainActivity**  
   - Controls UI and contains a button (`btnReveal`) that triggers flag display.  
   - The button callback calls:
     ```java
     Crypto.loadAndDecrypt$default(Crypto.INSTANCE, this$0, null, 2, null);
     ```
   - This indicates the flag is retrieved from the `Crypto` class.

2. **Crypto**  
   - Responsible for loading an asset (`enc_flag.bin`) and decrypting it using a repeating XOR key.

---

## Crypto Class Logic

- Constant key:
  ```java
  private static final String KEY = "ONOFFONOFF";
Behavior:

Open asset enc_flag.bin.

Read all bytes into data.

Allocate out with same length as data.

For each byte index i:

java
Sao chép mã
out[i] = (byte) (data[i] ^ key[i % key.length]);
Convert out to a UTF-8 String and return it.

Decryption Process (how to reproduce)
Extract enc_flag.bin from the APK assets/ directory (e.g., with apktool or unzip).

Use the repeating key "ONOFFONOFF" to XOR-decrypt the file:

For each byte at index i: plain[i] = enc[i] ^ key[i % key.length].

Interpret the resulting bytes as UTF-8 to get the flag.

Example (Python):

python
Sao chép mã
key = b"ONOFFONOFF"
enc = open("enc_flag.bin","rb").read()
dec = bytes([enc[i] ^ key[i % len(key)] for i in range(len(enc))])
print(dec.decode("utf-8"))
Result
Flag: poctf{uwsp_c4nc3l_c0u7ur3}

Summary
Component	Description
Encryption	XOR cipher
Key	ONOFFONOFF
File	enc_flag.bin (in APK assets)
Language	Kotlin (decompiled with JADX / IL)
Decompilers	JADX, dnSpy, ILSpy (recommended)
Decryption	Simple repeating-key XOR
