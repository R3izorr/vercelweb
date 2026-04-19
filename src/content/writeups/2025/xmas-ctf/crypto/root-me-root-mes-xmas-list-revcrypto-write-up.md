---
title: "Root-Me – Root-Me's Xmas List (Rev/Crypto) – Write-up"
description: "* **Category:** Reverse Engineering / Cryptography * **Target Binary:** `listviewer` (Linux ELF, GTK GUI) * **Extra File:** `dump.pcapng` (Captured network traffic) * **Goal:** Rec"
event: "XMAS CTF"
year: 2025
category: crypto
tags: ["crypto","ghidra"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "XMAS_Ctf"
featured: false
flagsHidden: false
---

> Imported from [XMAS_Ctf](https://github.com/R3izorr/CTF_writeup/tree/main/XMAS_Ctf).

# Root-Me – “Root-Me's Xmas List” (Rev/Crypto) – Write-up

## Overview

* **Category:** Reverse Engineering / Cryptography
* **Target Binary:** `listviewer` (Linux ELF, GTK GUI)
* **Extra File:** `dump.pcapng` (Captured network traffic)
* **Goal:** Recover Father Christmas’s credentials and decrypt his restricted lists/flag from the packet capture.

**High-Level Summary:**
The client (`listviewer`) performs a custom AES-GCM handshake to derive a session AES-128-ECB key. All subsequent commands and responses are AES-128-ECB encrypted and transmitted as hex-encoded strings. Because the GCM key and IV are *hardcoded* within the client binary, anyone possessing the binary and the packet capture can reconstruct the session key and decrypt the entire traffic stream.

---

## 1. Code Flow & Protocol Analysis

### 1.1 GUI & Main Flow
Reversing `listviewer` with Ghidra/IDA reveals a 3-page GTK GUI:
* **Login Screen:** Prompts for Server, Port, Username, Password, and features a "Connect" button (handled by `sub_3500`).
* **Menu Screen:** Displays available Christmas lists with options to "Refresh lists" (`sub_32E0`) or "View selected list" (`sub_3160`).
* **List Screen:** A text view displaying the decrypted contents of a selected list.

### 1.2 The Handshake & Login (`sub_3500`)
When the user clicks **Connect**, the application follows this sequence:
1. Connects to the remote server.
2. Receives a 15-byte banner (`"ListViewer v1.0"`) which is validated against local constants.
3. Receives a 32-byte encrypted seed from the server.



The client splits these 32 bytes into two halves:
* `C` = First 16 bytes (Ciphertext)
* `T` = Next 16 bytes (GCM Tag)

It then decrypts `C` using **AES-128-GCM** with a key and IV hardcoded in the `.rodata` section.

```c
// Extracted from .rodata
uint8_t GCM_IV[12]  = { 0xba, 0xa0, 0x63, 0x70, 0x02, 0x31, 0xc9, 0x4c, 0xa1, 0x61, 0x8c, 0x6c };
uint8_t GCM_KEY[16] = { 0xf9, 0x19, 0x81, 0xd6, 0xbc, 0xb8, 0x72, 0xf4, 0x34, 0x31, 0x98, 0x41, 0x86, 0x15, 0x21, 0x97 };

// Decryption yields the 16-byte plaintext seed (P)
P = AES_GCM_decrypt(GCM_KEY, GCM_IV, C, T);
```



**Session Key Derivation:**
The 16-byte plaintext seed (`P`) is transformed into block `B` by shuffling its bytes, and then XORed against a static `0xAB` mask to derive the final AES-128-ECB session key (`K`).

```c
// Shuffle pattern
B[0..3]   = P[12..15];
B[4..11]  = P[0..7];
B[12..15] = P[8..11];

// XOR mask application
uint8_t mask[16] = { 0xAB, 0xAB, ... };
for (int i = 0; i < 16; i++) {
    K[i] = B[i] ^ 0xAB;
}
```

### 1.3 Generic Encrypted Commands (`sub_2CA0`)
All subsequent communication uses `sub_2CA0(const char *cmd, char **out_plain)`. 
* **Sending:** The plaintext command (e.g., `LOGIN fatherchristmas <pass>`) is padded via PKCS#7, encrypted with AES-128-ECB using `K`, hex-encoded into ASCII, and sent over TCP with a trailing newline.
* **Receiving:** The server responds with a newline-terminated hex string, which is hex-decoded, decrypted via AES-128-ECB, and unpadded to yield the plaintext.

---

## 2. The Vulnerability

The intended protection assumes a passive network attacker only sees ciphertext. However, the implementation is critically flawed: **The GCM key and IV are statically hardcoded in the client binary.**

Because the server does not use any client-specific secret for the handshake, anyone possessing the `listviewer` binary and `dump.pcapng` can:
1. Extract `C` and `T` from the packet capture.
2. GCM-decrypt the seed using the hardcoded key/IV.
3. Replicate the shuffle + XOR logic to derive the session key `K`.
4. Decrypt every single command and response in the PCAP.

---

## 3. Exploit Walkthrough

### Step 1: Extract the GCM Seed from PCAP
Following the TCP stream in Wireshark, the 32-byte payload immediately following the `"ListViewer v1.0"` banner is extracted:
```text
C = 3d d1 84 02 58 fa a1 d1 50 8c 37 40 b6 c8 9f 64
T = 31 15 c0 7d 60 05 cb c6 5f 24 7b 27 ce 01 fa 12
```

### Step 2: Decrypt the Seed & Derive the Key
Using a Python script, we reverse the handshake logic to recover the session key.

```python
from Crypto.Cipher import AES

# 1. Hardcoded GCM secrets
key = bytes.fromhex("f91981d6bcb872f43431984186152197")
iv  = bytes.fromhex("baa063700231c94ca1618c6c")
C   = bytes.fromhex("3dd1840258faa1d1508c3740b6c89f64")
T   = bytes.fromhex("3115c07d6005cbc65f247b27ce01fa12")

# 2. Recover the plaintext seed (P)
cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
P = cipher.decrypt_and_verify(C, T)
# P = 6f4ecb2847a39dc48d8da1ac0ed393fd

# 3. Shuffle and XOR to derive Session Key (K)
B = P[12:16] + P[0:8] + P[8:12]
K = bytes(b ^ 0xAB for b in B)

print(f"Session Key: {K.hex()}")
# Output: a5783856c4e56083ec08366f26260a07
```

### Step 3: Decrypt the PCAP Traffic
With `K` recovered, we can decrypt the application-layer hex strings found in the packet capture.

```python
from Crypto.Util.Padding import unpad

def decrypt_hex(hex_ct: str, session_key: bytes) -> str:
    ct = bytes.fromhex(hex_ct.strip())
    cipher = AES.new(session_key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ct), 16).decode()

# Example: Captured client login request
hex_login = "81e0994c037dffdd8c4ef6e242234cd303ab364c58ae20eb15703cbecec5bf10bc710b2c574db81d23434836f24d8224db9dfff7095a8f6743033d65e854c82e"
print(decrypt_hex(hex_login, K))
```
**Output:** `LOGIN fatherchristmas hOa84ONoAu8MfmPZzNK7Zpr43hCOGqD`

We now have Father Christmas's credentials. Repeating this decryption process for the subsequent `LIST <name>` commands in the PCAP reveals the contents of the restricted lists.

---

## 4. Final Flag & Takeaways

By either decrypting the remaining PCAP traffic or logging into the live server via the GUI using the recovered credentials, we can view Father Christmas's restricted list to obtain the flag:

**Flag:** `RM{Sh1t_3nCrypT10n_H0h0h0_Y0u_G0t_Th3_L1sT:}`

**Key Takeaways:**
* Hardcoding symmetric keys inside client binaries is a fatal flaw; attackers can easily extract them to spoof traffic or break confidentiality.
* "Rolling your own crypto" protocols are highly prone to implementation errors. Even when secure algorithms (like AES-GCM) are used, poor key management compromises the entire system.
* For true confidentiality, utilize established protocols (like TLS) that perform proper asymmetric key exchanges, and keep authoritative secrets strictly on the server.
