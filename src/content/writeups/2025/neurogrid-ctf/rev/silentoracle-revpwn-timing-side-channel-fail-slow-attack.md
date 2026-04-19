---
title: "SilentOracle (rev/pwn) — Timing Side-Channel (fail-slow) Attack"
description: "**Flag:** `HTB{Tim1ng_z@_h0ll0w_t3ll5}`"
event: "Neurogrid CTF"
year: 2025
category: rev
tags: ["rev","heap","pwntools"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "Neurogrid CTF/rev"
featured: false
flagsHidden: false
---

> Imported from [Neurogrid CTF/rev](https://github.com/R3izorr/CTF_writeup/tree/main/Neurogrid%20CTF/rev).

# SilentOracle (rev/pwn) — Timing Side-Channel (“fail-slow”) Attack

**Flag:** `HTB{Tim1ng_z@_h0ll0w_t3ll5}`  

---

## 1. Code Flow (What the Program Does)

### main

Decompiled `main`:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
    size_t v4;
    char s[72];              // user input buffer
    unsigned __int64 v6;

    v6 = __readfsqword(0x28u);
    sub_11B9();              // disables buffering
    puts(a0m382332m48229);   // banner line 1
    puts(a1533m);            // banner line 2
    printf("\x1B[1;5;33mATTEMPT YOUR SCHEMES: \x1B[1;5;31m");

    memset(s, 0, 0x40);
    if (!fgets(s, 64, stdin))
        exit(-1);

    v4 = strlen(s);
    if (v4 && s[v4 - 1] == '\n')
        s[v4 - 1] = 0;       // strip newline

    puts("\x1B[0m");         // reset color

    if (sub_11FC((__int64)s, v4)) {
        puts(a0m382204183149);
        puts("\x1B[1;32mCONTINUE ON WITH YOUR ADVENTURE, O HONORABLE ONE\x1B[0m");
    } else {
        puts(a0m382443m48231);
        puts("\x1B[1;5;31mYOU ARE BANISHED\x1B[0m");
    }
    return 0;
}
```
sub_11B9
```c

void sub_11B9()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
→ All I/O is unbuffered, so timing is not distorted by stdio buffering.
```
sub_11FC – the core check
```c

bool __fastcall sub_11FC(__int64 a1, __int64 a2)
{
    signed int i;

    for (i = 0; (unsigned int)i <= 0x14 && i < (unsigned __int64)(a2 - 1); ++i)
    {
        if (*(_BYTE *)(i + a1) != off_5D068[i])  // compare with secret flag bytes
        {
            puts(s);                             // echo input
            sleep(5u);                           // <-- time delay
            return 0;                            // fail immediately
        }
    }
    return i == 21;
}
```

### And in .data:

```c

.data:000000000005D068 off_5D068 dq offset aHtbTestFlagHah
// "HTB{test_flag_hahaha}"  (local test flag)
```
### Overall logic:

1. Program prints banner.

2. Reads up to 63 bytes into s (user input).

3. Calls sub_11FC(s, len):

4. Compares each character with the secret flag (off_5D068).

5. On the first mismatch:

6. Prints your input (puts(s)).

7. Sleeps 5 seconds.

8. Returns false.

### If all checked characters match and length is correct    (i == 21), returns true.

### main prints either:

- Success banner (CONTINUE ON...), or

- Failure (YOU ARE BANISHED).

## Where Is the Bug? (The Timing Side-Channel)
### The critical behavior inside sub_11FC:

```c

if (*(_BYTE *)(i + a1) != off_5D068[i]) {
    puts(s);
    sleep(5u);
    return 0;
}
```
### Correct prefix: Loop continues instantly to the next character.

### Wrong character: Immediately:

- Echoes your input.

- Sleeps 5 seconds.

- Fails.

### So:

- Input with a valid prefix (all chars correct up to some position) returns quickly.

- Input with a wrong char at position i triggers a 5-second delay.

### This is the bug: the running time leaks how many characters of your input match the secret flag — a timing side-channel, specifically a “fail slow” pattern.

### Important subtlety: They call puts(s) before sleep(5).

-> If your exploit only does recvline(), you may get that echoed line instantly and think the request is “fast”. But the process is still sleeping 5 seconds in the background.

### To distinguish fast vs slow, you must:

Wait for the full response / connection close (e.g., recvall)

Measure total time from send → EOF

## Exploit Strategy


### Naïve sequential brute-force (too slow)
For each position i, try all candidate characters:

Each wrong guess → sleep(5) → ~5s.

If alphabet ≈ 70 characters:

Worst-case per position: 70 × 5s ≈ 350 seconds.

For ~20 characters, that’s ....



### Strategy: Parallel timing attack
- We exploit several properties:

- We can start many independent connections to the service.

- Each connection is cheap (short input, one check).

- The sleep only affects that one connection.

- So for each character position:

- We have a known correct prefix flag_prefix.

- We create candidate payloads flag_prefix + c for all c in an alphabet:

- alphabet = [A–Z, a–z, 0–9, symbols like {}_!@?]

- Launch all candidates in parallel threads/processes:

- For each candidate:

- Connect to remote.

- Send payload.

- Wait for EOF with recvall(timeout=6).

- Measure elapsed time.

### Interpretation:

- If we see CONTINUE ON in the response → we reached end of flag.

### Else:

- elapsed < 3s → no sleep, so this candidate char is correct.

- elapsed > 3s → hit sleep(5), candidate char is wrong.

- Once we find a fast candidate:

- Append that char to flag_prefix.

### Break the loop for this position, move to the next index.

### Stop when:

- We hit }, or

- The success message “CONTINUE ON…” appears.

- Because we test 20+ candidates in parallel, each position costs only ~5s worst-case instead of 5s × alphabet.

## Exploit Code (Final Working Script)
```python

import time
import string
import concurrent.futures
from pwn import *

# Remote target
HOST = '83.136.250.108'
PORT = 40610

context.log_level = 'error'

# Candidate character set
alphabet = string.ascii_letters + string.digits + "{}_!@?"

def test_char(current_flag, candidate):
    """
    Test one character in parallel.

    Returns:
      (candidate, True)  -> this char is correct and we saw the success banner
      (candidate, False) -> this char is correct (fast timing), continue to next pos
      (None, False)      -> this char is wrong (slow timing due to sleep)
    """
    try:
        # Remote solve by default
        r = remote(HOST, PORT)

        # Sync with prompt
        r.recvuntil(b'ATTEMPT YOUR SCHEMES: ')

        # Try current prefix + candidate char
        payload = current_flag + candidate
        start = time.time()
        r.sendline(payload.encode())

        # IMPORTANT: wait for full response / socket close
        resp = r.recvall(timeout=6)
        elapsed = time.time() - start
        r.close()

        # Check explicit success message
        if b"CONTINUE ON" in resp:
            return candidate, True

        # Time-based decision:
        # - Fast (< 3s)  => no sleep => correct char
        # - Slow (>= 3s) => sleep(5) => wrong char
        if elapsed < 3.0:
            return candidate, False
        else:
            return None, False

    except Exception:
        # Network glitches or timeouts: treat as inconclusive
        return None, False

def main():
    flag = "HTB{"  # known prefix format for HTB flags
    print(f"[*] Starting timing attack against {HOST}:{PORT}")

    while True:
        found_this_round = False

        # Test many candidates in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(test_char, flag, ch): ch
                for ch in alphabet
            }

            for future in concurrent.futures.as_completed(futures):
                candidate, is_end = future.result()

                if candidate:
                    flag += candidate
                    print(f"[+] Extended flag: {flag}")
                    found_this_round = True

                    # Either explicit success or closing brace => done
                    if is_end or candidate == "}":
                        print(f"\n[SUCCESS] Final Flag: {flag}")
                        executor.shutdown(wait=False, cancel_futures=True)
                        return

                    # Once we have the correct char for this position,
                    # cancel remaining tests for this index.
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

        # If no char was confidently found, try the same position again
        if not found_this_round:
            print("[!] No char found this round (jitter?), retrying...")

if __name__ == "__main__":
    main()
```
## Result
Running the above script recovers:

```bash
HTB{Tim1ng_z@_h0ll0w_t3ll5}
```

