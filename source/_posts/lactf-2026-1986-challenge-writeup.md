---
title: LA CTF 2026 - the 1986 challenge writeup
date: 2026-02-08 08:01
tags: ctf, writeup, security, reverse engineering
---

The task intro was very informative: 

> Dug around the archives and found a floppy disk containing a long-forgotten LA CTF challenge.

<br>

## What we get

A floppy disk image (`CHALL.IMG`) containing `CHALL.EXE` - a tiny program written for
MS-DOS. The program asks you to type a flag and tells you whether you're right or wrong.

<br>

Looks like we need to figure out what the correct flag is without just guessing (we shall see!)

<br>

## Reverse engineering the binary

Using Ghidra I was able to decompile the binary and see what it actually does. Three steps were particularly interesting:

<br>

### Step 1 - Hashing the flag into a "seed"

The program reads the entire input (e.g. `lactf{hello}`) and crunches it down into a
single number called a **seed**. It does this to every single character at a time:

<br>

```
seed = 0
for each character c in the flag:
    seed = (seed × 67 + c) mod 1048576
```

<br>

The `modulo 1048576` (which is 2^20) means the seed is always a number between 0 and
1,048,575 - so it fits in 20 bits. This is essentially a very simple hash function: it mixes
all the flag characters together into one small fingerprint.

<br>

### Step 2 - Generating a keystream with an LFSR

The resulting 20-bit seed is then used to initialize something called a **Linear Feedback Shift
Register (LFSR)**. An LFSR is a classic building block in cryptography and hardware
design. I think of it as a row of 20 light switches (bits), where at each "tick":

1. We look at two specific switches (called **taps** - here, bits 0 and 3).
2. We XOR them together (XOR answers "are they different?" question) to get a new bit.
3. We shift the whole row one position to the right [effectively dropping the rightmost bit].
4. The new bit slides in on the left end.

<br>

This particular variation of LFSR is **maximal-length**, meaning it cycles through every possible
non-zero state (2^20 − 1 = 1,048,575 states) before wrapping around and repeating. That's the longest possible cycle for a 20-bit register.

<br>

Each tick produces a **keystream byte**: we then grab the least significant 8 bits of the current
LFSR state. This gives us a stream of pseudorandom-looking bytes, one for each flag character.

<br>

### Step 3 - XOR and compare

Each keystream byte is then XORed with the corresponding flag character. XOR in it's nature is reversible:
[`A XOR B = C` means `C XOR B = A`]. The result is then compared against 73 bytes hardcoded into the program. If every byte matches, it's a win.

<br>

## The plot-twist

Here's the odd part: the **seed** is computed **from the flag**, but you need the seed
to **decrypt the flag**. The flag determines the seed, and the seed determines the flag [circular dependency].

<br>

## How to solve?

The key insight is that the seed is only 20 bits, so there are "only" ~1 million possible
values. We can just ~~guess~~ try them all:

1. Set a candidate seed (0 through 1,048,575).
2. Run the LFSR forward, XOR the keystream with the 73 encrypted bytes → get a candidate flag.
3. Hash that candidate flag back through the seed function.
4. If the hash equals our candidate seed, it must be the real flag.

<br>

Because the prefix is known [`lactf{`], it lets us skip most candidates instantly. The guess-force script took around ~18 seconds to run on my laptop.

<br>

```
Seed:  0xf3fb5
Flag:  lactf{3asy[REDACTED]n0t_ea5y_en0ugh_jus7_t0_brut3_forc3}
```

<br>

# Final words

For a second I was wondering what does the flag say to me. Then it clicked - it's a play on the actual solution method - a combination of reversing the binary and brute-forcing the seed. But what does the `1986` mean? I guess I will never find out.

<br>

# Source code

```
def update_seed(state, char):
    return (state * 67 + char) & 0xFFFFF

def lfsr_step(state):
    feedback = ((state >> 3) ^ state) & 1
    return ((state >> 1) | (feedback << 19)) & 0xFFFFF

ENCRYPTED = [
    0xB6, 0x8C, 0x95, 0x8F, 0x9B, 0x85, 0x4C, 0x5E, 0xEC, 0xB6, 0xB8, 0xC0, 0x97, 0x93, 0x0B, 0x58,
    0x77, 0x50, 0xB0, 0x2C, 0x7E, 0x28, 0x7A, 0xF1, 0xB6, 0x04, 0xEF, 0xBE, 0x5C, 0x44, 0x78, 0xE8,
    0x99, 0x81, 0x04, 0x8F, 0x03, 0x40, 0xA7, 0x3F, 0xFA, 0xB7, 0x08, 0x01, 0x63, 0x52, 0xE3, 0xAD,
    0xD1, 0x85, 0x9F, 0x94, 0x21, 0xD5, 0x2A, 0x5C, 0x20, 0xD4, 0x31, 0x12, 0xCE, 0xAA, 0x16, 0xC7,
    0xAD, 0xDF, 0x29, 0x5D, 0x72, 0xFC, 0x24, 0x90, 0x2C,
]
PREFIX = b"lactf{"

for seed in range(1 << 20):
    lfsr = seed
    flag_bytes = []
    for enc_byte in ENCRYPTED:
        lfsr = lfsr_step(lfsr)
        flag_bytes.append(enc_byte ^ (lfsr & 0xFF))

    if flag_bytes[:6] != list(PREFIX):
        continue


    check = 0
    for b in flag_bytes:
        check = update_seed(check, b)

    if check == seed:
        print(f"Seed:  {seed:#07x}")
        print(f"Flag:  {''.join(chr(b) for b in flag_bytes)}")
        break

```
