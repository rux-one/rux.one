---
title: LA CTF 2026 - the starless-c writeup
date: 2026-02-08 08:02
tags: ctf, writeup, security, reverse engineering
thumbnail: /images/thumb_lactf.png
excerpt: A maze hidden inside 58 ELF LOAD segments - solving a sliding puzzle of crash rooms with BFS to reach the flag.
---

## What is this?

> The son of the fortune-teller stands before three doors. A bee. A key. A flag.

<br>

In this challenge, I was gifted with a mysterious Linux program called `starless_c`. Running it drops you into what at first glance looked like a weird jumping game.

No instructions. No map. Now when refactoring this writeup, I am introducing the maze analogy. It was not very clear to me at first. Although the task description is suggesting doors and keys [btw. what's with the bees?]

<br>

## What is inside?

Usually when reverse engineering a binary, it makes sense to try understand what the binary does. 

<br>

Used Ghidra to decompile and analyze the pseudo source code. At first glance, it was a wall of nonsense. The decompiler choked on it. There were no function boundaries, no symbols, no interesting strings. 

Observations:
* **58 LOAD segments** [what!]
* Many segments mapped to the same file offset but at different virtual addresses

<br/>

Hmm, same code reused in different places? What does that mean?

<br>

Some idas started to form once I realized the program is expecting input in form of WASD keys. [and then the F key as well].

<br>

Are we... walking the binary?
Each key press results in a jump to a different address. 

<br>

### The maze is made of "Rooms"

So again, it was one weird debugging session but in the end I settled on the following mental model: 
* Each 4KB chunk of memory is a "room", but also a set of instructions that can be executed
* You start in one room and move between them using **W** (up), **A** (left), **S** (down), **D** (right). 
* There's also an **F** key, which does something [a jump to a different address]

<br/>

### Some "rooms" are not so friendly

Some rooms crashed. A few bytes of machine code (`xor %eax, %eax; mov %al, (%rax)`) that deliberately writes to memory address zero. On any modern system, that's an instant **segfault**. So if you wander into the wrong room, the program just dies. Nasty?

<br/>

### Some "rooms" are locked

Some rooms start with a different byte: `0x90`, which in x86 assembly is a **NOP** [No Operation]. It means "do nothing and move on." A room that starts with NOPs is **safe** - the crash code has been replaced with harmless filler, so execution can safely pass through.

<br/>

A room that starts with the crash sequence is **dangerous**. Walk into it and boom - game over. Trap is activated.

<br/>

At the start of the program, only 5 specific rooms are considered safe (rooms `03`, `04`, `05`, `0b`, `0c`). Everything else is trouble.

<br/>

### "Chasing a ghost" - The sliding puzzle mechanic

This is where it gets weird. When you move in a direction, the game checks: *is the room I'm heading toward safe (starts with NOP)?* If so, something different happens:

1. The destination room becomes **dangerous** - its NOPs are overwritten with crash code.
2. A *different* room (determined by the current room's code) becomes **safe** - it receives the NOPs.

<br>

So it's like following a ghost which guides you safely through...the dungeon.

**Why chasing ghosts?** You can't just walk to the flag - the path is blocked by locked rooms. By carefully choosing which direction to move, you chase the danger zones (the "ghosts") around the maze, gradually herding them onto the exact rooms you need open. It's a sliding puzzle *inside* a maze. What the actual..?

<br/>

### The secret move: The F Key and the special jump

Every room has a hidden option: pressing **F** always jumps you to **Room 18**. But this room is locked by default, so pressing F early "in the game" just crashes the program.

<br/>

*However*, if Room 18 happens to be unlocked (starts with NOPs), execution doesn't crash - it slides past the NOPs and hits a **jump instruction** at byte 4 of that room. That jump sends you to Room 02. If that's also unlocked, you bounce to Room 03, then Room 07, then Room 01, and finally **Room 06** - the Flag Room, which reads and prints `flag.txt`.

<br/>

So the intended jump chain turned out to be:

```
F key → Room 18 → Room 02 → Room 03 → Room 07 → Room 01 → Room 06 (FLAG!)
```

So it means the crucial rooms need to be made safe prior to the jump chain being triggered. 

<br/>

### What are the "LOAD Segments"?

I had to educate myself a bit. When Linux runs a program, it reads the binary file and maps chunks of it into memory. These chunks are called **LOAD segments**. The binary in subject had **58** of them instead of the usual 2–3. Each LOAD segment corresponded to one "room" in the maze, mapped to a different memory address. This is how the challenge author built a maze out of raw program structure - and it's the abnormal segment count that was the first hint that someting is off.

<br/>

## The solution

### Step 1: Map the maze

I used `readelf` to extract the addresses of all 58 LOAD segments and figure out which file offsets mapped to which rooms.

<br>

```
 ❯ readelf  -Wl starless_c

Elf file type is EXEC (Executable file)
Entry point 0x13370000
There are 58 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x001000 0x0000000067687000 0x0000000067687000 0x000000 0x000000     0x3e13a5a1a5226217
  LOAD           0x001000 0x0000000067672000 0x0000000067672000 0x000000 0x000000     0xd9d9b40ec422d7

(SNIP)
```

### Step 2: Analyze the room logic [draw a map]

I wrote Python scripts to read the binary and extract, for each room:
- **Where does each direction (W/A/S/D) take you?** (by decoding jump instructions)
- **If a ghost is present, where does it flee to?** (by decoding the "move" instructions)

<br/>

### Step 3: Solve the Puzzle with BFS

Now I had a complete model of the maze: 25 rooms, 5 ghosts, and rules for how ghosts move. The **goal state** is: rooms `18`, `02`, `03`, `07`, and `01` all unlocked at the same time.

<br/>

Using **Breadth-First Search (BFS)** - an algorithm that explores all possible moves level by level, it eventually finds the *shortest* solution. The traced "state" at each step was: which room I'm in + which rooms are currently unlocked.

<br/>

My search found a **144-step path**:

```
sddddswaasdwaaasdssawwdwddsawasassdddwsddwasaaaawwdwdddsawaasassdddwwdwasssaaawwdwwassdddssddwasaaawwddwdsaaawdsassddwsddwawaawasdddssawdwaaddwaa
```

Could there be a shorter path?

<br/>

### Step 4: Press F

After those 144 moves, all five rooms in the jump chain are unlocked. One final **F** keystroke triggers the chain reaction through all of them, landing in the Flag Room.

<br>

## The Flag

I connected to the remote server, sent the 144-character path followed by `f`, and got:

<br/>

```
lactf{[REDACTED]more_like_starless_0xcc}
```

<br/>

Final realizaton: The `0xcc` in the flag is a reference to the x86 `INT 3` breakpoint instruction - for all the debugging required.

<br/>

I sometimes try to figure out what the author had in mind when naming the challenge or the flag, and this time I think it's a reference to navigating through the maze without any guidance [stars]. 

<br/>

The "crash" message:
> And so the son of the fortune-teller does not find his way to the Starless C. Not yet.

<br/>

That was a fun one!

<br/>

## The code [refactored later on]

```
import struct
import collections

mapping = {
    0x01000: 0x67692000, 0x02000: 0x67682000, 0x03000: 0x6768a000, 0x04000: 0x6768c000,
    0x05000: 0x67689000, 0x06000: 0x42069000, 0x07000: 0x67691000, 0x08000: 0x6769e000,
    0x09000: 0x13370000, 0x0a000: 0x6769d000, 0x0b000: 0x67694000, 0x0c000: 0x6768d000,
    0x0d000: 0x6769a000, 0x0e000: 0x67699000, 0x0f000: 0x67681000, 0x10000: 0x67679000,
    0x11000: 0x6769c000, 0x12000: 0x67685000, 0x13000: 0x67695000, 0x14000: 0x6768b000,
    0x15000: 0x67684000, 0x16000: 0x67696000, 0x17000: 0x67683000, 0x18000: 0x6767a000,
    0x19000: 0x6769b000,
}
vaddr_to_room = {v: f"{k//4096:02x}" for k, v in mapping.items()}
room_to_vaddr = {f"{k//4096:02x}": v for k, v in mapping.items()}

with open('starless_c', 'rb') as f:
    data = f.read()

dirs = {'w': (0x56, 0x50), 's': (0x75, 0x6f), 'a': (0x94, 0x8e), 'd': (0xb3, 0xad)}

initial_locked = frozenset(['03', '04', '05', '0b', '0c'])
initial_room = '10'
target_rooms = set(['18', '02', '03', '07', '01'])

queue = collections.deque([(initial_room, initial_locked, "")])
visited = set([(initial_room, initial_locked)])

best_locked_count = 0

while queue:
    curr_room, locked, path = queue.popleft()
    
    match_count = len(target_rooms.intersection(locked))
    if match_count > best_locked_count:
        best_locked_count = match_count
        print(f"found path with {match_count} targets: {path}")
        if match_count == 5:
            print(f"full path found! Input: {path}f")
            break
    
    vaddr = room_to_vaddr[curr_room]
    offset = int(curr_room, 16) * 4096
    
    for move in 'wsad':
        jmp_off, mov_off = dirs[move]
        rel_jmp = struct.unpack('<i', data[offset + jmp_off + 1 : offset + jmp_off + 5])[0]
        target_vaddr = (vaddr + jmp_off + 5 + rel_jmp) & 0xffffffffffffffff
        target_vaddr_base = target_vaddr & ~0xfff
        if target_vaddr_base not in vaddr_to_room: continue
        
        target_room = vaddr_to_room[target_vaddr_base]
        new_locked = set(locked)
        if target_room in locked:
            rel_mov = struct.unpack('<i', data[offset + mov_off + 2 : offset + mov_off + 6])[0]
            bee_target_vaddr = (vaddr + mov_off + 6 + rel_mov) & 0xffffffffffffffff
            bee_target_vaddr_base = bee_target_vaddr & ~0xfff
            if bee_target_vaddr_base not in vaddr_to_room: continue
            new_locked.remove(target_room)
            new_locked.add(vaddr_to_room[bee_target_vaddr_base])
        
        new_locked = frozenset(new_locked)
        if (target_room, new_locked) not in visited:
            visited.add((target_room, new_locked))
            queue.append((target_room, new_locked, path + move))

```


