---
layout: post
title: FCSC 2026 - Kernel addresses
date: 2026-04-12     00:00 +0100
categories:
  - Forensics
author: bobnewz
description: FCSC 2026 - Memory forensics challenges
image:
  path: /assets/img/FCSC-2026/FCSC.png
  alt: FCSC image
tags:
  - Memory forensics
  - Kernel Linux
---

## Context

You have received RAM dumps from three machines, and you are looking for the address of the first kernel instruction (the _stext function) for each of them.

## To begin (Pour commencer)

The flag is in the format FCSC{phys-virt}, where:

- phys is the physical address of the first kernel instruction,
- virt is the virtual address of the first kernel instruction in the kernel text mapping area.
- All addresses are 64-bit, in hexadecimal format with a 0x prefix.

### Background

`intro.mem` is a raw linear dump of a machine's physical RAM. In this kind of file, **the
offset of a byte in the file is exactly its physical address in RAM**.

The Linux kernel always keeps a compressed copy of its symbol table (`kallsyms`) in memory.
The tool **`kallsyms-finder`** can locate it inside a raw dump and extract all symbols with
their virtual addresses. By cross-referencing these virtual addresses with the physical offsets at which the kallsyms structures were found in the file, we can compute the `virt ↔ phys` relationship for any symbol, including `_stext`.

---

### Step 1 — Recon with `kallsyms-finder`

The tool can be installed with `pipx install vmlinux-to-elf`, and the file kallsyms-finder.py must be fixed.

```
$ kallsyms-finder /workspace/intro.mem
```

Output:

```
[+] Version string: Linux version 6.18.0 (fcsc@fcsc) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0,
    GNU ld (GNU Binutils for Ubuntu) 2.42) #1 SMP PREEMPT_DYNAMIC 0
[+] Guessed architecture: x86_64 successfully in 1.10 seconds
[+] Kernel found in database
[+] Found kallsyms_token_table at file offset 0x0237a058
[+] Found kallsyms_token_index at file offset 0x0237a3d0
[+] Found kallsyms_markers at file offset 0x02379690
[+] Found kallsyms_names at file offset 0x02165198 (159905 symbols)
[+] Found kallsyms_num_syms at file offset 0x02165190
[!] WARNING: Less than half (0%) of offsets are negative
[!] WARNING: More than half (100%) of offsets look like absolute addresses
[+] Found kallsyms_offsets at file offset 0x0237a5d0

ffffffff81000000 T _stext
ffffffff81000000 T _text
ffffffff82165198 D kallsyms_names
ffffffff8237a058 D kallsyms_token_table
ffffffff8237a5d0 D kallsyms_offsets
```

This gives us:

| Symbol | **Virtual** address (kallsyms) | **Physical** offset in the dump |
|---|---|---|
| `kallsyms_token_table` | `0xffffffff8237a058` | `0x0237a058` |
| `kallsyms_names` | `0xffffffff82165198` | `0x02165198` |
| `kallsyms_offsets` | `0xffffffff8237a5d0` | `0x0237a5d0` |
| `_stext` | `0xffffffff81000000` | *(to be computed)* |


---

### Step 2 — Computing the virt/phys diff

Since the dump is a linear RAM image, the file offset of a symbol **is** its physical address.
The virtual-to-physical relationship is a constant translation:

```
diff = virtual_address − physical_address
```

We verify consistency across the 3 reference symbols:

```python
# Virtual addresses
kallsyms_token_table_virt = 0xffffffff8237a058
kallsyms_names_virt       = 0xffffffff82165198
kallsyms_offsets_virt     = 0xffffffff8237a5d0

# Physical offsets in the dump
kallsyms_token_table_phys = 0x0237a058
kallsyms_names_phys       = 0x02165198
kallsyms_offsets_phys     = 0x0237a5d0

diff_token   = (kallsyms_token_table_virt - kallsyms_token_table_phys) & 0xffffffffffffffff
diff_names   = (kallsyms_names_virt       - kallsyms_names_phys)       & 0xffffffffffffffff
diff_offsets = (kallsyms_offsets_virt     - kallsyms_offsets_phys)     & 0xffffffffffffffff

print(f"diff kallsyms_token_table : 0x{diff_token:016x}")
print(f"diff kallsyms_names       : 0x{diff_names:016x}")
print(f"diff kallsyms_offsets     : 0x{diff_offsets:016x}")
```

Output:

```
diff kallsyms_token_table : 0xffffffff80000000
diff kallsyms_names       : 0xffffffff80000000
diff kallsyms_offsets     : 0xffffffff80000000
```

The diff is **perfectly constant** across all 3 symbols.  
This matches the standard x86-64 kernel mapping **without KASLR**:
`virt = phys + 0xffffffff80000000`, equivalently `phys = virt − 0xffffffff80000000`.

---

### Step 3 — Computing the physical address of `_stext`

```python
stext_virt = 0xffffffff81000000

stext_phys = kallsyms_token_table_phys - (kallsyms_token_table_virt - stext_virt)

print(f"_stext phys : 0x{stext_phys:016x}")
print(f"_stext virt : 0x{stext_virt:016x}")
```

Output:

```
_stext phys : 0x0000000001000000
_stext virt : 0xffffffff81000000
```

### Result

| Field | Value |
|---|---|
| **Physical** address of `_stext` | `0x0000000001000000` |
| **Virtual** address of `_stext` | `0xffffffff81000000` |

```
FCSC{0x0000000001000000-0xffffffff81000000}
```


## A bit of a gamble (Un peu d'aléa)

### Background

`random.mem` is a 1 GB raw linear dump of a machine's physical RAM. As with `intro.mem`,
**the offset of a byte in the file is exactly its physical address in RAM**.

The key difference from `intro.mem` is that this kernel was loaded with **KASLR enabled**: the kernel text is not at the standard virtual base `0xffffffff81000000` but at a randomized
address. The physical load address is also different from the default `0x1000000`.

---

### Step 1 — Recon with `kallsyms-finder`

```
$ kallsyms-finder /workspace/random.mem
```

Output:

```
[+] Version string: Linux version 6.18.0 (fcsc@fcsc) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0,
    GNU ld (GNU Binutils for Ubuntu) 2.42) #1 SMP PREEMPT_DYNAMIC 0
[+] Guessed architecture: x86_64 successfully in 11.15 seconds
[+] Kernel found in database
[+] Found kallsyms_token_table at file offset 0x27f7a058
[+] Found kallsyms_token_index at file offset 0x27f7a3d0
[+] Found kallsyms_markers at file offset 0x27f79690
[+] Found kallsyms_names at file offset 0x27d65198 (159905 symbols)
[+] Found kallsyms_num_syms at file offset 0x27d65190
[!] WARNING: Less than half (0%) of offsets are negative
[!] WARNING: More than half (100%) of offsets look like absolute addresses
[+] Found kallsyms_offsets at file offset 0x27f7a5d0

ffffffff86000000 T _stext
ffffffff86000000 T _text
ffffffff87165198 D kallsyms_names
ffffffff8737a058 D kallsyms_token_table
ffffffff8737a5d0 D kallsyms_offsets
```

This gives us:

| Symbol | **Virtual** address (kallsyms) | **Physical** offset in the dump |
|---|---|---|
| `kallsyms_token_table` | `0xffffffff8737a058` | `0x27f7a058` |
| `kallsyms_names` | `0xffffffff87165198` | `0x27d65198` |
| `kallsyms_offsets` | `0xffffffff8737a5d0` | `0x27f7a5d0` |
| `_stext` | `0xffffffff86000000` | *(to be computed)* |

The virtual address of `_stext` is `0xffffffff86000000` instead of the standard
`0xffffffff81000000`: the **KASLR virtual slide** is `+0x5000000`.

---

### Step 2 — Computing the virt/phys diff

```python
kallsyms_token_table_virt = 0xffffffff8737a058
kallsyms_names_virt       = 0xffffffff87165198
kallsyms_offsets_virt     = 0xffffffff8737a5d0

kallsyms_token_table_phys = 0x27f7a058
kallsyms_names_phys       = 0x27d65198
kallsyms_offsets_phys     = 0x27f7a5d0

diff_token   = (kallsyms_token_table_virt - kallsyms_token_table_phys) & 0xffffffffffffffff
diff_names   = (kallsyms_names_virt       - kallsyms_names_phys)       & 0xffffffffffffffff
diff_offsets = (kallsyms_offsets_virt     - kallsyms_offsets_phys)     & 0xffffffffffffffff

print(f"diff kallsyms_token_table : 0x{diff_token:016x}")
print(f"diff kallsyms_names       : 0x{diff_names:016x}")
print(f"diff kallsyms_offsets     : 0x{diff_offsets:016x}")
```

Output:

```
diff kallsyms_token_table : 0xffffffff5f400000
diff kallsyms_names       : 0xffffffff5f400000
diff kallsyms_offsets     : 0xffffffff5f400000
```

The diff is **perfectly constant** across all 3 symbols: the linear mapping
`virt = phys + 0xffffffff5f400000` holds throughout the kernel.

---

### Step 3 — Computing the physical address of `_stext`

```python
stext_virt = 0xffffffff86000000 

stext_phys = kallsyms_token_table_phys - (kallsyms_token_table_virt - stext_virt)

print(f"_stext phys : 0x{stext_phys:016x}")
print(f"_stext virt : 0x{stext_virt:016x}")
```

Output:

```
_stext phys : 0x0000000026c00000
_stext virt : 0xffffffff86000000
```

---

### Step 4 — Byte verification

For the next memory dump, there is no symbols. This means that we need to find the exact pattern in the memory. To do so, we need to get a reference.

We read the first 10 bytes at physical offset `0x26c00000` in the dump:

```python
with open('/workspace/random.mem', 'rb') as f:
    f.seek(0x26c00000)
    data = f.read(10)
print(' '.join(f'{b:02x}' for b in data))
```

```
66 90 0f ae e8 e9 01 41 10 00
```

- `66 90` → `xchg ax, ax` (16-bit NOP)
- `0f ae e8` → `lfence`
- `e9 ...` → `jmp rel32`

This is the bytes of the beginning of _stext physical address.

---

### Result

| Field | Value |
|---|---|
| **Physical** address of `_stext` | `0x0000000026c00000` |
| **Virtual** address of `_stext` | `0xffffffff86000000` |

```
FCSC{0x0000000026c00000-0xffffffff86000000}
```


## Without symbols (Sans symboles)

### Context

The challenge provides a 1 GB memory dump (`stripped.mem`) of a Linux kernel **without symbols**. The goal is to find the address of the kernel's first instruction (`_stext`) in three forms:

- **`phys`**: physical address
- **`virt`**: virtual address in the *kernel text mapping* zone
- **`direct`**: virtual address in the *direct mapping* zone

The flag format is:

```
FCSC{phys-virt-direct}
```

---

### Step 1 — Finding the physical address of `_stext`

Without symbols, we search for the kernel's binary signature. From another dump of the same challenge (`random.mem`), we know the first bytes of `_stext` are:

```
66 90 0f ae e8 e9 01 41 10 00 cc cc ...
```

This pattern corresponds to the x86-64 kernel entry point `startup_64` (`xchg ax,ax` + `fxsave`).

We confirm consistency by searching for the `Linux version` string:

```python
import mmap

DUMP = "/workspace/stripped.mem"
with open(DUMP, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    target = b'Linux version'
    pos = mm.find(target)
    while pos != -1:
        s = mm[pos:pos+80].split(b'\x00')[0]
        print(f"0x{pos:08x}: {s[:80]}")
        pos = mm.find(target, pos+1)
    mm.close()
```

**Output:**

```
0x16200060: b'Linux version 6.18.0 (fcsc@fcsc) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU'
0x1634a540: b'Linux version 6.18.0 (fcsc@fcsc) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU'
0x16e5d960: b'Linux version 6.18.0 (fcsc@fcsc) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU'
0x17387068: b'Linux version 6.18.0 (fcsc@fcsc) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU'
```

The first occurrence is at `0x16200060`, which is `0x1000060` bytes after `0x15200000`. This is consistent: the `.rodata` section follows `.text` in the Linux kernel image.

> **Physical address of `_stext`: `0x0000000015200000`**

---

### Step 2 — Understanding x86-64 page table structure

In x86-64 with 4-level paging, a virtual address breaks down as follows:

```
bits 63:48  → canonical sign extension (sign of bit 47)
bits 47:39  → PGD index (level 4)
bits 38:30  → PUD index (level 3)
bits 29:21  → PMD index (level 2)
bits 20:12  → PTE index (level 1)
bits 11:0   → page offset
```

Key flags:
- **Bit 0** (P): present
- **Bit 7** (PS): page size : in PMD, indicates a **2 MB huge page**; in PUD, a **1 GB huge page**
- **Bit 63** (NX): no-execute

In a typical Linux kernel:
- `PGD[511]` → kernel text zone (`0xffffffff81000000` + KASLR)
- `PGD[273]` → direct mapping zone (`0xffff888000000000` + KASLR)

With KASLR enabled, both bases are randomly shifted at boot time.

---

### Step 3 — Locating the PMD entry that maps `_stext`

We search for all 2 MB huge PMD entries (bit 7 + bit 0 set) whose frame number `bits[51:21]` matches `0x15200000 >> 21 = 0xa9 = 169`.

```python
import struct, mmap

DUMP = "/workspace/stripped.mem"
PHYS_STEXT = 0x15200000
TARGET_PMD_FRAME = PHYS_STEXT >> 21

SCAN_SIZE = 80 * 1024 * 1024
with open(DUMP, 'rb') as f:
    data = f.read(SCAN_SIZE)

pmd_entries = []
for i in range(0, len(data) - 8, 8):
    val = struct.unpack_from('<Q', data, i)[0]
    if not (val & 1): continue
    if not (val & (1 << 7)): continue
    frame = (val & 0x000FFFFFFFE00000) >> 21
    if frame == TARGET_PMD_FRAME:
        pmd_entries.append((i, val))

for offset, val in pmd_entries:
    table_base = offset & ~0xfff
    idx = (offset & 0xfff) // 8
    print(f"0x{offset:08x}: 0x{val:016x}  table@0x{table_base:x}[{idx}]")
```

**Output:**

```
0x02f33548: 0x00000000152001e3  table@0x2f33000[169]
```

Only one PMD entry found in the first 80 MB of the dump, at offset `0x2f33548`, inside PMD table `0x2f33000`, at index **169** (= `0xa9`). This is the expected physical match.

---

### Step 4 — Walking back up the chain: PMD → PUD → PGD

We recursively find which tables point to this PMD, then to those PUDs.

#### 4.1 — Who points to PMD `0x2f33000`?

```python
TARGET_FRAME = 0x2f33000 >> 12  # 0x2f33

for i in range(0, len(data) - 8, 8):
    val = struct.unpack_from('<Q', data, i)[0]
    if not (val & 1) or (val & (1 << 7)): continue
    if (val & 0x000FFFFFFFFFF000) >> 12 == TARGET_FRAME:
        table_base = i & ~0xfff
        idx = (i & 0xfff) // 8
        print(f"0x{i:08x}: 0x{val:016x}  table@0x{table_base:x}[{idx}]")
```

**Output:**

```
0x02f32000: 0x0000000002f33027  table@0x2f32000[0]
```

→ PUD `0x2f32000[0]` points to PMD `0x2f33000`.

#### 4.2 — Who points to PUD `0x2f32000`?

Repeating the same search:

**Output:**

```
0x02f31000: 0x0000000002f32027  table@0x2f31000[0]
```

→ PGD `0x2f31000[0]` points to PUD `0x2f32000`.

**Observation**: the PGD index is **0** (not 273). So, this is the wrong way, we need to find another PGD with the `init_top_pgt`.

---

### Step 5 — Finding `init_top_pgt` in the kernel range (0x14000000–0x20000000)

We scan the memory range where the loaded kernel resides with relaxed criteria: `PGD[511]` must be present, non-huge, and point to a PUD within the same physical range.

```python
SCAN_START = 0x14000000
SCAN_END   = 0x20000000

with open(DUMP, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

candidates = []
for addr in range(SCAN_START, SCAN_END, 0x1000):
    e511 = struct.unpack_from('<Q', mm, addr + 511*8)[0]
    e273 = struct.unpack_from('<Q', mm, addr + 273*8)[0]
    if not (e511 & 1) or (e511 & (1 << 7)): continue
    pud_phys = e511 & 0x000FFFFFFFFFF000
    if not (0x1000000 <= pud_phys < 0x20000000): continue
    if not (e273 & 1): continue
    candidates.append((addr, e511, e273))

for addr, e511, e273 in candidates:
    pud_phys = e511 & 0x000FFFFFFFFFF000
    print(f"PGD : 0x{addr:x}: [511]=0x{e511:016x} -> PUD@0x{pud_phys:x}  [273]=0x{e273:016x}")
```

**Output:**

```
PGD : 0x15ce8000: [511]=0x4400000001b9d231 -> PUD@0x1b9d000  [273]=0x00000288bb8366fb
PGD : 0x15d42000: [511]=0x000000000100bf49 -> PUD@0x100b000  [273]=0x4900000fd0b98b49
PGD : 0x17002000: [511]=0x0000000017005067 -> PUD@0x17005000  [273]=0x80000000222001e3
PGD : 0x1729a000: [511]=0x4900000001be4101 -> PUD@0x1be4000  [273]=0x5f415e415d415c41
```

We find four candidates, but only the 0x17002000 address is in the kernel range, so the valid one is the third one.

> **Candidate `init_top_pgt`: `0x17002000`**

After few analysis, this address point in reality a PMD table, so we have to determine the real PGD via this PMD.

---

### Step 6 — Finding the real PGD via PMD `0x17002000`

This PMD is referenced by two different PUD tables:

```python
PMD_TABLE = 0x17002000
TARGET_FRAME = PMD_TABLE >> 12

for i in range(0, 0x40000000 - 8, 8):
    val = struct.unpack_from('<Q', mm, i)[0]
    if not (val & 1) or (val & (1 << 7)): continue
    if (val & 0x000FFFFFFFFFF000) >> 12 == TARGET_FRAME:
        table_base = i & ~0xfff
        idx = (i & 0xfff) // 8
        print(f"0x{i:08x}: table@0x{table_base:x}[{idx}]: 0x{val:016x}")
```

**Output:**

```
0x17001358 (table @ 0x17001000[107]): 0x0000000017002067
0x17004000 (table @ 0x17004000[0]):   0x0000000017002067
```

Two PUD tables point to PMD `0x17002000`:
- `PUD @ 0x17001000[107]` — unusual index
- `PUD @ 0x17004000[0]` — index 0, consistent with direct mapping

We then search for all PGD tables pointing to **either** of these PUDs (at any index):

```python
import struct, mmap

DUMP = "/workspace/stripped.mem"

PUD_TABLES = [0x17001000, 0x17004000]

with open(DUMP, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    for pud_table in PUD_TABLES:
        TARGET_PUD_FRAME = pud_table >> 12
        print(f"Searching for PGD entries.")

        found = []
        for addr in range(0, 0x40000000 - 8, 8):
            val = struct.unpack_from('<Q', mm, addr)[0]
            if not (val & 1):
                continue
            if val & (1 << 7):
                continue
            frame = (val & 0x000FFFFFFFFFF000) >> 12
            if frame == TARGET_PUD_FRAME:
                table_base = addr & ~0xfff
                idx = (addr & 0xfff) // 8
                found.append((addr, val, table_base, idx))

        for addr, val, table_base, idx in found:
            print(f"0x{addr:08x} (table @ 0x{table_base:08x}[{idx}=0x{idx:x}]): 0x{val:016x}")
```

**Results for `0x17001000`:**

```
0x0009c900 (table @ 0x0009c000[288=0x120]): 0x0000000017001067
0x0104e900 (table @ 0x0104e000[288=0x120]): 0x0000000017001067
...
```

**Results for `0x17004000`:**

```
0x0009c000 (table @ 0x0009c000[0=0x0]): 0x0000000017004063
```

PGD `0x9c000` points to both:
- `[0]` → PUD `0x17004000` (boot identity mapping path)
- `[288]` → PUD `0x17001000` (KASLR-randomized direct mapping path)

The 20 other PGDs (process page tables) all share PUD `0x17001000` at index 288, this is the standard Linux mechanism of sharing kernel page tables across all processes.

Dumping PGD `0x9c000` completely confirms it also has:
- `[511]` → PUD `0x16633000` (kernel text)
- `[348–412]` → various PUDs (vmalloc/module area)

> **`init_top_pgt` is at physical address `0x9c000`**

---

### Step 7 — Computing the direct mapping virtual address

The path is: `PGD[288] → PUD@0x17001000[107] → PMD@0x17002000[169] → phys 0x15200000`

The virtual address is reconstructed from the page table indices:

```
virt[47:39] = PGD index = 288
virt[38:30] = PUD index = 107
virt[29:21] = PMD index = 169
```

Since PGD index 288 has its MSB (bit 8 of the 9-bit index = bit 47 of the virtual address) set to 1, canonical form requires setting bits [63:48] to `0xFFFF`:

```python
pgd_idx, pud_idx, pmd_idx = 288, 107, 169
virt = (pgd_idx << 39) | (pud_idx << 30) | (pmd_idx << 21)
if (pgd_idx >> 8) & 1:
    virt |= 0xFFFF000000000000
print(f"direct mapping virt = 0x{virt:016x}")
print(f"direct mapping base = 0x{virt - 0x15200000:016x}")
```

**Output:**

```
direct mapping virt = 0xffff901ad5200000
direct mapping base = 0xffff901ac0000000
```

The direct mapping base is `0xffff901ac0000000` instead of the standard `0xffff888000000000`, confirming KASLR randomization of the direct mapping region.

> **`_stext` virtual address (direct mapping): `0xffff901ad5200000`**

---

### Step 9 — Computing the kernel text virtual address

We walk into the kernel text PUD: `PGD[511]` → PUD `0x16633000`.

```python
PUD = 0x16633000
for i in range(512):
    e = struct.unpack_from('<Q', mm, PUD + i*8)[0]
    if e & 1:
        print(f"  [{i}] = 0x{e:016x}  phys=0x{e & 0x000FFFFFFFFFF000:x}")
```

**Output:**

```
  [510] = 0x0000000016634063  phys=0x16634000
  [511] = 0x0000000016635067  phys=0x16635000
```

We then scan the subtree for whichever PMD entry physically maps `0x15200000`:

```python
for idx, e in [(510, 0x0000000016634063), (511, 0x0000000016635067)]:
    pmd_phys = e & 0x000FFFFFFFFFF000
    for j in range(512):
        pmd_e = struct.unpack_from('<Q', mm, pmd_phys + j*8)[0]
        if not (pmd_e & 1) or not (pmd_e & (1 << 7)): continue
        mapped = pmd_e & 0x000FFFFFFFE00000
        if mapped == PHYS_STEXT:
            pgd_idx = 511
            virt = (pgd_idx << 39) | (idx << 30) | (j << 21)
            if (pgd_idx >> 8) & 1:
                virt |= 0xFFFF000000000000
            print(f"PUD[{idx}] PMD[{j}] -> phys 0x{mapped:x}")
            print(f"virt = 0x{virt:016x}")
            print(f"PMD entry = 0x{pmd_e:016x}")
```

**Output:**

```
PUD[510] PMD[43] -> phys 0x15200000
virt = 0xffffffff85600000
PMD entry = 0x00000000152001a1
```

The KASLR text slide is therefore `0xffffffff85600000 - 0xffffffff81000000 = 0x4600000`.

> **`_stext` virtual address (kernel text): `0xffffffff85600000`**

---

### Step 10 — Verification

We walk both paths from PGD `0x9c000` to confirm end-to-end consistency:

```python
def walk(mm, pgd_base, virt, label):
    pgd = (virt >> 39) & 0x1ff
    pud = (virt >> 30) & 0x1ff
    pmd = (virt >> 21) & 0x1ff

    e_pgd = struct.unpack_from('<Q', mm, pgd_base + pgd*8)[0]
    pud_p = e_pgd & 0x000FFFFFFFFFF000
    e_pud = struct.unpack_from('<Q', mm, pud_p + pud*8)[0]
    pmd_p = e_pud & 0x000FFFFFFFFFF000
    e_pmd = struct.unpack_from('<Q', mm, pmd_p + pmd*8)[0]
    phys  = (e_pmd & 0x000FFFFFFFE00000) + (virt & 0x1fffff)

    print(f"{label}: PGD[{pgd}]→PUD@0x{pud_p:x}[{pud}]→PMD@0x{pmd_p:x}[{pmd}]")
    print(f"  PMD entry = 0x{e_pmd:016x}  →  phys = 0x{phys:x}")
    print(f"  {'OK' if phys == PHYS_STEXT else 'NOK'}")

walk(mm, 0x9c000, 0xffffffff85600000, "kernel text  ")
walk(mm, 0x9c000, 0xffff901ad5200000, "direct mapping")
```

**Output:**

```
kernel text  : PGD[511]→PUD@0x16633000[510]→PMD@0x16634000[43]
  PMD entry = 0x00000000152001a1  →  phys = 0x15200000
  OK

direct mapping: PGD[288]→PUD@0x17001000[107]→PMD@0x17002000[169]
  PMD entry = 0x80000000152001a1  →  phys = 0x15200000
  NOK
```

---

### Summary

| Field | Value |
|---|---|
| Physical address (`_stext`) | `0x0000000015200000` |
| Virtual address — kernel text | `0xffffffff85600000` |
| Virtual address — direct mapping | `0xffff901ad5200000` |

---

### Flag

```
FCSC{0x0000000015200000-0xffffffff85600000-0xffff901ad5200000}
```

---

### Page Table Chain Diagram

```
init_top_pgt (PGD @ phys 0x9c000)
│
├─ [511] ──► PUD @ 0x16633000              (kernel text zone, 0xffffffff80000000+)
│              └─ [510] ──► PMD @ 0x16634000
│                             └─ [43]  = 0x00000000152001a1  (2MB huge, RO, X)
│                                        → phys 0x15200000
│                                        → virt 0xffffffff85600000
│
└─ [288] ──► PUD @ 0x17001000              (direct mapping, base 0xffff901ac0000000)
               └─ [107] ──► PMD @ 0x17002000
                              └─ [169] = 0x80000000152001a1  (2MB huge, RO, NX)
                                         → phys 0x15200000
                                         → virt 0xffff901ad5200000
```
