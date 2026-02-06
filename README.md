# sema

`sema` is a deterministic, rule-based *static* reverse-engineering aid for **x86-64 ELF** binaries (and also a fallback mode for raw x86-64 assembly text).

It tries to answer the reverse engineer’s “CPU-intent” questions without emulation:

- *What is this instruction doing in CPU terms?*
- *Where are the function boundaries and who calls what?*
- *Where are the obvious strings and where are they referenced from?*
- *Where does control flow branch, and where are the loop candidates?*
- *What is the stack doing (best-effort linear scan)?*

`sema` deliberately does **not** guess high-level meaning beyond what can be stated conservatively from static facts.

## Why you’d use this

Reverse engineering often starts with chaos: disassembly, unfamiliar instruction sequences, compiler noise, and too many details at once.

`sema` is meant to be the “first-pass notebook assistant” that:

- makes **deterministic** observations,
- prints **repeatable** structured output,
- and narrates instruction intent in a consistent way.

If you run it repeatedly over the same artifact, it should say the same things in the same order.

## What `sema` accepts

### 1) ELF mode (preferred)
Give `sema` an **x86-64 ELF** file path.

- Parses ELF sections.
- Disassembles `.text` via Capstone.
- Extracts function symbols when available.
- Falls back to heuristic function starts if symbols are missing.
- Extracts `.rodata` strings and tries to correlate RIP-relative references.

### 2) Assembly-text mode (fallback)
If the input file is not an ELF, `sema` treats it as text and attempts a simple “mnemonic + operands” parse.

This mode:

- does **not** disassemble,
- does **not** decode operands precisely,
- but still produces the same style of categories + narration.

## Build dependencies

You need:

- Zig (this repo is written for Zig 0.13.x)
- Capstone development files (library + headers)

On many distros the capstone package names look like:

- `capstone` / `capstone-devel`
- or `libcapstone-dev`

## Build

From the repo root:

```bash
zig build
```

Or via the Makefile:

```bash
make
```

## Install so it runs from any directory

### Option A: local install (recommended)
Installs to `~/.local/bin/sema` (no root required):

```bash
make install PREFIX=$HOME/.local
```

Then ensure `~/.local/bin` is on your `PATH`.

A common one-liner (Bash):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

(If you want it permanently, add that to your shell rc file.)

### Option B: system-wide install
Installs to `/usr/local/bin/sema` by default (often requires root):

```bash
sudo make install
```

Or to `/usr/bin`:

```bash
sudo make install PREFIX=/usr
```

## Usage

### Analyze an ELF

```bash
sema /path/to/binary
```

Example:

```bash
sema /bin/true
```

### Analyze “raw assembly text”

Create a file like:

```text
0x401000: mov rax, 60
0x401005: xor rdi, rdi
0x401008: syscall
```

Then:

```bash
sema snippet.asm
```

## Output overview

The output is intentionally structured and stable:

- Architecture
- Instruction Overview (category counts)
- Functions (name/start/end/type/calls)
- CPU Semantics (instruction-by-instruction narration)
- Syscalls (if present/inferred)
- Strings (if `.rodata` exists)
- Control Flow (conditional/unconditional jumps + loop back-edges)
- Memory Behavior (best-effort stack usage, `.data` RIP-relative references)
- Keywords (cmp/test counts, constants)

If you want the notebook-style deep dive docs (with diagrams), read:

- `docs/NOTEBOOK.md`

## Project layout

- `src/main.zig` — tiny entrypoint wrapper
- `src/analysis.zig` — all analysis logic (ELF parsing, disassembly, narration)
- `src/x86_64.zig` — x86-64 specific tables (syscalls, jcc meaning)
- `build.zig` — Zig build definition
- `Makefile` — convenience targets (`make`, `make install`, etc.)

## Notes on determinism

`sema` aims for deterministic output by:

- sorting function symbols by address
- deduping and sorting detected constants
- keeping analysis rule-based (no emulation)
- using conservative tables for syscalls and conditional jumps

## License

Choose a license if you plan to publish this.
