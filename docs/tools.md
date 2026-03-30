# Tools

libload includes two packing tools that convert ELF and Mach-O executables into the llbin pre-packed format. Both tools produce byte-identical output.

## llpack (C)

A C tool built as part of the standard CMake build.

### Usage

```sh
llpack <input> <output.llbin>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `input` | Path to a Mach-O or ELF executable |
| `output.llbin` | Path for the output llbin file |

### Example

```sh
# Build
cmake -B build && cmake --build build

# Pack an executable
build/llpack ./myprogram myprogram.llbin

# Verify it loads
build/test_llbin myprogram.llbin
```

### Supported Input Formats

| Format | Details |
|--------|---------|
| Mach-O 64-bit | `MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE` |
| Fat/Universal | Extracts the native architecture slice |
| ELF64 | x86_64, aarch64 |
| ELF32 | i386, ARM, MIPS, SPARC |

### What It Does

1. Parses the input binary's headers and load commands
2. Computes the flat image layout (all segments contiguous)
3. Extracts and classifies all relocations/fixups:
   - Internal pointer adjustments → `LLBIN_FIXUP_REBASE`
   - External symbol references → `LLBIN_FIXUP_IMPORT`
4. Builds the import and string tables
5. Writes the llbin file (header + image + fixup table + import table + strings + segments)

For Mach-O inputs, it processes:
- `LC_DYLD_INFO_ONLY` rebase/bind/lazy-bind opcode streams
- `LC_DYLD_CHAINED_FIXUPS` chained pointer fixups

For ELF inputs, it processes:
- `DT_RELA` / `DT_REL` relocation tables
- `DT_JMPREL` + `DT_PLTREL` PLT relocations
- Per-architecture relocation type classification

---

## lltool (Python 3)

A Python 3 tool with no external dependencies (stdlib only).

### Usage

```sh
# Pack a binary into llbin
python3 tools/lltool.py pack <input> <output.llbin>

# Inspect a binary (Mach-O, ELF, or llbin)
python3 tools/lltool.py info <file>
```

### Commands

#### `pack`

Converts a Mach-O or ELF executable into llbin format.

```sh
python3 tools/lltool.py pack ./myprogram myprogram.llbin
```

| Argument | Description |
|----------|-------------|
| `input` | Path to a Mach-O or ELF executable |
| `output` | Path for the output llbin file |

#### `info`

Displays detailed information about a binary file. Supports Mach-O, ELF, and llbin formats.

```sh
python3 tools/lltool.py info myprogram.llbin
```

Example output for an llbin:

```
=== llbin header ===
  magic:          0x4e424c4c (LLBN)
  version:        1
  arch:           0x0100000c (ARM64)
  entry_off:      0x3f40
  image_size:     0x8000 (32768)
  preferred_base: 0x100000000
  fixup_count:    142
  import_count:   8
  strings_size:   87
  seg_count:      3

=== imports ===
  [0] _printf
  [1] _malloc
  ...

=== segments ===
  [0] offset=0x0000 size=0x4000 prot=r-x
  [1] offset=0x4000 size=0x3000 prot=rw-
  [2] offset=0x7000 size=0x1000 prot=r--
```

Example output for an ELF:

```
=== ELF header ===
  class:   ELF64
  machine: EM_AARCH64 (183)
  type:    ET_DYN
  entry:   0x1060
  ...

=== program headers ===
  PT_LOAD  offset=0x0000 vaddr=0x0000 memsz=0x0800 flags=r--
  PT_LOAD  offset=0x1000 vaddr=0x1000 memsz=0x0200 flags=r-x
  ...

=== dynamic section ===
  DT_NEEDED: libc.so.6
  DT_RELA:   0x0580
  ...
```

### Advantage Over llpack

lltool requires only Python 3 (no compilation needed), making it useful for:
- Quickly inspecting binaries on any system with Python
- Packing in build scripts or CI pipelines
- Cross-platform use without a cross-compiler

### Verifying Equivalence

Both tools produce byte-identical output:

```sh
build/llpack ./program a.llbin
python3 tools/lltool.py pack ./program b.llbin
diff a.llbin b.llbin   # no output (identical)
```
