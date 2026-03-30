# Architecture Overview

libload is a C library for loading and executing binaries entirely from memory, with no filesystem artifacts. It provides a unified API across Linux and macOS, with platform-specific implementations underneath.

## Design Principles

1. **No disk writes** — all loading happens from memory buffers. No temp files, no `memfd_create`, no `/proc/self/fd`.
2. **Minimal dependencies** — only libc and system headers. No external libraries.
3. **Compile-time architecture selection** — the correct code path is selected by preprocessor macros (`__x86_64__`, `__aarch64__`, `__i386__`, `__arm__`, `__mips__`, `__sparc__`). A single build targets one architecture.
4. **Single header API** — `#include <libload.h>` provides everything.

## Component Map

```
include/
  libload.h          Public API header
  llbin.h            llbin format structures

src/
  elf.c              Linux: reflective ELF loader + userland exec
  elf_inject.c       Linux: ptrace-based process injection
  entry_x86_64.S     Linux: x86_64 entry trampoline
  entry_aarch64.S    Linux: aarch64 entry trampoline
  entry_x86.S        Linux: i386 entry trampoline
  entry_arm.S        Linux: ARM32 entry trampoline
  entry_mips.S       Linux: MIPS entry trampoline
  entry_sparc.S      Linux: SPARC entry trampoline
  macho.c            macOS: reflective Mach-O loader
  inject.c           macOS: Mach port-based process injection

tools/
  llpack.c           C packer: ELF/Mach-O → llbin
  lltool.py          Python3 packer: ELF/Mach-O → llbin

examples/
  common/
    test_exec.c        In-memory execution test (libload_exec)
    test_llbin.c       llbin format execution test
    test_open.c        Reflective loading test (libload_open/sym/close)
    test_lib.c         Shared library target for test_open
    testexec.c         Simple test executable
    testexec_edge.c    Edge-case test executable
    inject_target.c    Target process for injection tests
    inject_payload.c   Payload library for injection tests
  linux/
    test_inject.c      PIC injection test (libload_inject)
    test_inject_dylib.c  Remote dlopen test (libload_inject_dylib)
    test_inject_spawn.c  LD_PRELOAD test (libload_inject_spawn)
    testexec_nolibc.c  No-libc raw syscall test
  macos/
    test_inject.c      PIC injection test (libload_inject)
    test_inject_dylib.c  Remote dlopen test (libload_inject_dylib)
    test_inject_spawn.c  Exception port test (libload_inject_spawn)
    testexec_objc.m    Objective-C runtime test
```

## How It Works

### Loading (`libload_open`)

The loader accepts a raw memory buffer containing an ELF shared object (Linux), Mach-O dylib/bundle/executable (macOS), or an llbin pre-packed binary (both platforms).

**Linux ELF path:**
1. Parse ELF headers (ELF32 or ELF64 based on pointer size)
2. Map LOAD segments into process memory via `mmap`
3. Process relocations (REL, RELA, JMPREL) with architecture-specific handlers
4. Resolve imports via `dlsym(RTLD_DEFAULT, ...)`
5. Flush instruction cache on architectures that require it
6. Run `.init` and `.init_array` constructors
7. Return handle for symbol lookup

**macOS Mach-O path:**
1. Parse Mach-O headers (handles fat/universal binaries)
2. Allocate memory via dual-map (`mach_vm_remap` — RW and RX views of the same physical pages) for W^X compliance
3. Process relocations:
   - `LC_DYLD_INFO_ONLY`: legacy rebase/bind opcode streams
   - `LC_DYLD_CHAINED_FIXUPS`: modern chained fixup format (macOS 12+)
4. Resolve imports via `dlsym(RTLD_DEFAULT, ...)`
5. Walk the export trie for `libload_sym` lookups
6. Run `__mod_init_func` constructors
7. Set per-segment memory protections

**llbin fast path:**
1. Detect `LLBN` magic at buffer start
2. Allocate a single contiguous region
3. Copy flat image
4. Walk fixup table (rebases + imports)
5. Set protections, flush icache, done

### Execution (`libload_exec` / `libload_run`)

These functions execute a complete executable (not a shared library) from memory.

- `libload_exec`: forks, loads in the child, jumps to entry. Returns child PID.
- `libload_run`: loads in-place, replaces the current process. Does not return on success.

The entry trampoline (architecture-specific `.S` file) sets up the initial stack frame (argc, argv, envp, auxv) matching what the kernel would provide, then jumps to the executable's entry point.

### Injection (`libload_inject*`)

Three injection methods are available on each platform:

| Method | Linux | macOS | Privileges |
|--------|-------|-------|------------|
| `libload_inject` | ptrace + syscall proxy | Mach task port + thread create | ptrace / task_for_pid |
| `libload_inject_dylib` | ptrace + remote dlopen | Mach task port + thread hijack | ptrace / task_for_pid |
| `libload_inject_spawn` | LD_PRELOAD | Exception port inheritance | None |

See [injection.md](injection.md) for detailed descriptions.

## Architecture Selection

Architecture is selected at **compile time** via the compiler's predefined macros. There is no runtime dispatch — each build targets exactly one architecture. To build for a different target, use a cross-compiler:

```sh
# Native (host architecture)
cmake -B build

# Cross-compile for MIPS little-endian
cmake -B build -DCMAKE_C_COMPILER=mipsel-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=mipsel-linux-gnu-gcc

# Cross-compile for ARM32
cmake -B build -DCMAKE_C_COMPILER=arm-linux-gnueabi-gcc \
               -DCMAKE_ASM_COMPILER=arm-linux-gnueabi-gcc
```

The preprocessor selects:
- ELF class: `__SIZEOF_POINTER__ == 8` → ELF64, otherwise ELF32
- Relocation types: per-architecture `is_relative_reloc()` / `is_import_reloc()`
- Syscall ABI: register conventions and instruction patterns for ptrace injection
- Entry trampoline: CMake includes all `.S` files; the assembler only compiles the one matching the target architecture
