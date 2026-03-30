# API Reference

All functions are declared in `<libload.h>`.

## Types

### `libload_t`

```c
typedef struct libload_ctx *libload_t;
```

Opaque handle representing a loaded library. Returned by `libload_open`, used with `libload_sym` and `libload_close`.

---

## Loading Functions

### `libload_open`

```c
libload_t libload_open(const unsigned char *buf, size_t len);
```

Load a shared library or executable from a memory buffer.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `buf` | Pointer to the binary data (ELF, Mach-O, or llbin) |
| `len` | Size of the buffer in bytes |

**Returns:** Handle on success, `NULL` on failure.

**Behavior:**

- Auto-detects the binary format by examining magic bytes:
  - `LLBN` (0x4E424C4C) → llbin fast path
  - `\x7fELF` → reflective ELF loader (Linux)
  - `\xFE\xED\xFA` / `\xCF\xFA\xED\xFE` → Mach-O loader (macOS)
  - Fat/universal headers → extracts the native architecture slice
- On Linux: parses ELF headers, maps segments, processes relocations, resolves imports, runs constructors
- On macOS: parses Mach-O load commands, dual-maps segments (RW+RX), processes fixups, runs initializers
- The buffer can be freed after this call returns

**Supported binary types:**

| Platform | Types |
|----------|-------|
| Linux | ELF shared objects (`ET_DYN`), executables (`ET_EXEC`), llbin |
| macOS | `MH_DYLIB`, `MH_BUNDLE`, `MH_EXECUTE`, llbin |

---

### `libload_sym`

```c
void *libload_sym(libload_t ctx, const char *name);
```

Resolve an exported symbol from a loaded library.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `ctx` | Handle from `libload_open` |
| `name` | Symbol name (C string) |

**Returns:** Symbol address, or `NULL` if not found.

**Behavior:**

- On Linux: walks the ELF dynamic symbol table (`.dynsym` + `.dynstr`), using GNU hash or SysV hash for lookup
- On macOS: walks the Mach-O export trie (`LC_DYLD_INFO_ONLY` or `LC_DYLD_EXPORTS_TRIE`)

---

### `libload_close`

```c
int libload_close(libload_t ctx);
```

Unload a previously loaded library and free associated resources.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `ctx` | Handle from `libload_open` |

**Returns:** 0 on success, -1 on failure.

**Behavior:**

- Runs destructors (`.fini_array` on Linux, `__mod_term_func` on macOS)
- Unmaps allocated memory
- Frees the context structure

---

## Execution Functions

### `libload_exec`

```c
pid_t libload_exec(const unsigned char *buf, size_t len,
                   char *const argv[], char *const envp[]);
```

Execute an executable from a memory buffer in a forked child process.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `buf` | Pointer to the executable data |
| `len` | Size of the buffer in bytes |
| `argv` | NULL-terminated argument vector |
| `envp` | NULL-terminated environment vector (NULL = inherit) |

**Returns:** Child PID on success, -1 on failure.

**Behavior:**

1. Forks the current process
2. In the child: loads the executable via the reflective loader
3. Sets up the initial stack (argc, argv, envp, auxiliary vector)
4. Jumps to the entry point via the architecture-specific trampoline
5. The parent returns immediately with the child PID

The child process runs the loaded executable as if it had been started normally by the kernel. Use `waitpid()` to collect the exit status.

**Example:**

```c
char *argv[] = { "myprogram", "--flag", NULL };
pid_t pid = libload_exec(buf, len, argv, NULL);
if (pid > 0) {
    int status;
    waitpid(pid, &status, 0);
    printf("exited: %d\n", WEXITSTATUS(status));
}
```

---

### `libload_run`

```c
int libload_run(const unsigned char *buf, size_t len,
                char *const argv[], char *const envp[]);
```

Execute an executable from a memory buffer, replacing the current process.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `buf` | Pointer to the executable data |
| `len` | Size of the buffer in bytes |
| `argv` | NULL-terminated argument vector |
| `envp` | NULL-terminated environment vector (NULL = inherit) |

**Returns:** -1 on failure. **Does not return on success.**

**Behavior:**

Identical to `libload_exec` except it does not fork. The current process image is replaced by the loaded executable. This is analogous to `execve()` but from a memory buffer.

---

## Injection Functions

All injection functions are platform-specific and conditionally compiled. They are available when `__APPLE__` or `__linux__` is defined.

### `libload_inject`

```c
int libload_inject(pid_t pid, const void *code, size_t len,
                   size_t entry_offset, uint64_t arg);
```

Inject position-independent code (PIC) into a running process and execute it.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `pid` | Target process ID |
| `code` | Pointer to PIC machine code |
| `len` | Size of the code in bytes |
| `entry_offset` | Byte offset within `code` where execution should start |
| `arg` | 64-bit argument passed to the injected code (in the first argument register) |

**Returns:** 0 on success, -1 on failure.

**Platform behavior:**

| Platform | Mechanism | Requirements |
|----------|-----------|--------------|
| Linux | ptrace attach → find syscall instruction → proxy mmap/mprotect/clone via remote syscalls → write code via `process_vm_writev` | ptrace access (Yama scope 0 or `CAP_SYS_PTRACE`) |
| macOS | Mach task port → `mach_vm_allocate` + `mach_vm_write` → `mach_vm_protect(RX)` → `thread_create_running` | `task_for_pid` access (root, or `get-task-allow`) |

**Notes:**
- The code must be fully position-independent — it will be loaded at an arbitrary address
- On macOS, this fails on Hardened Runtime targets (AMFI blocks unsigned RX pages)
- On Linux, the injected code runs as a new thread in the target process

---

### `libload_inject_dylib`

```c
/* macOS */
int libload_inject_dylib(pid_t pid, const char *dylib_path);

/* Linux */
int libload_inject_dylib(pid_t pid, const char *so_path);
```

Inject a shared library into a running process by triggering `dlopen()`.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `pid` | Target process ID |
| `dylib_path` / `so_path` | Absolute path to the library to inject |

**Returns:** 0 on success, -1 on failure.

**Platform behavior:**

| Platform | Mechanism | Requirements |
|----------|-----------|--------------|
| Linux | ptrace attach → hijack thread registers → set PC to `dlopen` with path argument → wait for return → restore registers | ptrace access |
| macOS | Mach task port → hijack thread → set PC to `dlopen` with LR pointing to a BRK trap → catch exception on return → restore | `task_for_pid` access |

**Notes:**
- The library path must be an **absolute path** accessible to the target process
- The library's constructors (`__attribute__((constructor))`) run in the target process
- Works on macOS Hardened Runtime targets (no new executable pages are created)
- On Linux, uses the target's own `dlopen` symbol resolved via `/proc/<pid>/maps`

---

### `libload_inject_spawn`

```c
pid_t libload_inject_spawn(const char *target_path,
                           const char *lib_path,
                           char *const argv[],
                           char *const envp[]);
```

Spawn a new process with a library pre-injected.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `target_path` | Path to the executable to spawn |
| `lib_path` | Absolute path to the library to inject |
| `argv` | NULL-terminated argument vector for the target |
| `envp` | NULL-terminated environment vector (NULL = inherit) |

**Returns:** Spawned PID on success, -1 on failure.

**Platform behavior:**

| Platform | Mechanism | Requirements |
|----------|-----------|--------------|
| Linux | `fork()` + set `LD_PRELOAD` environment variable + `execve()` | None |
| macOS | Exception port inheritance across `fork()`+`exec()` → catch `EXC_BREAKPOINT` → thread-hijack to `dlopen()` → resume | None (no root, no entitlements) |

**Notes:**
- **Linux**: Simple and reliable, but does not work on statically-linked or setuid binaries. The dynamic linker loads the `.so` before `main()`, running constructors.
- **macOS**: Uses a novel zero-privilege technique exploiting Mach exception port inheritance. See [EXCEPTION_PORT_INJECTION.md](../EXCEPTION_PORT_INJECTION.md) for the full technical writeup. Works on Hardened Runtime binaries (non-platform). Does NOT work on Apple platform binaries (`/usr/bin/*`, `/System/*`).
