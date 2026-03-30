# Process Injection

libload provides three injection methods on each platform. This document covers the technical details of each method.

## Method Summary

| Method | Function | Linux Mechanism | macOS Mechanism |
|--------|----------|----------------|-----------------|
| PIC injection | `libload_inject` | ptrace + syscall proxy | Mach task port + thread create |
| Library injection | `libload_inject_dylib` | ptrace + remote dlopen | Mach task port + thread hijack |
| Spawn injection | `libload_inject_spawn` | LD_PRELOAD | Exception port inheritance |

## Privilege Requirements

### Linux

| Method | Requirement |
|--------|-------------|
| `libload_inject` | ptrace access: Yama scope 0 (`/proc/sys/kernel/yama/ptrace_scope`), or `CAP_SYS_PTRACE`, or target is a direct child |
| `libload_inject_dylib` | Same as above |
| `libload_inject_spawn` | **None** |

To check Yama scope:
```sh
cat /proc/sys/kernel/yama/ptrace_scope
# 0 = any process can ptrace any other (if same UID)
# 1 = only direct parent can ptrace (default on Ubuntu)
# 2 = admin only
# 3 = no ptrace at all
```

To temporarily allow ptrace:
```sh
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### macOS

| Method | Requirement |
|--------|-------------|
| `libload_inject` | `task_for_pid` access: root, or target built with `get-task-allow` entitlement |
| `libload_inject_dylib` | Same as above |
| `libload_inject_spawn` | **None** (no root, no entitlements) |

---

## Method 1: PIC Code Injection (`libload_inject`)

Injects raw position-independent machine code into a running process and executes it as a new thread.

### Linux Implementation

The Linux PIC injection uses ptrace to proxy syscalls in the target process:

```
Injector                           Target
   │                                  │
   ├── PTRACE_ATTACH ────────────────►│ (stopped)
   │                                  │
   ├── Save registers                 │
   │                                  │
   ├── Find SYSCALL instruction       │ (scan /proc/pid/mem)
   │   in target's memory             │
   │                                  │
   ├── Remote mmap() ───────────────► │ allocate RW region
   │   (set regs, PTRACE_SYSCALL)     │
   │                                  │
   ├── process_vm_writev() ──────────►│ write PIC code
   │                                  │
   ├── Remote mprotect() ───────────► │ RW → RX
   │                                  │
   ├── Remote clone() ──────────────► │ new thread at entry
   │                                  │
   ├── Restore registers              │
   ├── PTRACE_DETACH ────────────────►│ (resumed)
   │                                  │
```

**Finding the syscall instruction**: The injector scans the target's executable memory regions (via `/proc/<pid>/maps` and `/proc/<pid>/mem`) looking for the architecture-specific syscall instruction:

| Architecture | Instruction | Bytes |
|-------------|-------------|-------|
| x86_64 | `syscall` | `0F 05` |
| i386 | `int 0x80` | `CD 80` |
| aarch64 | `svc #0` | `01 00 00 D4` |
| ARM | `svc #0` | `00 00 00 EF` (ARM) or `00 DF` (Thumb) |
| MIPS | `syscall` | `0C 00 00 00` |
| SPARC | `ta 0x10` | `91 D0 20 10` |

**Syscall proxying**: To execute a syscall in the target, the injector:
1. Saves the target's registers
2. Sets the syscall number and arguments in the appropriate registers
3. Sets PC to the found syscall instruction
4. Calls `PTRACE_SYSCALL` to execute one syscall
5. Reads the return value from the result register
6. Restores the original registers

Register ABIs for syscall arguments:

| Architecture | Syscall # | Arg1 | Arg2 | Arg3 | Arg4 | Arg5 | Arg6 | Return |
|-------------|-----------|------|------|------|------|------|------|--------|
| x86_64 | rax | rdi | rsi | rdx | r10 | r8 | r9 | rax |
| i386 | eax | ebx | ecx | edx | esi | edi | ebp | eax |
| aarch64 | x8 | x0 | x1 | x2 | x3 | x4 | x5 | x0 |
| ARM | r7 | r0 | r1 | r2 | r3 | r4 | r5 | r0 |
| MIPS | v0 | a0 | a1 | a2 | a3 | stack | stack | v0 |
| SPARC | g1 | o0 | o1 | o2 | o3 | o4 | o5 | o0 |

**MIPS special case**: Arguments 5 and 6 are passed on the stack (at `sp+16` and `sp+20`), not in registers. The injector writes them via `PTRACE_POKEDATA`.

**MIPS/SPARC error handling**: These architectures signal errors via a separate flag register (`a3` on MIPS, the carry bit in `psr` on SPARC) rather than returning negative values.

**32-bit sign extension**: On 32-bit architectures, syscall return values are sign-extended to 64-bit for consistent error checking: `(int64_t)(int32_t)retval`.

### macOS Implementation

macOS PIC injection uses Mach APIs:

1. `task_for_pid(pid)` → obtain task port
2. `mach_vm_allocate(task, &addr, size, VM_FLAGS_ANYWHERE)` → allocate in target
3. `mach_vm_write(task, addr, code, len)` → copy code
4. `mach_vm_protect(task, addr, size, FALSE, VM_PROT_READ|VM_PROT_EXECUTE)` → mark RX
5. `thread_create_running(task, ARM_THREAD_STATE64, state, count, &thread)` → start execution

The `arg` parameter is passed in register x0 (arm64) or rdi (x86_64).

**Limitation**: Fails on Hardened Runtime targets because AMFI kills the process when unsigned executable pages are created.

### Writing PIC Code

The injected code must be fully position-independent since it will be loaded at an arbitrary address. Example (aarch64, creates a marker file):

```c
static const unsigned char pic_payload[] = {
    /* adr x1, path (PC-relative) */
    0x21, 0x01, 0x00, 0x10,
    /* movn w0, #99 → AT_FDCWD */
    0x60, 0x0c, 0x80, 0x12,
    /* mov x2, #0x241 (O_WRONLY|O_CREAT|O_TRUNC) */
    0x22, 0x48, 0x80, 0xd2,
    /* mov x3, #0x1a4 (0644) */
    0x83, 0x34, 0x80, 0xd2,
    /* mov x8, #56 (__NR_openat) */
    0x08, 0x07, 0x80, 0xd2,
    /* svc #0 */
    0x01, 0x00, 0x00, 0xd4,
    /* mov x8, #57 (__NR_close) */
    0x28, 0x07, 0x80, 0xd2,
    /* svc #0 */
    0x01, 0x00, 0x00, 0xd4,
    /* ret */
    0xc0, 0x03, 0x5f, 0xd6,
    /* NUL-terminated path string */
    '/', 't', 'm', 'p', '/', 'm', 'a', 'r',
    'k', 'e', 'r', '\0',
};

libload_inject(pid, pic_payload, sizeof(pic_payload), 0, 0);
```

---

## Method 2: Library Injection (`libload_inject_dylib`)

Injects a shared library by hijacking a thread to call `dlopen()` in the target process. No new executable pages are created.

### Linux Implementation

```
Injector                           Target
   │                                  │
   ├── PTRACE_ATTACH ────────────────►│ (stopped)
   │                                  │
   ├── Save all registers             │
   │                                  │
   ├── Find dlopen address            │ (parse /proc/pid/maps
   │   in target's libc               │  + symbol tables)
   │                                  │
   ├── Write library path ───────────►│ (via process_vm_writev
   │   to target stack                │  or stack manipulation)
   │                                  │
   ├── Set PC = dlopen ──────────────►│
   │   Set arg1 = path_addr           │
   │   Set arg2 = RTLD_NOW            │
   │   Set return addr = trap         │
   │                                  │
   ├── PTRACE_CONT ──────────────────►│ dlopen() runs
   │                                  │  constructors execute
   │                                  │  returns to trap
   │                                  │
   ├── Catch SIGTRAP/SIGSTOP ◄────────│
   │                                  │
   ├── Restore all registers          │
   ├── PTRACE_DETACH ────────────────►│ (resumed, library loaded)
```

The injector resolves the address of `dlopen` in the target by:
1. Reading `/proc/<pid>/maps` to find the base of libc/libdl
2. Parsing the ELF symbol table to find `dlopen`'s offset
3. Adding the offset to the mapped base

### macOS Implementation

Similar to Linux but using Mach APIs:

1. Obtain task port
2. Suspend target thread, save state via `thread_get_state`
3. Write dylib path into target via `mach_vm_allocate` + `mach_vm_write`
4. Set PC to `dlopen`, x0 to path address, x1 to `RTLD_NOW`, LR to a `BRK #1` instruction
5. Resume thread via `thread_set_state` + `thread_resume`
6. Catch `EXC_BREAKPOINT` on exception port when `dlopen` returns
7. Restore original thread state

### Library Requirements

- The library path must be **absolute**
- The library must be accessible (readable) by the target process
- Constructors (`__attribute__((constructor))`) run during `dlopen`
- On macOS, the library must be properly code-signed (ad-hoc signing is sufficient)

---

## Method 3: Spawn Injection (`libload_inject_spawn`)

Spawns a new process with a library pre-loaded. Requires **no privileges**.

### Linux Implementation

Uses `LD_PRELOAD`, the standard dynamic linker mechanism:

```c
pid_t pid = fork();
if (pid == 0) {
    setenv("LD_PRELOAD", so_path, 1);
    execve(target_path, argv, envp);
}
```

The dynamic linker loads the `.so` before `main()`, running its constructors.

**Limitations:**
- Does not work on statically-linked binaries (no dynamic linker)
- Does not work on setuid/setgid binaries (`LD_PRELOAD` is ignored)
- The `.so` must be compatible with the target's architecture and libc

### macOS Implementation

Uses a novel zero-privilege technique based on Mach exception port inheritance:

1. Copy target binary, patch entry point with `BRK #1`, ad-hoc re-sign (HR targets only)
2. Set exception ports on self (`task_swap_exception_ports`)
3. `fork()` — child inherits exception port registrations
4. Child `exec()`s into the target — exception ports survive exec
5. Target hits `BRK` → kernel delivers `EXC_BREAKPOINT` with full task control port
6. Parent hijacks thread to call `dlopen(payload_path)`
7. Catch return exception, skip past `BRK`, resume normally

**Key insight:** Exception ports are task-level state that survives `fork()` + `exec()`. The task control port delivered in the exception message bypasses `task_for_pid` access controls entirely, even for Hardened Runtime binaries.

For the complete technical analysis, see [EXCEPTION_PORT_INJECTION.md](../EXCEPTION_PORT_INJECTION.md).

**Limitations:**
- Does not work on Apple platform binaries (`/usr/bin/*`, `/System/*`)
- HR targets require a temporary binary copy on disk (deleted after injection)
- Spawn only — cannot inject into already-running processes

---

## Choosing an Injection Method

### For running Linux processes:

| Scenario | Recommended Method |
|----------|--------------------|
| Full control, custom code | `libload_inject` (PIC) |
| Load a .so with constructors | `libload_inject_dylib` |
| No ptrace access | Not possible (use spawn instead) |

### For spawning Linux processes:

| Scenario | Recommended Method |
|----------|--------------------|
| Inject before main() | `libload_inject_spawn` (LD_PRELOAD) |

### For running macOS processes:

| Scenario | Recommended Method |
|----------|--------------------|
| Non-HR target, custom code | `libload_inject` (PIC) |
| Any target with task_for_pid | `libload_inject_dylib` |
| No root/entitlements | Not possible (use spawn instead) |

### For spawning macOS processes:

| Scenario | Recommended Method |
|----------|--------------------|
| Any non-platform binary | `libload_inject_spawn` |
| Hardened Runtime binary | `libload_inject_spawn` |
| Apple platform binary | Not supported |
