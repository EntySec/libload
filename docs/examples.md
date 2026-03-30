# Examples

The `examples/` directory contains test programs organized by platform:

```
examples/
├── common/       Cross-platform tests and support files
├── linux/        Linux-specific injection tests
└── macos/        macOS-specific injection tests
```

## Building Examples

All examples are built automatically by CMake:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

---

## Common — In-Memory Execution

### test_exec

Tests `libload_exec` — fork + reflective load from a memory buffer.

**Source:** `examples/common/test_exec.c`

```sh
build/test_exec                        # uses testexec by default
build/test_exec build/testexec_edge    # with edge-case binary
```

### test_llbin

Tests `libload_exec` with an llbin pre-packed binary.

**Source:** `examples/common/test_llbin.c`

```sh
build/llpack build/testexec testexec.llbin
build/test_llbin testexec.llbin
```

### test_open

Tests `libload_open`, `libload_sym`, and `libload_close` — reflective loading of a shared library from memory and symbol resolution.

**Source:** `examples/common/test_open.c`

```sh
# macOS
build/test_open build/test_lib.dylib

# Linux
build/test_open build/test_lib.so
```

---

## Common — Test Binaries

### testexec

Simple "hello world" binary that prints its arguments. Used as the default load target for `test_exec`.

**Source:** `examples/common/testexec.c`

### testexec_edge

Edge-case stress test: global data, BSS, function pointers, recursion, large stack frames, heap allocation.

**Source:** `examples/common/testexec_edge.c`

### inject_target

Loop process (60 seconds) that serves as the injection target for all injection tests.

**Source:** `examples/common/inject_target.c`

### inject_payload

Shared library payload for injection tests. Constructor creates `/tmp/libload_inject_ok` marker file.

**Source:** `examples/common/inject_payload.c`

### test_lib

Minimal shared library exporting `test_add(int, int)` for `test_open`.

**Source:** `examples/common/test_lib.c`

---

## Linux — Process Injection

All injection tests require ptrace access (root or Yama scope 0):
```sh
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### test_inject_spawn

Tests `libload_inject_spawn` — LD_PRELOAD-based injection at spawn time.

**Source:** `examples/linux/test_inject_spawn.c`

```sh
build/test_inject_spawn build/inject_target build/inject_payload.so
```

### test_inject_dylib

Tests `libload_inject_dylib` — ptrace attach + remote `dlopen()`.

**Source:** `examples/linux/test_inject_dylib.c`

```sh
sudo build/test_inject_dylib build/inject_target build/inject_payload.so
```

### test_inject

Tests `libload_inject` — ptrace + PIC shellcode injection.

**Source:** `examples/linux/test_inject.c`

```sh
sudo build/test_inject build/inject_target
```

### testexec_nolibc

Statically-linked executable using raw syscalls (no libc). Validates loader stack layout.

**Source:** `examples/linux/testexec_nolibc.c`

Build manually (requires `-nostdlib -static`):
```sh
gcc -nostdlib -static -o testexec_nolibc examples/linux/testexec_nolibc.c
```

---

## macOS — Process Injection

### test_inject_spawn

Tests `libload_inject_spawn` — exception port inheritance injection. **No root or entitlements required.**

**Source:** `examples/macos/test_inject_spawn.c`

```sh
build/test_inject_spawn build/inject_target build/inject_payload.dylib
```

### test_inject_dylib

Tests `libload_inject_dylib` — Mach task port + thread hijack to `dlopen()`. Requires `task_for_pid` access (root or `get-task-allow`).

**Source:** `examples/macos/test_inject_dylib.c`

```sh
sudo build/test_inject_dylib build/inject_target build/inject_payload.dylib
```

### test_inject

Tests `libload_inject` — Mach task port + PIC code injection. Requires `task_for_pid` access.

**Source:** `examples/macos/test_inject.c`

```sh
sudo build/test_inject build/inject_target
```

### testexec_objc

Objective-C runtime test. Validates ObjC class lookup, selectors, `objc_msgSend` dispatch, `@autoreleasepool`, and Foundation classes via `dlopen`.

**Source:** `examples/macos/testexec_objc.m`

---

## Writing Your Own Examples

### Minimal loader

```c
#include <stdio.h>
#include <stdlib.h>
#include <libload.h>

int main(void)
{
    /* Read binary into memory (your method) */
    FILE *f = fopen("mylib.so", "rb");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);
    unsigned char *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    /* Load and use */
    libload_t lib = libload_open(buf, len);
    free(buf);  /* buffer can be freed after open */

    if (!lib) {
        fprintf(stderr, "load failed\n");
        return 1;
    }

    void (*hello)(void) = libload_sym(lib, "hello");
    if (hello) hello();

    libload_close(lib);
    return 0;
}
```

Build:
```sh
gcc -o myloader myloader.c -Iinclude -Lbuild -lload -ldl
```

### Minimal injector

```c
#include <stdio.h>
#include <libload.h>

int main(int argc, char **argv)
{
    char *target_argv[] = { argv[1], NULL };
    pid_t pid = libload_inject_spawn(argv[1], argv[2],
                                      target_argv, NULL);
    if (pid < 0) {
        fprintf(stderr, "injection failed\n");
        return 1;
    }
    printf("injected into PID %d\n", pid);
    return 0;
}
```

### Minimal payload library

```c
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void)
{
    fprintf(stderr, "[payload] running in PID %d\n", getpid());
}
```

Build:
```sh
# Linux
gcc -shared -fPIC -o payload.so payload.c

# macOS
clang -shared -o payload.dylib payload.c
```
