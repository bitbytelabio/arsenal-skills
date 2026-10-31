# Native Go Binary Reverse Engineering

## 1. Title & Overview
- **Domain**: Go binaries (compiled with the official `gc` toolchain for Linux ELF, Windows PE, and macOS Mach-O).
- **Scope**: Reconstructing function boundaries, file paths, and symbol tables from `.gopclntab`, distinguishing Go 1.17+ register-based ABI from stack-based calling conventions, mapping interface structures (`iface` and `eface`), reversing struct type descriptors via `runtime.moduledata`, identifying `runtime.morestack` split-stack prologues, and recovering goroutine entry points and channel dispatch.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing compiled binaries with Go runtime signatures:

### Binary Signatures & Section Clues
- **Sections**:
  - ELF: `.gopclntab`, `.gosymtab`
  - PE / Mach-O: Sections named `__gopclntab` or `.rdata` containing pclntab magic headers.
- **Header Magic Bytes in `.gopclntab`**:
  - Go 1.2 – 1.15: `0xFFFFFFFB` (`\xFB\xFF\xFF\xFF`)
  - Go 1.16 – 1.17: `0xFFFFFFFA` (`\xFA\xFF\xFF\xFF`)
  - Go 1.18 – 1.20+: `0xFFFFFFF0` (`\xF0\xFF\xFF\xFF`)
  - Go 1.20+ (alternate header): `0xFFFFFFF1` (`\xF1\xFF\xFF\xFF`)
- **Strings**:
  - `runtime.main`, `runtime.morestack`, `go:buildid`, `Go build ID:`, `runtime.gopanic`.
  - Package path patterns: `main.main`, `net/http.(*Server).Serve`, `github.com/...`.
- **Prologue Disassembly**:
  - Stack bound checks against thread-local `g` struct:
    ```nasm
    ; x86-64 Go split-stack prologue
    cmp     rsp, qword ptr [r14 + 10h] ; r14 holds current 'g' (goroutine)
    jbe     runtime.morestack_noctxt   ; Jump to stack allocation runtime function
    ```

---

## 3. Tooling & CLI/MCP Actions
- **Headless IDA Pro MCP / Disassembler**:
  - `open_binary`: Load Go binary.
  - Apply scripts: `GoReSym` IDA script or `AlphaGolang` plugin to parse pclntab and restore symbols.
- **Go Inspection & Extraction CLI Utilities**:
  ```bash
  # Check Go compiler version and build information directly
  go version <binary>
  go version -m <binary>              # Recovers full SBOM: modules, dependencies, compiler flags

  # GoReSym: High-performance pclntab and type extractor
  GoReSym -t -d -p <binary> > symbols.json
  # -t: dump user types; -d: dump stdlib functions; -p: dump source file paths

  # redress: Alternative Go binary structural analyzer
  redress info <binary>
  redress packages <binary>
  redress types <binary>
  ```

---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 `.gopclntab` Parsing & Symbol Recovery
Even when a Go binary is stripped using `strip` or compiled with `-ldflags="-s -w"`, the Go runtime requires a function-to-program-counter table (`.gopclntab`) to generate stack traces during panic recovery.

#### Gopclntab Header Layout:
```text
Header (Go 1.18+):
  +0x00: uint32_t magic;           // 0xFFFFFFF0
  +0x04: uint8_t  pad1, pad2;      // 0x00, 0x00
  +0x06: uint8_t  minLC;           // Instruction size quantum (1 on x86, 4 on ARM)
  +0x07: uint8_t  ptrSize;         // Pointer size (4 or 8)
  +0x08: uintptr_t nfunc;          // Number of functions in binary
  +0x10: uintptr_t nfiles;         // Number of source files
  +0x18: uintptr_t textStart;      // Virtual memory address of .text segment
  +0x20: uintptr_t funcnameOffset; // Offset from pclntab start to function name table
  +0x28: uintptr_t cuOffset;       // Compilation unit table offset
  +0x30: uintptr_t filetabOffset;  // Source file name table offset
  +0x38: uintptr_t pctabOffset;    // PC data table offset
  +0x40: uintptr_t pclnOffset;     // PC-to-line table offset
```

#### Function Table Entry (`runtime.funcTab` / `_func`):
Each function is indexed by its entry point and offset to the `_func` record:
```text
struct _func {
    uintptr_t entryOff;            // Function entry point (PC) offset from textStart
    int32_t   nameOff;             // Offset into function name table (null-terminated string)
    int32_t   args;                // Argument frame size in bytes
    uint32_t  deferreturn;         // Offset of deferreturn call within function
    int32_t   pcsp;                // Offset into pctab for PC-to-SP delta table
    int32_t   pcfile;              // Offset into pctab for PC-to-file-index table
    int32_t   pcln;                // Offset into pctab for PC-to-line-number table
    int32_t   npcdata;             // Number of PCDATA entries
    int32_t   cuOffset;            // Offset of compilation unit
    int32_t   startLine;           // Line number of function start
    int32_t   funcID;              // Internal runtime function ID
    int32_t   nfuncdata;           // Number of FUNCDATA entries (stack maps, gc info)
};
```

#### Symbol Restoration Workflow:
1. Locate the pclntab magic byte sequence in read-only memory.
2. Read `nfunc` to determine the count of functions.
3. Iterate over the function table entries: calculate `entryPC = textStart + entryOff`.
4. Read function name from `funcnameOffset + nameOff`.
5. Apply recovered function name and function boundary (`entryPC` to next function) in the disassembler database.

---

### 4.2 Calling Conventions: Stack-Based vs Go 1.17+ Register-Based ABI

| Attribute | Go <= 1.16 (ABI0) | Go >= 1.17 (ABIInternal on AMD64/ARM64) |
| :--- | :--- | :--- |
| **Parameter Passing** | Exclusively on stack (passed right-to-left) | In registers first, overflow to stack |
| **AMD64 Integer Regs** | None | 9 registers: `RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11` |
| **AMD64 Float Regs** | None | 15 registers: `X0 - X14` |
| **ARM64 Integer Regs** | None | 16 registers: `R0 - R15` |
| **Current Goroutine `g`** | Thread-local storage (`FS:0` or TLS base) | Dedicated register: `R14` (AMD64), `R28` (ARM64) |
| **Multiple Return Values** | Allocated on caller stack frame above args | Returned in argument registers: `RAX, RBX, RCX...` |

#### Decompiler Implication:
- In Go 1.16 and earlier, decompilers like IDA and Ghidra easily trace arguments because all inputs and outputs sit in sequential stack offsets (`[rsp + 8]`, `[rsp + 16]`).
- In Go 1.17+, decompilers often fail to detect that `(result, err)` pairs are returned simultaneously in `RAX` (value) and `RBX` (error interface). Set function prototypes explicitly in your decompiler.

---

### 4.3 Go Type System & Interface Structures

#### 1. Slices and Strings
- **`string` (16 bytes on 64-bit)**:
  ```text
  [+0x00]: const char* str;  // Pointer to byte buffer (no trailing null terminator)
  [+0x08]: int64_t     len;  // Length in bytes
  ```
- **`slice` (24 bytes on 64-bit)**:
  ```text
  [+0x00]: void*   array;    // Pointer to underlying array
  [+0x08]: int64_t len;      // Active element count
  [+0x10]: int64_t cap;      // Maximum element capacity before reallocation
  ```

#### 2. Interface Dispatch: `eface` vs `iface`
Go defines two internal representations for interfaces:

- **Empty Interface (`any` / `interface{}` / `eface`)**:
  ```c
  struct eface {
      struct _type* _type;   // Pointer to runtime type descriptor
      void*         data;    // Pointer to value or copied data
  };
  ```
- **Non-Empty Interface (`iface`)**:
  ```c
  struct iface {
      struct itab*  tab;     // Interface method table descriptor
      void*         data;    // Pointer to underlying value
  };

  struct itab {
      struct InterType* inter; // Interface type definition
      struct _type*     _type; // Concrete type implementing the interface
      uint32_t          hash;  // Hash of _type for fast type assertions
      uint8_t           _bad;
      uint8_t           _unused[3];
      void*             fun[1]; // Method function pointer table
  };
  ```

#### Interface Call Disassembly Pattern:
```nasm
mov     rax, [rsp + 20h]     ; Load itab* from iface struct
mov     rcx, [rsp + 28h]     ; Load data pointer
mov     rax, [rax + 20h]     ; Load method function pointer from fun[index]
mov     rdi, rcx             ; Pass concrete receiver in RDI (or RAX in ABIInternal)
call    rax                  ; Dynamic dispatch
```

---

### 4.4 Struct Type Descriptors & `runtime.moduledata`
The Go runtime stores complete reflection metadata within `runtime.firstmoduledata`.

#### `moduledata` Key Pointers:
- `moduledata.types`: Base address of the binary's type section.
- `moduledata.etypes`: End address of the type section.
- `moduledata.typelinks`: Array of 32-bit offsets relative to `types` pointing to every `runtime._type` record in the program.

#### `runtime._type` Header (Common to all Go types):
```c
struct _type {
    uintptr_t size;          // Size of type in bytes
    uintptr_t ptrdata;       // Size of memory prefix containing pointers (for GC)
    uint32_t  hash;          // Type hash
    uint8_t   tflag;         // Extra type flags (name present, star prefix, etc.)
    uint8_t   align;         // Struct field alignment
    uint8_t   fieldAlign;
    uint8_t   kind;          // Enum (bool=1, int=2, string=24, slice=23, struct=25, etc.)
    void*     equal;         // Comparison function pointer
    void*     gcdata;        // Garbage collector pointer bitmap
    int32_t   str;           // Offset into string pool for type name
    int32_t   ptrToThis;     // Offset to pointer type descriptor
};
```
For structs (`kind & 0x1F == 25`), following `_type` is `structType`, containing an array of `structField` elements specifying each field's name, type offset, and byte offset within the struct.

---

### 4.5 Goroutine Spawning & Channel Synchronization
- **Goroutine Creation**: Calls to `runtime.newproc` or `runtime.newproc1`:
  - Parameter 1: Function pointer to the goroutine entry point.
  - Parameter 2: Size of arguments or frame pointer.
  - *Reversing Action*: Trace calls to `runtime.newproc` to map all asynchronous background worker routines in the application.
- **Channel Operations**:
  - `runtime.makechan`: Channel instantiation (element type, buffer capacity).
  - `runtime.chansend1(chan* c, void* val)`: Channel send operation (`c <- val`).
  - `runtime.chanrecv1(chan* c, void* val)`: Channel receive operation (`val = <-c`).
  - `runtime.selectgo`: Implements multi-channel `select { ... }` state machines.

---

## 5. Concrete Code & Script Examples

### Python Standalone Script to Parse Go 1.18+ `.gopclntab`
```python
import struct
import sys

def parse_pclntab(data, base_addr=0):
    # Search for Go 1.18+ magic bytes: 0xFFFFFFF0
    magic_idx = data.find(b"\xF0\xFF\xFF\xFF")
    if magic_idx == -1:
        # Search for Go 1.16 magic: 0xFFFFFFFA
        magic_idx = data.find(b"\xFA\xFF\xFF\xFF")
        if magic_idx == -1:
            print("[-] No known gopclntab magic bytes found.")
            return

    print(f"[+] Found gopclntab at offset 0x{magic_idx:X}")
    header = data[magic_idx:magic_idx + 64]
    magic, pad1, pad2, min_lc, ptr_size = struct.unpack_from("<IBBBB", header, 0)
    
    if ptr_size == 8:
        nfunc, nfiles, text_start, funcname_off, cu_off, filetab_off, pctab_off, pcln_off = struct.unpack_from(
            "<QQQQQQQQ", header, 8
        )
    else:
        nfunc, nfiles, text_start, funcname_off, cu_off, filetab_off, pctab_off, pcln_off = struct.unpack_from(
            "<IIIIIIII", header, 8
        )

    print(f"    Ptr Size: {ptr_size} bytes, Function Count: {nfunc}")
    print(f"    Text Start VMA: 0x{text_start:X}")

    # Read func table entries (array of [entryOff, funcOff])
    ftab_offset = magic_idx + 64
    entry_size = ptr_size * 2

    functions = []
    for i in range(min(nfunc, 1000)):  # First 1000 functions
        slot = data[ftab_offset + (i * entry_size): ftab_offset + ((i + 1) * entry_size)]
        if len(slot) < entry_size:
            break
        if ptr_size == 8:
            entry_off, func_off = struct.unpack("<QQ", slot)
        else:
            entry_off, func_off = struct.unpack("<II", slot)

        func_vma = text_start + entry_off
        
        # Read _func record at magic_idx + func_off
        func_rec_idx = magic_idx + func_off
        if ptr_size == 8:
            name_off = struct.unpack_from("<i", data, func_rec_idx + 8)[0]
        else:
            name_off = struct.unpack_from("<i", data, func_rec_idx + 4)[0]

        # Extract null-terminated name string
        name_start = magic_idx + funcname_off + name_off
        name_end = data.find(b"\x00", name_start)
        name = data[name_start:name_end].decode("utf-8", errors="ignore")

        functions.append((func_vma, name))

    print(f"[+] Successfully extracted {len(functions)} functions.")
    for vma, name in functions[:20]:
        print(f"    0x{vma:016X} -> {name}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_pclntab.py <path_to_binary>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        parse_pclntab(f.read())
```

---

## 6. Boundaries & Anti-Patterns
- **Do not decompile before applying pclntab symbols**: A stripped Go binary displays thousands of anonymous functions (`sub_401000`, `sub_401500`). Manually reading stripped control flow before running `GoReSym` or `AlphaGolang` is an enormous waste of time; pclntab contains full function names.
- **Do not get lost in standard library functions**: 90% or more of functions in any Go binary originate from standard library packages (`runtime.*`, `net/http.*`, `crypto/*`, `syscall.*`). Filter your symbol list immediately: focus on `main.*` and project-specific vendor paths (`github.com/myorg/...`).
- **Do not misinterpret Go strings as C strings**: Go strings are not null-terminated; reading past the length field results in reading adjacent string literals stored in the continuous `.rodata` string blob.
- **Do not ignore `runtime.morestack`**: When observing a jump at the beginning of a function to `runtime.morestack`, this is standard stack growth logic. Do not treat it as branchy business logic.
