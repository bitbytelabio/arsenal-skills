# Native Rust Binary Reverse Engineering

## 1. Title & Overview
- **Domain**: Native Rust binaries (ELF, PE, Mach-O compiled via `rustc` and LLVM).
- **Scope**: Rust fat pointer memory models, `Option`/`Result` niche optimizations, panic handler pattern reconstruction (`core::panicking`), symbol demangling (legacy hash-based vs v0 RFC 2603), embedded `.dep-v0` / `cargo-auditable` metadata extraction, and crate boundary isolation from inlined monomorphized standard library routines.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing compiled native binaries exhibiting Rust runtime characteristics:

### Binary Signatures & Section Clues
- **Strings**:
  - Compiler signatures: `rustc version <version>`, `/rustc/<commit_hash>/library/`.
  - Panic calls: `core::panicking::panic`, `core::panicking::panic_bounds_check`, `core::fmt::Arguments`.
  - Dependency paths: `cargo/registry/src/github.com-...` or `cargo/registry/src/index.crates.io-...`.
- **Symbols**:
  - Legacy mangling: Begins with `_ZN` and ends with a 17-character hex hash, e.g., `_ZN3std2io4Read11read_to_end17h7d2f9b87a6c5e4d3E`.
  - v0 (RFC 2603) mangling: Prefixed with `_R` or `_RNv`, e.g., `_RNvNtCs1234_4core3fmt4impl3fmt`.
- **Binary Structure**:
  - Embedded ELF/Mach-O/PE sections: `.dep-v0` section (present if compiled with `cargo-auditable`).
  - Strings stored contiguously in `.rodata` without trailing null terminators (`\x00`), passed as pointer + length pairs.

---

## 3. Tooling & CLI/MCP Actions
- **Headless IDA Pro MCP / Disassembler**:
  - `open_binary`: Load the Rust binary.
  - `get_pseudocode`: View decompiler pseudocode. Configure IDA's Rust demangler in compiler options.
- **Demangling & SBOM CLI Utilities**:
  ```bash
  # Demangle both Legacy and v0 Rust symbols
  rustfilt < mangled_symbols.txt

  # Extract embedded Cargo SBOM using cargo-auditable
  rust-audit <binary_path>
  # Alternatively read raw .dep-v0 ELF section
  readelf -p .dep-v0 <binary>

  # Triage panic strings and source file paths
  strings -a <binary> | grep -E 'src/[a-zA-Z0-9_\-\/]+\.rs' | sort -u
  ```

---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 Fat Pointer Memory Layout & Calling Conventions
Unlike C/C++ where pointers are uniform machine words (8 bytes on x64), Rust employs **fat pointers** (16 bytes on 64-bit systems) for dynamically sized types (DSTs):

```text
1. String Slice (&str) and Array Slice (&[T]):
   [+0x00]: const uint8_t* ptr;      // Pointer to first byte or element
   [+0x08]: uintptr_t      len;      // Element count (explicit byte length for &str)

2. Trait Object (&dyn Trait):
   [+0x00]: void*          data_ptr; // Pointer to concrete struct instance
   [+0x08]: const void**   vtable;   // Pointer to Rust Trait VTable
```

#### Trait Object VTable Layout:
Rust trait vtables do not store a complete class hierarchy descriptor like C++. Instead, the layout is:
- `vtable[0]`: Pointer to destructor / drop glue function (`core::ptr::drop_in_place<T>`).
- `vtable[1]`: `size_t size` (size of concrete type `T` in bytes).
- `vtable[2]`: `size_t align` (alignment of concrete type `T`).
- `vtable[3..N]`: Pointers to trait method implementations.

#### ABI Register Passing:
- Slices passed as parameters occupy **two separate registers**:
  - System V AMD64: `RDI` = pointer, `RSI` = length.
  - Microsoft x64: `RCX` = pointer, `RDX` = length.
  - ARM64: `X0` = pointer, `X1` = length.
- Standard Library `String` and `Vec<T>` are **24 bytes** (3 words):
  - `[+0x00]`: Data pointer
  - `[+0x08]`: Capacity (allocated element count)
  - `[+0x10]`: Length (currently initialized element count)

---

### 4.2 Niche Optimization & Enum Discriminants
Rust eliminates memory overhead for enums through **niche filling optimizations**:

#### Pointer Niches (`Option<&T>`, `Option<Box<T>>`, `Option<NonNull<T>>`):
Because references (`&T`) and heap pointers (`Box<T>`) are guaranteed non-null in safe Rust, the null address `0x0` represents `None`.
- `Some(ptr)`: Non-zero pointer value.
- `None`: Exactly `0x0000000000000000`.
- Result: `sizeof(Option<&T>) == sizeof(uintptr_t)`. No additional tag byte exists.

#### Non-Zero Integer Niches (`Option<NonZeroU32>`):
- Any value in `1..=0xFFFFFFFF` represents `Some(v)`.
- `0x0` represents `None`.

#### Boolean Niches:
A `bool` only takes values `0` or `1`. Values `2..255` are invalid and used to encode `None` variants when wrapped in an `Option<bool>`:
- `Some(false)` = `0x00`
- `Some(true)`  = `0x01`
- `None`        = `0x02`

#### Non-Niche Enums:
When no niche is available, `rustc` assigns an explicit discriminant tag:
- Look for a 1-byte, 2-byte, or 4-byte integer tag field preceding or packed inside structure padding.
- When reversing `Result<T, E>`, if `T` and `E` have no niches, check if the first byte is tested:
  ```nasm
  cmp     byte ptr [rbx], 0     ; 0 = Ok, 1 = Err
  jne     handle_error_branch
  ```

---

### 4.3 Panic Site Analysis & Source Tree Reconstruction
Rust's panic mechanism is one of the highest-value static intelligence sources. Whenever `panic!`, `unwrap()`, or `expect()` is invoked, or an array index is out-of-bounds, `rustc` emits calls to `core::panicking` with references to the source file location:

#### Key Functions to Cross-Reference:
- `core::panicking::panic`: Takes static string message, filename, line, and column.
- `core::panicking::panic_fmt`: Takes formatted arguments (`core::fmt::Arguments`) and location struct.
- `core::panicking::panic_bounds_check`: Triggered on slice indexing errors; passes invalid index and slice length.

#### Panic Location Structure (`core::panic::Location`):
```c
struct PanicLocation {
    const char* file_ptr;     // Pointer to source file path string
    uintptr_t   file_len;     // Length of source file path string
    uint32_t    line;         // 1-indexed source line number
    uint32_t    col;          // 1-indexed source column number
};
```
#### Reversing Action:
1. Search cross-references to `core::panicking::panic*`.
2. Inspect the arguments passed to the panic function: read the file path string and line number from the static location struct.
3. Label the calling function using the source path and line: e.g., if a panic occurs in `/app/src/network/client.rs:142`, rename the surrounding subfunction to `network::client::sub_xxx_line142`.

---

### 4.4 Demangling Schemes: Legacy vs v0 (RFC 2603)

| Feature | Legacy Mangling | v0 (RFC 2603) Mangling |
| :--- | :--- | :--- |
| **Prefix** | `_ZN` | `_R` or `_RNv` |
| **Hash Suffix** | `17h<16_hex_digits>E` (e.g., `17h0123456789abcdefE`) | Embedded disambiguator (e.g., `Cs1234_`) |
| **Generics** | Rendered as text literals in name | Explicit structured type encodings |
| **Standard Support** | GNU c++filt (partial), rustfilt | rustfilt, IDA Pro 8+, Ghidra 11+ |

#### Workflow:
1. Extract mangled symbol list using `nm -g <binary>`.
2. If symbols begin with `_R`, ensure disassembler is set to Rust v0 demangler.
3. If using automated scripts, feed symbols into `rustfilt` CLI:
   ```bash
   rustfilt "_RNvCs1234_7mycrate3foo" # Outputs: mycrate::foo
   ```

---

### 4.5 Dependency Recovery via `.dep-v0` & Registry Paths
Modern Rust binaries frequently preserve compile-time dependency lists:

1. **`cargo-auditable` / `.dep-v0` section**:
   - Modern Rust software built with supply-chain auditing embeds an audited dependency tree in the `.dep-v0` section.
   - It is encoded as zlib-compressed JSON.
   - Extraction:
     ```bash
     readelf -x .dep-v0 <binary>
     # Or using cargo-audit:
     cargo audit bin <binary>
     ```
2. **Fallback Registry Path Scraping**:
   If `.dep-v0` is stripped, scan for standard cargo registry panic paths:
   ```bash
   strings <binary> | grep -E 'cargo/registry/src/[^/]+/[^/]+' | sed -E 's/.*cargo\/registry\/src\/[^\/]+\/([^\/]+).*/\1/' | sort -u
   ```
   This immediately reveals third-party crates and exact versions used (e.g., `tokio-1.28.1`, `serde-1.0.160`, `ring-0.16.20`).

---

## 5. Concrete Code & Script Examples

### Python Panic Site Scanner & Function Labeler (IDAPython / Headless)
```python
import ida_bytes
import ida_funcs
import ida_name
import ida_xref
import idc

def extract_rust_string(ptr_ea, len_val):
    """Extract string given pointer and explicit length."""
    if ptr_ea == 0 or len_val == 0 or len_val > 512:
        return None
    data = ida_bytes.get_bytes(ptr_ea, len_val)
    if data:
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return None
    return None

def scan_panic_locations():
    """Find references to panic locations and name enclosing functions."""
    # Common panic symbols across toolchains
    panic_syms = [
        "core::panicking::panic",
        "core::panicking::panic_fmt",
        "_ZN4core9panicking5panic",
        "_ZN4core9panicking9panic_fmt"
    ]

    for sym in panic_syms:
        sym_ea = idc.get_name_ea_simple(sym)
        if sym_ea == idc.BADADDR:
            continue

        print(f"[+] Processing panic target: {sym} at 0x{sym_ea:X}")
        for xref in idautils.CodeRefsTo(sym_ea, 0):
            func = ida_funcs.get_func(xref)
            if not func:
                continue

            # Check preceding instructions for Location struct reference
            # In x64 System V, Location struct pointer is often in RDX or RSI
            # In MSVC x64, in RDX or R8
            curr_ea = xref - 0x20
            while curr_ea < xref:
                # Search for LEA or MOV immediate referencing .rodata
                val = idc.get_operand_value(curr_ea, 1)
                if val and ida_bytes.is_loaded(val):
                    # Check if val points to Location struct: [file_ptr(8), file_len(8), line(4), col(4)]
                    f_ptr = ida_bytes.get_qword(val)
                    f_len = ida_bytes.get_qword(val + 8)
                    line_num = ida_bytes.get_dword(val + 16)

                    path_str = extract_rust_string(f_ptr, f_len)
                    if path_str and (".rs" in path_str):
                        clean_path = path_str.split("/")[-1].replace(".rs", "")
                        new_name = f"rust_{clean_path}_L{line_num}_{func.start_ea:X}"
                        ida_name.set_name(func.start_ea, new_name, ida_name.SN_NOWARN)
                        print(f"  [+] Renamed 0x{func.start_ea:X} -> {new_name} (from {path_str}:{line_num})")
                        break
                curr_ea += idc.get_item_size(curr_ea)

scan_panic_locations()
```

---

## 6. Boundaries & Anti-Patterns
- **Do not assume null-terminated strings**: Rust strings are pointer + length pairs. Reading memory until `\x00` will produce corrupted strings, run into adjacent literals, or crash static parsers.
- **Do not waste time decompiling generic runtime machinery**: 80-90% of a stripped Rust binary consists of monomorphized generics from `core`, `alloc`, and `std` (e.g., hash tables, formatting logic, allocator abstractions). First isolate user crate names via panic strings or crate prefixes (`<app_name>::*`).
- **Do not assume missing `.dep-v0` means no dependencies**: `.dep-v0` requires `cargo-auditable`. If built with vanilla `cargo build --release`, `.dep-v0` will not exist. Fall back to registry path regex scanning.
- **Do not overlook the 128-byte System V red zone on x64**: Rust leaf functions frequently do not adjust `RSP` and store local fat pointers directly into `[rsp - 0x08]` through `[rsp - 0x80]`.
