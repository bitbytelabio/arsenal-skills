# Native Rust Binary Reverse Engineering

## When To Open
Open this file when a native ELF, PE, or Mach-O was built by `rustc`. Typical signs are `_R` / `__R` or `_ZN...17h<hash>E` symbols, `/rustc/<40-hex>/library/` paths, `core::panicking`, `rust_eh_personality`, `__rust_alloc`, or a `.dep-v0` section. Rust has no runtime type metadata. What survives is symbols, panic locations, dependency paths, and layout habits. Use them before reading code.

Scope: toolchain and crate recovery, demangling, ABI, fat pointers, `String`/`Vec`/`HashMap` layouts, enum niches, trait object vtables, panic sites, and how to cut the user crate out of monomorphized `core`/`alloc`/`std` code.

---

## 1. Recover Toolchain And Dependencies First

| Source | Command | Yields |
|---|---|---|
| `cargo auditable` data | `rust-audit-info "$BIN"` or `cargo audit bin "$BIN"` | Exact crate names and versions, as JSON or as a vulnerability scan. `cargo audit bin` falls back to panic paths when the section is absent. |
| `.dep-v0` section by hand | LIEF snippet below, or `objcopy --dump-section .dep-v0=/dev/stdout "$BIN" \| pigz -zd -` | Same JSON. Zlib-compressed. ELF/PE section `.dep-v0`. Mach-O `__DATA,.dep-v0`. |
| rustc commit hash | `strings -a "$BIN" \| grep -o '/rustc/[0-9a-f]\{40\}' \| sort -u` | Compiler commit. Map it to a release with `https://github.com/rust-lang/rust/commit/<hash>` or `rustc -vV` of the candidate toolchain. |
| ELF `.comment` | `readelf -p .comment "$BIN"` | `rustc version 1.xx.y (hash date)` when not stripped |
| Registry paths in panic locations | `strings -a "$BIN" \| grep -oE 'registry/src/[^/]+/[A-Za-z0-9_.+-]+-[0-9][^/]*' \| sort -u` | `crate-version` for every third-party crate with a panic site |
| std-internal deps | `/rust/deps/<crate>-<ver>/` | Crates vendored into `std` (`hashbrown`, `gimli`, `addr2line`). Not the program's dependencies. |
| User paths | `strings -a "$BIN" \| grep -E '^(src\|crates?)/.*\.rs$\|/src/.*\.rs$' \| grep -v -e /rustc/ -e registry/ -e /rust/deps/` | Workspace layout and module names |

Registry directory names are `index.crates.io-<hash>` (sparse index, Cargo 1.68+) or `github.com-1ecc6299db9ec823` (git index). Either way the crate directory is `<name>-<version>`.

`--remap-path-prefix`, `-Z trim-paths`, `panic = "abort"`, and `panic_immediate_abort` builds reduce or remove paths. Absence of paths is not absence of dependencies.

```python
# Read cargo-auditable data with LIEF (ELF, PE, Mach-O). uv run --with lief python -I dep_v0.py "$BIN"
import json, sys, zlib
import lief

b = lief.parse(sys.argv[1])
sec = next((s for s in b.sections if s.name == ".dep-v0"), None)
if sec is None:
    sys.exit("no .dep-v0: not built with cargo auditable, or stripped")
d = zlib.decompressobj()
raw = d.decompress(bytes(sec.content), 8 << 20)          # cap output: zip-bomb guard
for p in json.loads(raw)["packages"]:
    print(p["name"], p["version"], p.get("source", ""), p.get("kind", ""))
```

---

## 2. Symbols And Demangling

| Scheme | Prefix | Example | Default |
|---|---|---|---|
| Legacy | `_ZN` ... `17h<16 hex>E` | `_ZN3std2io4Read11read_to_end17h7d2f9b87a6c5e4d3E` | Rust ≤ 1.96 |
| v0 (RFC 2603) | `_R` (Mach-O `__R`) | `_RNvCsbmk5WGNULJt_5rdemo4main` → `rdemo::main` | Rust 1.97+ (nightly since Nov 2025). Opt-in since 1.59 with `-C symbol-mangling-version=v0`. |

v0 encodes generics, the crate disambiguator (`Cs<base62>_`), and impl paths structurally. The legacy `h<hash>` suffix is a hash of the instance and carries no type information.

```bash
nm -a "$BIN" | llvm-cxxfilt           # LLVM demangles legacy and v0
nm -a "$BIN" | c++filt                # binutils 2.36+; v0 output includes the crate hash: rdemo[845156352589a0d1]::main
rustfilt < syms.txt                   # cargo install rustfilt
```

Even stripped binaries keep exported and dynamic symbols. In Rust 1.9x builds the allocator shims are `__rustc::__rust_alloc`, `__rust_dealloc`, `__rust_realloc`, `__rust_alloc_zeroed`. In older builds they are plain `__rust_alloc` and so on. Name them first. Their call sites reveal object sizes.

IDA 9.x and Ghidra 11+ demangle both schemes. Check one known symbol after loading. In IDA, run the scripts below through `ida-mcp` `execute_python`.

### Fully Stripped
1. Name the panic functions by their call pattern (section 5). They are the most-called functions that never return.
2. Name `__rust_alloc(size, align)` / `__rust_dealloc(ptr, size, align)`. They are tiny wrappers that tail-call `malloc`/`free` (or the configured global allocator) and are called from almost every function.
3. Apply FLIRT/FLAIR or Ghidra FID signatures built from the same rustc version and target. Signatures from another version match poorly because of inlining.
4. Run the panic location scan and cluster functions by source file.

---

## 3. Calling Convention

`extern "Rust"` is unspecified, but in practice it follows the platform C ABI with these habits:

- A `&str` / `&[T]` argument takes 2 registers (ptr, len). `&dyn Trait` takes 2 (data, vtable). On SysV x64 that is `RDI, RSI`; on Windows x64 `RCX, RDX`; on ARM64 `X0, X1`.
- Return values up to 2 words come back in `RAX:RDX` (SysV), `RAX` (Windows, ≤ 8 bytes), or `X0:X1` (ARM64). `Result<u64, E>` and `Option<usize>` often return tag + value as a pair.
- Larger returns use a hidden out-pointer: first argument on x64 (`RDI` / `RCX`), `X8` on ARM64. A function that writes through `RDI` and returns `RDI` is returning a struct.
- Small structs are often scalarized into separate registers. Large by-value structs are passed by pointer to a caller copy.
- `extern "C"` functions (`#[no_mangle]`, FFI exports) follow the C ABI exactly.

---

## 4. Data Layouts (64-bit)

`repr(Rust)` field order is not guaranteed. rustc reorders fields to minimize padding. Confirm every layout with the code that allocates or frees the object.

| Type | Observed layout | Size | How to confirm |
|---|---|---|---|
| `&str`, `&[T]`, `Box<[T]>` | `{ptr, len}` | 16 | len used as a loop bound |
| `&dyn Tr`, `Box<dyn Tr>` | `{data, vtable}` | 16 | call through `[vtable+0x18+8*i]` |
| `String`, `Vec<T>` | `{cap, ptr, len}` in rustc 1.7x+ builds | 24 | `__rust_dealloc(ptr, cap*size_of::<T>(), align)` uses cap. `len` feeds bounds checks. |
| `Box<T>`, `&T`, `NonNull<T>`, `Rc<T>`, `Arc<T>` | one pointer | 8 | |
| `Rc<T>` / `Arc<T>` heap block | `{strong, weak, value}` | 16 + T | `lock xadd [p], 1` / `ldadd` on `+0` is an `Arc` clone. |
| `Option<Box<T>>`, `Option<&T>` | null = `None` | 8 | |
| `HashMap<K,V>` (hashbrown) | `RawTable` fields `ctrl`, `bucket_mask`, `growth_left`, `items` (order per build) + hasher (`RandomState` = 2 × u64) | 48 | Control bytes: `0xFF` empty, `0x80` deleted, else top 7 hash bits. Buckets sit *below* `ctrl`, indexed backward: bucket `i` is at `ctrl - (i+1)*size_of::<(K,V)>()`. |
| `core::panic::Location` | `{file_ptr, file_len, line: u32, col: u32}` | 24 | Section 5 |

Example from a rustc 1.98 arm64 build (String "hello world" with capacity 11): words `[0xb, <heap ptr>, 0xb]`. A `Vec::with_capacity(33)` was `[0x21, <ptr>, 0]`.

### Enum Niches

| Type | `None` / second variant encoding | Size |
|---|---|---|
| `Option<&T>`, `Option<Box<T>>`, `Option<NonNull<T>>`, `Option<Arc<T>>` | pointer = 0 | 8 |
| `Option<NonZeroU32>` | 0 | 4 |
| `Option<bool>` | `0x02` (verified) | 1 |
| `Option<char>` | `0x110000` (first value past `char::MAX`) | 4 |
| `Option<core::cmp::Ordering>` | `0x02` (`Ordering` is -1/0/1) | 1 |
| `Option<String>`, `Option<Vec<T>>` | `cap` field holds a value above `isize::MAX`. A rustc 1.98 build used `0xFFFFFFFFFFFFFFFF`; `0x8000000000000000` is also common. Other words are garbage. | 24 |
| `Option<u32>`, `Result<u32, u8>` | No niche. Separate tag, usually at offset 0, payload aligned after it. | 8 |

A comparison of a pointer or capacity field against `0x8000000000000000` (or `cmp x, #0` on a pointer) right after a call is an `Option`/`Result` check, not business logic. With multiple dataful variants, rustc stores the tag in the niche of the largest variant, so the "tag" may be a value range inside a field.

### Trait Object Vtable
| Slot | Content |
|---|---|
| 0 | `drop_in_place::<T>` (may be 0 when `T` has no drop glue) |
| 1 | `size_of::<T>()` |
| 2 | `align_of::<T>()` |
| 3.. | Trait methods in declaration order. Supertrait methods come first. With trait upcasting (1.86+), supertrait vtable pointers can appear among the entries. |

Size and align identify the concrete type. Group vtables with the same `drop_in_place` to find all trait impls of one type. There is no RTTI and no class name. Names come from the method symbols or from panic paths inside them.

---

## 5. Panic Sites

Every `unwrap`, `expect`, index, slice, overflow check (debug), and `panic!` passes a `&'static Location` as its last argument. That record names the source file, line, and column of the user code.

| Function | Arguments (in order) |
|---|---|
| `core::panicking::panic_fmt` | `fmt::Arguments` (by pointer), `&Location` |
| `core::panicking::panic` | `msg_ptr, msg_len, &Location` |
| `core::panicking::panic_bounds_check` | `index, len, &Location` |
| `core::slice::index::slice_end_index_len_fail` / `slice_start_index_len_fail` / `slice_index_order_fail` | `index, len, &Location` |
| `core::option::unwrap_failed` (recent) / `core::option::expect_failed` | `&Location` / `msg_ptr, msg_len, &Location` |
| `core::result::unwrap_failed` | `msg_ptr, msg_len, err_ptr, &dyn Debug vtable, &Location` |
| `core::panicking::panic_const::panic_const_add_overflow` etc. (recent; older builds call `panic` with the message) | `&Location` |
| `alloc::raw_vec::handle_error` / `capacity_overflow`, `alloc::alloc::handle_alloc_error` | allocation failure, no user location |

Example (rustc 1.98, arm64): `mov w0,#3; mov x1,x19; adrp x2,...; add x2,x2,#0x88; bl core::panicking::panic_bounds_check`. The record at `x2` decodes to `src/main.rs:26:21`.

`fmt::Arguments` changed layout. Older releases use three slices (`pieces`, `fmt`, `args`, 48 bytes). Current `core` uses two pointers (`template`, `args`). Do not hard-code it. Read the literal text from `.rodata` near the call.

Recent `core` stores the file name with a NUL byte after `file_len` (for `Location::file_as_c_str`). Older builds do not. Always use the length.

### Static Location Scan (No Disassembler)
Tested on a rustc 1.98 Mach-O arm64 build. It works on any 64-bit little-endian ELF/PE/Mach-O.

```python
# rust_locs.py. uv run --with lief python -I rust_locs.py "$BIN" [-v]
import collections, struct, sys
import lief

b = lief.parse(sys.argv[1])
base = b.optional_header.imagebase if isinstance(b, lief.PE.Binary) else 0
secs = [(base + s.virtual_address, bytes(s.content)) for s in b.sections if s.size and len(s.content)]

def read(va, n):
    for start, data in secs:
        if start <= va and va + n <= start + len(data):
            return data[va - start: va - start + n]

hits = collections.Counter()
for start, data in secs:
    for off in range(0, len(data) - 23, 8):
        ptr, ln, line, col = struct.unpack_from("<QQII", data, off)
        if 4 <= ln <= 400 and 0 < line < 1_000_000 and 0 < col < 1000:
            s = read(ptr, ln)
            if s and s.endswith(b".rs"):
                hits[s.decode("utf-8", "replace")] += 1
                if "-v" in sys.argv:
                    print(f"0x{start+off:x} {s.decode('utf-8','replace')}:{line}:{col}")
for path, n in sorted(hits.items()):
    print(f"{n:5d} {path}")
```

The per-file count shows where the code mass is. Paths without `/rustc/`, `registry/`, or `/rust/deps/` are the user crate.

### Label Functions By Location In IDA (`ida-mcp` `execute_python`)
```python
import struct
import ida_bytes, ida_funcs, ida_name, ida_segment, idautils

def is_loc(ea):
    ptr, ln = ida_bytes.get_qword(ea), ida_bytes.get_qword(ea + 8)
    line, col = ida_bytes.get_dword(ea + 16), ida_bytes.get_dword(ea + 20)
    if not (4 <= ln <= 400 and 0 < line < 1_000_000 and 0 < col < 1000 and ida_bytes.is_loaded(ptr)):
        return None
    s = ida_bytes.get_bytes(ptr, ln)
    return f"{s.decode('utf-8', 'replace')}:{line}:{col}" if s and s.endswith(b".rs") else None

labeled = 0
for n in range(ida_segment.get_segm_qty()):
    seg = ida_segment.getnseg(n)
    if seg.perm & ida_segment.SEGPERM_EXEC:
        continue
    for ea in range(seg.start_ea, seg.end_ea - 23, 8):
        loc = is_loc(ea)
        if not loc:
            continue
        for x in idautils.XrefsTo(ea):
            f = ida_funcs.get_func(x.frm)
            if not f:
                continue
            old = ida_funcs.get_func_cmt(f, False) or ""
            if loc not in old:
                ida_funcs.set_func_cmt(f, (old + "\n" + loc).strip(), False)
            if ida_name.get_name(f.start_ea).startswith("sub_") and "/rustc/" not in loc:
                stem = loc.split("/")[-1].split(".rs")[0]
                ida_name.set_name(f.start_ea, f"{stem}_{f.start_ea:x}", ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
                labeled += 1
print("renamed", labeled)
```
A function can reference locations from inlined callees. When comments list several files, the user file with the highest line count is usually the real owner. Keep the name a candidate until the code agrees.

---

## 6. Separating User Code From std

- After demangling, user code is everything under the crate names from `.dep-v0` or the `[package]` root, plus generic instances whose type parameters are user types (`core::ptr::drop_in_place<myapp::Config>`).
- `drop_in_place<T>` instances are free layout documentation. Each one frees fields in declaration order and calls `__rust_dealloc` with each field's size.
- `<T as core::fmt::Debug>::fmt` instances call `debug_struct("Name")` / `field("name", ...)` with literal type and field names when `#[derive(Debug)]` is used.
- `serde` derive code embeds field names as string tables (`"host"`, `"port"`) inside `visit_str` / `deserialize_identifier` instances. This often recovers a full config schema.
- `tokio`/`async` code appears as `{{closure}}` state machines. The state byte is a `u8` discriminant inside the future struct. Each `.await` point is one `match` arm. `poll` functions with a jump table on that byte are the async bodies.

---

## 7. Verify
- The crate list from `.dep-v0` or registry paths agrees with the demangled crate names.
- One `String`/`Vec` layout is confirmed by a `__rust_dealloc` call with `cap * size` as its size argument.
- A panic `Location` you label is the last argument of a known panic function at its call site.
- A recovered trait vtable has plausible size/align in slots 1–2 and code pointers from slot 3.

## 8. Boundaries And Anti-Patterns
- Do not read Rust strings to a NUL. Use the length.
- Do not decompile generic `core`/`alloc`/`std` code. Most of a release binary is monomorphized library code.
- Do not assume field order from the source. `repr(Rust)` reorders.
- Do not report `.dep-v0` absence as "no dependencies". Fall back to registry paths, then demangled crate names.
- Do not treat `/rust/deps/` crates as program dependencies. They are part of `std`.
- Do not trust a demangler older than the binary for v0 symbols. Old tools print raw `_R...` names or fail silently.
