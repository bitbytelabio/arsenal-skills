# Native Go Binary Reverse Engineering

## When To Open
Open this file when the binary was built by the official `gc` Go toolchain. Typical signs are a `.gopclntab` section or pclntab magic, the `\xff Go buildinf:` marker, `runtime.morestack`, or `Go build ID:`. Go symbol names survive `strip` and `-ldflags="-s -w"` because the runtime needs them for tracebacks. Recover names first. Read code second.

Scope: version identification, pclntab layouts per version, `moduledata`, the register ABI, string/slice/interface/map layouts, type descriptors, goroutine and channel call sites, and obfuscated builds (garble). `gccgo` and TinyGo binaries do not use these layouts. Treat them as C/LLVM output ([native-cpp-abi.md](native-cpp-abi.md)).

---

## 1. Detection And Version

| Indicator | Where | Meaning |
|---|---|---|
| `\xff Go buildinf:` (14 bytes) | ELF `.go.buildinfo`, PE `.data`, Mach-O `__go_buildinfo` | Build info header. Toolchain version and module list follow. |
| `Go build ID: "..."` | Start of text, or ELF note `.note.go.buildid` | Build ID. Present even when stripped. |
| pclntab magic (table below) | ELF `.gopclntab`, Mach-O `__gopclntab`, PE inside `.rdata` | Function table. |
| `.go.module` / `__go_module` | ELF / Mach-O section | `moduledata` lives here from Go 1.26. |
| `.gosymtab` | ELF | Always empty. Removed in Go 1.26. Its absence proves nothing. |

Read the version and module list statically. `go version` parses the file. It does not run it.

```bash
go version "$BIN"          # e.g. "go1.22.5"
go version -m "$BIN"       # main module, every dependency with version and h1: hash, build flags, GOOS/GOARCH, vcs.revision
```

Build info header (`debug/buildinfo`). It is 16-byte aligned and 32 bytes long:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 14 | `"\xff Go buildinf:"` |
| 0x0E | 1 | pointer size |
| 0x0F | 1 | flags. Bit 1 (`0x2`) set = Go 1.18+: varint-length-prefixed version string and module string follow at +0x20. Clear = pre-1.18: two pointers at +0x10 and +0x10+ptrsize to Go string headers. |

`-trimpath`, `-buildvcs=false`, and garble remove or blank parts of this. A missing module list is not proof of an old toolchain.

### pclntab Magic By Version

| Magic (LE bytes) | Value | Toolchains | Layout notes |
|---|---|---|---|
| `fb ff ff ff` | `0xFFFFFFFB` | 1.2 – 1.15 | Header is 8 bytes + `nfunc`. functab follows immediately. All offsets relative to the header. |
| `fa ff ff ff` | `0xFFFFFFFA` | 1.16 – 1.17 | Separate funcname/cu/file/pc tables. functab entries are `uintptr` pairs with absolute PCs. |
| `f0 ff ff ff` | `0xFFFFFFF0` | 1.18 – 1.19 | `textStart` added. functab entries become `uint32` pairs relative to text. |
| `f1 ff ff ff` | `0xFFFFFFF1` | 1.20+ | Same layout as 1.18. From 1.26 `textStart` is always 0. Use `moduledata.text` or the start of `.text`. |

Bytes 4–5 are zero. Byte 6 is `minLC` (1 on x86, 4 on ARM/ARM64/MIPS/RISC-V). Byte 7 is the pointer size. Validate those three before you trust a magic hit in PE `.rdata`.

The magic narrows the range only. `go version`, the `runtime.buildVersion` string, or a `go1.` string near the build info gives the exact version.

---

## 2. Tooling

| Tool | Use | Caveat |
|---|---|---|
| `go version -m` | Version, modules, build settings | Needs intact build info |
| GoReSym (Mandiant) | `GoReSym -t -d -p "$BIN" > goresym.json`. `-t` types, `-d` include std packages, `-p` file paths, `-strings` string table, `-human` text output, `-v go1.xx` force version | Check its release notes support your toolchain. Go 1.26 moved `moduledata`. Type parsing fails on a wrong `-v`. Its IDA importer is `IDAPython/goresym_rename.py`. |
| redress | `redress info`, `redress packages --filepath`, `redress types struct`, `redress source`, `redress moduledata`, `redress r2 init` inside r2 | Same version caveat |
| IDA 9.x | The Go loader names functions and applies Go calling conventions (`__golang`) | Verify on one known function. Older plugins (AlphaGolang, IDAGolangHelper) target old layouts. |
| Ghidra 11+ | Golang analyzer recovers names, types, and the register ABI | Supported Go range is listed in the release notes |
| The script in section 8 | Function list from pclntab, no dependencies beyond LIEF | Names and entry points only |

Run the triage scanner first: `uv run scripts/auto_triage.py "$BIN"`.

In IDA, drive everything through `ida-mcp` (`open_database`, then `execute_python`). Section 8 has an importer.

---

## 3. pclntab Layout (1.18+ Header)

All offsets are from the start of the header. Fields are `uintptr`-sized after byte 8.

| Offset (64-bit) | Field | Notes |
|---|---|---|
| 0x00 | `magic` uint32 | `0xFFFFFFF0` / `0xFFFFFFF1` |
| 0x04 | `pad1, pad2` | 0, 0 |
| 0x06 | `minLC` | Instruction quantum |
| 0x07 | `ptrSize` | 4 or 8 |
| 0x08 | `nfunc` | Function count |
| 0x10 | `nfiles` | File table entries |
| 0x18 | `textStart` | 0 from Go 1.26 |
| 0x20 | `funcnameOffset` | Name blob. Names are NUL-terminated. |
| 0x28 | `cuOffset` | Compilation-unit table (`uint32` file indexes) |
| 0x30 | `filetabOffset` | File name blob |
| 0x38 | `pctabOffset` | pc-value tables (varint delta encoded) |
| 0x40 | `pclnOffset` | functab, then `_func` records |

The 1.16 header has no `textStart`, so `funcnameOffset` is at 0x18 and `pclnOffset` at 0x38.

functab at `pclnOffset` holds `nfunc + 1` pairs. In 1.18+ each pair is `{uint32 entryOff; uint32 funcOff}`. `entryOff` is relative to text start. `funcOff` is relative to `pclnOffset`. The last entry gives the end PC of the last function.

`_func` record (1.18+). In 1.16–1.17, `entryOff` is a full `uintptr` `entry`, so every later field shifts by 4 on 64-bit.

| Offset | Field | Use |
|---|---|---|
| 0x00 | `entryOff` uint32 | Must equal the functab entry. Use it as a sanity check. |
| 0x04 | `nameOff` int32 | Into `funcnametab` |
| 0x08 | `args` int32 | Argument + result frame size |
| 0x0C | `deferreturn` uint32 | Non-zero when the function has `defer` |
| 0x10 | `pcsp`, `pcfile`, `pcln` uint32 ×3 | Offsets into `pctab` |
| 0x1C | `npcdata` uint32 | |
| 0x20 | `cuOffset` uint32 | |
| 0x24 | `startLine` int32 | Line of the `func` keyword (1.20+) |
| 0x28 | `funcID` uint8 | Non-zero for special runtime functions |
| 0x29 | `flag` uint8 | |
| 0x2B | `nfuncdata` uint8 | Followed by `pcdata[npcdata]` and `funcdata[nfuncdata]` (`uint32`) |

File and line for a PC: decode `pcfile` and `pcln` from `pctab` (zig-zag varint value delta, varint PC delta × `minLC`). The file index goes through `cutab[cuOffset + index]` into `filetab`. Use a tool for this. Do not hand-decode it.

### moduledata
`runtime.firstmoduledata` starts with a pointer to the pcHeader. Find it by searching writable data for the pclntab virtual address as a pointer. From Go 1.26 it sits alone in `.go.module`.

Fields that matter (64-bit offsets from the start, stable 1.18–1.25):

| Offset | Field |
|---|---|
| 0x00 | `pcHeader *pcHeader` |
| 0x08 | `funcnametab []byte` (ptr, len, cap) |
| 0x20 | `cutab []uint32` |
| 0x38 | `filetab []byte` |
| 0x50 | `pctab []byte` |
| 0x68 | `pclntable []byte` |
| 0x80 | `ftab []functab` |
| 0x98 | `findfunctab`, then `minpc`, `maxpc`, `text`, `etext`, ... |

After `etext` come the data/bss bounds, then `types`, `etypes`, and (up to 1.25) the `typelinks []int32` slice. Each `typelinks` entry is an offset from `types` to a `runtime._type`. Go 1.27 has no `typelinks` field. Walk `[types, etypes)` instead. The middle of the struct changes between releases. Count fields from the toolchain's `runtime/symtab.go` for that version, not from a blog post.

---

## 4. Register ABI (ABIInternal)

Register-based arguments arrived in Go 1.17 on amd64, and in 1.18 on arm64, ppc64, and riscv64. 386 and 32-bit ARM still pass everything on the stack (ABI0). Assembly functions in the runtime and in `crypto/*` are always ABI0. The compiler emits `<name>.abi0` wrapper stubs when ABIs mix.

| Arch | Integer args and results, in order | Float | `g` | Closure context | Other fixed |
|---|---|---|---|---|---|
| amd64 | `RAX RBX RCX RDI RSI R8 R9 R10 R11` | `X0`–`X14` | `R14` | `RDX` | `X15` = 0, `R12`/`R13` scratch |
| arm64 | `R0`–`R15` | `F0`–`F15` | `R28` | `R26` | `R27` scratch, `ZR` |
| riscv64 | `X10`–`X17`, `X8`, `X9`, `X18`–`X23` | `F10`–`F17`, `F8`, `F9`, `F18`–`F23` | `X27` | `X26` | |

Rules that change the decompiler output:
- Results come back in the same register sequence, starting again at `RAX` / `R0`. `(T, error)` returns `T` in `RAX` and the error interface in `RBX:RCX` (itab, data).
- Every multi-word value takes consecutive registers. A `string` is 2 registers. A slice is 3. An interface is 2. A struct is split field by field when it fits.
- A method receiver is the first argument.
- There are no callee-saved general registers. Every call clobbers everything except `RSP`, `RBP`, and `R14`.
- Spill slots for register arguments are reserved in the caller frame but written only around stack growth.

Pre-1.17 (ABI0): arguments and then results are laid out upward from `[rsp+8]` at entry. Results are written into the caller's frame. Decompilers show them as stack writes, not returns.

### Prologue
```text
amd64 small frame             amd64 frame > 128 bytes              arm64
cmp  rsp, [r14+0x10]          lea  r12, [rsp-0x28]                 ldr  x16, [x28,#0x10]
jbe  morestack_path           cmp  r12, [r14+0x10]                 sub  x17, sp, #0x30
                              jbe  morestack_path                  cmp  x16, x17
                                                                   b.ls morestack_path
```
`[g+0x10]` is `g.stackguard0`. The tail block spills argument registers, calls `runtime.morestack_noctxt` (or `runtime.morestack` for closures), restores them, and jumps back to the entry. It is not business logic. Pre-1.17 amd64 loads `g` from TLS (`fs:`-relative on Linux, `gs:`-relative on Windows) into a scratch register instead of using `R14`.

---

## 5. Data Layouts (64-bit)

| Go type | Layout | Size |
|---|---|---|
| `string` | `{ptr *byte; len int}`. Not NUL-terminated. | 16 |
| `[]T` | `{ptr *T; len int; cap int}` | 24 |
| `interface{}` / `any` (eface) | `{_type *_type; data unsafe.Pointer}` | 16 |
| non-empty interface (iface) | `{tab *itab; data unsafe.Pointer}` | 16 |
| `func` value | Pointer to a closure object `{fn uintptr; captured vars...}` | 8 |
| `chan T` | `*hchan` | 8 |
| `map[K]V` | `*hmap` (≤1.23) or `*maps.Map` Swiss table (1.24+) | 8 |

`data` holds the value itself when the type is pointer-shaped (pointer, map, chan, func, single-pointer struct). Otherwise it points to a copy.

String literals are packed back to back in one blob in `.rodata`. In code a literal is `lea rax, [rip+X]` / `mov ebx, LEN` (amd64) or `adrp/add x0` / `mov x1, #LEN` (arm64). Read exactly `LEN` bytes. Reading to a NUL runs into the next literal. Comparisons against short constant strings compile to integer compares on the bytes (`cmp dword ptr [rax], 0x74736f68` for `"host"`), so a string search misses them.

### itab
| Offset | Field |
|---|---|
| 0x00 | `inter *interfacetype` |
| 0x08 | `_type *_type` (concrete type) |
| 0x10 | `hash uint32` (copy of `_type.hash`, used by type switches) |
| 0x18 | `fun[0]`, `fun[1]`, ... method pointers sorted by method name |

`fun[0] == 0` means the type does not implement the interface. An interface call is `mov rcx, [itab+0x18+8*i]; call rcx` with the data word as the first argument. Map `i` to a method by sorting the interface's method names.

A type switch or assertion compares `itab.hash` or `_type.hash` to a constant, then compares the pointer. The constant is the hash of the type it tests for. Resolve it against the type table.

### runtime._type (abi.Type)
| Offset | Field | Notes |
|---|---|---|
| 0x00 | `size` uintptr | |
| 0x08 | `ptrdata` uintptr | Prefix bytes that can hold pointers |
| 0x10 | `hash` uint32 | |
| 0x14 | `tflag` uint8 | `1` uncommon, `2` extra star, `4` named, `8` regular memory, `0x10` GC mask on demand and `0x20` direct iface in recent toolchains |
| 0x15 | `align`, 0x16 `fieldAlign` | |
| 0x17 | `kind` uint8 | Kind in low 5 bits (mask `0x1F`). Older toolchains also set bit `0x20` here for direct iface. |
| 0x18 | `equal` func ptr | |
| 0x20 | `gcdata` *byte | |
| 0x28 | `str` int32 | `nameOff` from `moduledata.types` |
| 0x2C | `ptrToThis` int32 | `typeOff` |

Kinds: 1 bool, 2 int, 3–6 int8–int64, 7 uint, 8–11 uint8–uint64, 12 uintptr, 13 float32, 14 float64, 15–16 complex, 17 array, 18 chan, 19 func, 20 interface, 21 map, 22 pointer, 23 slice, 24 string, 25 struct, 26 unsafe.Pointer.

`structType` follows the 0x30-byte header: `pkgPath name` (8), `fields []structField` (24). Each `structField` is `{name name; typ *_type; offset uintptr}`. A `name` is a pointer to a flag byte, a length (varint from Go 1.17, 2-byte big-endian before), and the bytes. Flag bit 0 means exported. Bit 1 means a tag follows. Struct tags (`json:"host"`) are often the best field names you will get.

When `tflag & 1`, an `uncommonType` follows the kind-specific part: `{pkgPath nameOff; mcount uint16; xcount uint16; moff uint32}`. It points to a `[mcount]method{name nameOff; mtyp typeOff; ifn textOff; tfn textOff}` array. `tfn` is the method entry relative to `moduledata.text`. This recovers method names for stripped types.

Hand-decode one type to confirm a tool's output. Use the tool for the rest.

---

## 6. Runtime Call Sites That Reveal Intent

| Call | ABIInternal arguments | What it tells you |
|---|---|---|
| `runtime.newproc(fn *funcval)` | `RAX` = closure | `go f(x)`. Go 1.17+ wraps the call in a closure: `pkg.func.gowrapN` in recent toolchains, `pkg.func.funcN` in older ones. Follow `[RAX]` to the wrapper, then to the real target. |
| `runtime.makechan(t *chantype, size int)` | `RAX`, `RBX` | Element type and buffer size |
| `runtime.chansend1(c, elem *T)` / `chanrecv1` / `chanrecv2` | `RAX`, `RBX` | `c <- v`, `v = <-c`, `v, ok = <-c` |
| `runtime.selectgo` | case array | `select`. The returned index selects the case branch. |
| `runtime.newobject(t *_type)` | `RAX` = type | `new(T)` / escaping `&T{}`. Go 1.24+ often calls a size-class variant (`runtime.mallocgcSmallScanNoHeaderSCn`) with the type in `RBX`. |
| `runtime.makeslice(t, len, cap)` / `growslice` | | Slice element type |
| `runtime.mapaccess1_faststr(t *maptype, m, key string)` / `mapassign*` | | Map key and value types come from `t` |
| `runtime.convT64`, `convTstring`, `convT` | | A value boxed into an interface, usually just before `fmt.*` or a logger |
| `runtime.concatstring2..5`, `concatstrings` | | String building. Good place to read URLs and paths. |
| `runtime.gopanic`, `runtime.panicIndex`, `panicSliceAlen` | | Error paths. Skip them. |
| `runtime.deferproc` / `deferreturn` | | Non open-coded `defer` |

`main.main` is the user entry. `main.init` and `pkg.init.N` run first and often decode configuration. Package `init` order is fixed by the `inittasks` list in `moduledata`.

---

## 7. Obfuscated And Unusual Builds

| Sign | Cause | Approach |
|---|---|---|
| Function names like `a1B2c3.Xyz`, no build info, no file paths | garble (`-literals`, `-tiny`) | pclntab structure is intact. Entry points and boundaries still work. Package grouping survives as shared prefixes. `-literals` turns strings into inline XOR/arith decoders. Emulate them per function or hook the result. |
| No pclntab magic, high entropy | UPX or a crypter around the Go binary | Unpack first ([unpacking-memory-dump.md](../02-dynamic-instrumentation/unpacking-memory-dump.md)). |
| Magic present but `nfunc` absurd | Header magic tampered, or a false hit in PE `.rdata` | Validate `pad`/`minLC`/`ptrSize`, then check that `_func.entryOff` equals the functab entry for several functions. |
| `-buildmode=c-shared` / `plugin` | Go inside a `.so` or `.dll` | Exports are `//export` cgo wrappers (`_cgoexp_*`). The Go side is normal. |
| cgo | `_cgo_*`, `x_cgo_init`, `crosscall2` | C code uses the platform ABI. Go code uses the Go ABI. Switch conventions at `runtime.cgocall` / `asmcgocall`. |

---

## 8. Scripts

### Function List From pclntab (Static, Any Format)
Tested on Go 1.27 ELF amd64/arm64, PE amd64, and Mach-O arm64 stripped with `-s -w`. Output matched `go tool nm` on unstripped builds. The 1.2 and 1.16 branches follow `debug/gosym`. Validate them on a known sample before you rely on them.

```python
# go_pclntab.py. Run: uv run --with lief python -I go_pclntab.py "$BIN" [name-filter]
import struct, sys
import lief

MAGIC = {0xFFFFFFFB: "1.2", 0xFFFFFFFA: "1.16", 0xFFFFFFF0: "1.18", 0xFFFFFFF1: "1.20"}

def find_pclntab(data):
    for m in MAGIC:
        pat = struct.pack("<I", m)
        i = data.find(pat)
        while i != -1:
            if data[i+4:i+6] == b"\0\0" and data[i+6] in (1, 2, 4) and data[i+7] in (4, 8):
                return i, MAGIC[m], data[i+7]
            i = data.find(pat, i + 1)
    raise SystemExit("no pclntab header (packed, big-endian, or not gc)")

def text_start(path):
    b = lief.parse(path)
    for name in (".text", "__text"):
        s = b.get_section(name)
        if s:
            base = b.optional_header.imagebase if isinstance(b, lief.PE.Binary) else 0
            return base + s.virtual_address
    return 0

def cstr(data, off):
    return data[off:data.index(b"\0", off)].decode("utf-8", "replace")

def main(path, flt=""):
    data = open(path, "rb").read()
    h, ver, ps = find_pclntab(data)
    P = "<Q" if ps == 8 else "<I"
    word = lambda n: struct.unpack_from(P, data, h + 8 + n * ps)[0]
    nfunc, out = word(0), []
    if ver in ("1.18", "1.20"):
        text = word(2) or text_start(path)            # 0 from Go 1.26
        names, pcln = h + word(3), h + word(7)
        for i in range(nfunc):
            entry, foff = struct.unpack_from("<II", data, pcln + i * 8)
            nameoff = struct.unpack_from("<i", data, pcln + foff + 4)[0]
            out.append((text + entry, cstr(data, names + nameoff)))
    elif ver == "1.16":
        names, pcln = h + word(2), h + word(6)
        for i in range(nfunc):
            entry, foff = struct.unpack_from("<" + P[1] * 2, data, pcln + i * 2 * ps)
            nameoff = struct.unpack_from("<i", data, pcln + foff + ps)[0]
            out.append((entry, cstr(data, names + nameoff)))
    else:                                               # 1.2-1.15
        ftab = h + 8 + ps
        for i in range(nfunc):
            entry, foff = struct.unpack_from("<" + P[1] * 2, data, ftab + i * 2 * ps)
            nameoff = struct.unpack_from("<i", data, h + foff + ps)[0]
            out.append((entry, cstr(data, h + nameoff)))
    print(f"pclntab file+0x{h:x} layout={ver} ptrsize={ps} nfunc={nfunc}")
    for ea, name in out:
        if flt in name:
            print(f"0x{ea:x} {name}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
```

The file offset of the header is printed. The addresses are virtual addresses. Use `main.` as the filter for a first look.

### Apply Names In IDA (`ida-mcp` `execute_python`)
Write the script output to a file, then run this against the open database:
```python
import ida_funcs, ida_name, ida_auto

applied = 0
for line in open("/path/to/go_funcs.txt"):
    if not line.startswith("0x"):
        continue
    ea_s, name = line.split(" ", 1)
    ea = int(ea_s, 16)
    if not ida_funcs.get_func(ea):
        ida_funcs.add_func(ea)
    if ida_name.set_name(ea, name.strip(), ida_name.SN_FORCE | ida_name.SN_NOWARN):
        applied += 1
ida_auto.auto_wait()
print(f"applied {applied} names")
```
IDA's name sanitizer replaces characters such as `(*T)` brackets. The pclntab string stays the authoritative name.

---

## 9. Verify
- `go version -m` and the pclntab magic agree on the version range.
- For three functions, `_func.entryOff` equals the functab `entryOff`, and the entry disassembles to a stack-check prologue.
- `main.main` exists and is referenced from `runtime.main` (`call` through `main_main·f`).
- A recovered struct layout matches the offsets used in at least one function that touches it.

## 10. Boundaries And Anti-Patterns
- Do not read code before names are applied. A stripped Go binary is thousands of `sub_` functions that pclntab can name in seconds.
- Filter out `runtime.*`, `internal/*`, `sync.*`, `reflect.*`, and vendored std packages. Start from `main.*` and the module path shown by `go version -m`.
- Do not treat Go strings as C strings, and do not rely on `strings` alone for literals.
- Do not apply the System V or Microsoft x64 convention to a Go function. Results in `RBX`/`RCX` will look like garbage.
- Do not use pre-1.17 stack-offset reasoning on a register-ABI binary, or the reverse.
- Do not trust a Go-analysis tool's type output for a toolchain newer than the tool. Check one type by hand.
