# Native C/C++ ABI, Calling Conventions, And Data Structures

## When To Open
Open this file for native C or C++ built by MSVC, GCC, or Clang (x86, x64, ARM64) when you need to type functions, recover classes, or read STL objects. Typical signs are `.?AV` / `.?AU` strings, `??_7` / `_ZTV` symbols, indirect calls through `[reg+N]` after loading `[obj]`, and `std::` strings in panics or exceptions. Go and Rust have their own files ([native-golang.md](native-golang.md), [native-rust.md](native-rust.md)).

Scope: calling conventions per platform, vtable and RTTI layouts (MSVC and Itanium), multiple and virtual inheritance, constructor/destructor recognition, STL layouts for MSVC STL / libstdc++ / libc++, and struct recovery.

---

## 1. Identify The Compiler And C++ ABI

| Evidence | Toolchain / ABI |
|---|---|
| `.?AV`/`.?AU` strings, `??_7` symbols, Rich header, `_CxxThrowException`, `__CxxFrameHandler3/4`, `vcruntime140.dll` | MSVC ABI (MSVC or `clang-cl`) |
| `_ZTV`/`_ZTI`/`_ZTS` symbols, `__cxa_throw`, `__gxx_personality_v0`, `libstdc++.so.6` | Itanium ABI with libstdc++ (GCC, or Clang on Linux) |
| `std::__1::` or `NSt3__1` in names, `libc++.so` / `libc++abi`, `libc++_shared.so` on Android | Itanium ABI with libc++ (Apple, Android NDK, some Linux) |
| MinGW: `_ZTV` symbols inside a PE, `libstdc++-6.dll`, `libgcc_s_seh-1.dll` | Itanium ABI on Windows. Calling convention is still Microsoft x64. |
| `__cxx11` in names (`NSt7__cxx1112basic_string`) | libstdc++ C++11 ABI string (GCC 5+). Absent means the old COW string. |

```bash
llvm-undname '?f@D@ns@@UEAAHXZ'          # MSVC: "public: virtual int __cdecl ns::D::f(void)"
llvm-undname '??_7D@ns@@6BB@@@'          # "const ns::D::`vftable'{for `B'}"
echo _ZN2ns1D1fEv | c++filt              # Itanium; llvm-cxxfilt also works. llvm-cxxfilt does not decode MSVC names.
readelf -sW "$BIN" | c++filt | grep -E 'vtable for|typeinfo for'
strings -a -t x "$BIN" | grep -E '\.\?A[VUW]'   # MSVC TypeDescriptor names
```

On Windows hosts `undname.exe` ships with Visual Studio. `dumpbin /headers /exports` (VS) or `llvm-readobj --coff-exports` show the PE surface.

---

## 2. Calling Conventions

| Convention | Integer/pointer args | FP args | `this` | Return | Stack rules |
|---|---|---|---|---|---|
| System V AMD64 (Linux, macOS, BSD) | `RDI RSI RDX RCX R8 R9` | `XMM0`–`XMM7` | `RDI` | `RAX`(:`RDX`), `XMM0`(:`XMM1`) | 128-byte red zone below `RSP`. `AL` = number of vector regs for variadic calls. |
| Microsoft x64 | `RCX RDX R8 R9` (positional, shared with `XMM0`–`XMM3`) | `XMM0`–`XMM3` | `RCX` | `RAX`, `XMM0` | Caller reserves 32-byte home space. At callee entry it is `[rsp+8]`..`[rsp+0x20]`. Structs > 8 bytes or not 1/2/4/8 are passed by pointer. |
| AAPCS64 (Linux, Android) | `X0`–`X7` | `V0`–`V7` | `X0` | `X0`(:`X1`), `V0` | Indirect result pointer in `X8`. `X18` platform register. |
| Apple ARM64 | as AAPCS64 | as AAPCS64 | `X0` | as AAPCS64 | Variadic args always on the stack. `X18` reserved. Stack args use natural alignment, not 8-byte slots. |
| Windows ARM64 | as AAPCS64 | as AAPCS64 | `X0` | as AAPCS64 | `X18` = TEB. Variadic calls use no FP registers. Floats go through `X0`–`X7`, then the stack. |
| x86 `__cdecl` | Stack, right to left | Stack | n/a | `EAX`(:`EDX`), `ST0` | Caller cleans (`add esp, N` after the call) |
| x86 `__stdcall` (Win32 API) | Stack | Stack | n/a | `EAX` | Callee cleans (`ret N`). Decorated `_name@N`. |
| x86 `__fastcall` | `ECX`, `EDX`, then stack | Stack | n/a | `EAX` | Callee cleans. `@name@N`. |
| x86 MSVC `__thiscall` | Stack | Stack | `ECX` | `EAX` | Callee cleans |
| x86 GCC/Clang member functions | Stack | Stack | First stack arg | `EAX` | Caller cleans. No `ECX` `this`. |

Non-volatile (callee-saved) registers: SysV `RBX RBP R12–R15`. Microsoft x64 adds `RDI RSI` and `XMM6`–`XMM15`. AAPCS64 `X19`–`X28`, low 64 bits of `V8`–`V15`.

### Hidden Struct Return
A non-trivially-copyable or large return value goes through a hidden pointer:
- SysV: `RDI` = return buffer, `RSI` = `this`. The function returns the buffer in `RAX`.
- Microsoft x64: free function `RCX` = buffer. Member function `RCX` = `this`, `RDX` = buffer. Returns the buffer in `RAX`.
- AAPCS64 / Apple: `X8` = buffer. Windows ARM64 uses `X8` only for plain aggregates. Non-aggregate C++ types pass the buffer in `X0`, or in `X1` when `this` is in `X0`, and return it in `X0`.

A function that writes several fields through its first argument and returns it is a struct return, not a `void f(T*)`.

---

## 3. Vtables

### Itanium (GCC, Clang, MinGW)
A vtable group per class has one vtable per polymorphic base subobject. The object's vptr points at the first function slot, not the start of the symbol.

```text
_ZTV7Derived (vtable for Derived):
  [vptr-0x10-8n]  vcall offsets / vbase offsets   (only with virtual bases)
  [vptr-0x10]     offset_to_top  (ptrdiff_t; 0 for primary, -N for a base at +N)
  [vptr-0x08]     &_ZTI7Derived  (typeinfo)
  [vptr+0x00]     slot 0 ...
  next group:     offset_to_top = -0x10, &_ZTI7Derived, thunk slots for the secondary base
```
- A virtual destructor takes two slots: D1 complete-object (`_ZN1AD1Ev`) then D0 deleting (`_ZN1AD0Ev`). D0 calls D1 and then `operator delete` (`_ZdlPv` / `_ZdlPvm`).
- A pure virtual slot points to `__cxa_pure_virtual`. That class is abstract.
- Construction vtables (`_ZTC`) and the VTT (`_ZTT`) exist when there are virtual bases. Constructors take a VTT pointer as a hidden argument in that case.

Verified with Clang/libc++ (arm64): for `struct D : A, B` with 8-byte members, `offset_to_top` of the `B` vtable inside `D` is `-16`. For `struct V : virtual A`, `vtable[-3]` (the vbase offset) is `16`.

### MSVC
```text
[vftable-8 / -4]  pointer (absolute VA, relocated) to RTTICompleteObjectLocator
[vftable+0]       slot 0 ...
```
- One vftable per base that has virtual functions. Symbols `??_7Derived@@6B@` (single) or `??_7Derived@@6BBase@@@` ("for Base").
- A virtual destructor is one slot: the scalar deleting destructor `??_G` (or vector deleting `??_E`). It takes a flags argument. `flags & 1` means call `operator delete` after the destructor.
- Virtual bases use a separate vbptr and `??_8Class@@7B@` vbtable. Entry 0 is the offset from the vbptr to the object start (usually 0). Entry `i` is the offset from the vbptr to virtual base `i`. A `vtordisp` slot sits 4 bytes before a virtual base when constructors or destructors call virtuals.
- With `/GR-` there is no COL. The `vftable-8` slot then belongs to the previous data item.

### Dispatch Patterns
```nasm
mov rax, [rcx]          ; vptr (MSVC this = RCX; SysV this = RDI)
call qword ptr [rax+18h] ; slot 3 on x64 (0x18/8)
```
```text
ldr x8, [x0]            ; arm64
ldr x8, [x8, #0x18]
blr x8                  ; arm64e: ldraa/blraa with a discriminator
```
On arm64e (Apple), vtable entries are signed. The discriminator is the slot address blended with a hash of the mangled method name, which can identify the method.

### Thunks
- Itanium non-virtual thunk `_ZThn16_N7Derived1gEv`: `sub rdi, 16` (or `add rdi, -16`) then `jmp Derived::g`.
- Itanium virtual thunk `_ZTv0_n24_...`: loads the adjustment from the vtable at `-24`, then jumps.
- MSVC adjustor thunk `[thunk]:Derived::g'adjustor{16}'`: `sub rcx, 10h` then `jmp`.

The delta in a thunk is the base subobject offset. It corroborates the COL `offset` field or the Itanium `offset_to_top`.

---

## 4. RTTI Layouts

### MSVC (all fields 32-bit)
In x64 images the pointer fields are image-relative RVAs (`ImageBase + rva`). In x86 images they are absolute VAs. The vftable-to-COL pointer is always a full pointer.

`RTTICompleteObjectLocator` (`??_R4`). Size 0x18 on x64, 0x14 on x86:

| Off | Field | Meaning |
|---|---|---|
| 0x00 | `signature` | 1 on x64 (image-relative), 0 on x86 |
| 0x04 | `offset` | Offset of this vptr in the complete object |
| 0x08 | `cdOffset` | Constructor displacement (vtordisp) |
| 0x0C | `pTypeDescriptor` | → `TypeDescriptor` |
| 0x10 | `pClassDescriptor` | → `RTTIClassHierarchyDescriptor` |
| 0x14 | `pSelf` | x64 only. RVA of this COL. Best validation check. |

`TypeDescriptor` (`??_R0`). Lives in writable `.data`, because `spare` caches the undecorated name:

| Off x64 / x86 | Field |
|---|---|
| 0x00 / 0x00 | `pVFTable` → `type_info::vftable` (`??_7type_info@@6B@`) |
| 0x08 / 0x04 | `spare` (NULL in the file) |
| 0x10 / 0x08 | `name`: `.?AV` class, `.?AU` struct, `.?AT` union, `.?AW4` enum, then `Name@Namespace@@` |

`RTTIClassHierarchyDescriptor` (`??_R3`), 0x10 bytes: `signature` (0), `attributes` (`1` multiple inheritance, `2` virtual inheritance, `4` ambiguous), `numBaseClasses` (includes the class itself), `pBaseClassArray` (`??_R2`, array of pointers/RVAs to BCDs, entry 0 is the class itself).

`RTTIBaseClassDescriptor` (`??_R1`), 0x1C bytes: `pTypeDescriptor`, `numContainedBases`, `PMD {mdisp, pdisp, vdisp}` (int32 ×3), `attributes`, `pClassDescriptor`. `mdisp` is the base's offset. `pdisp` is the vbptr offset (`-1` when not virtual). `vdisp` is the index into the vbtable. Attribute bits: `1|8` private on path, `2` ambiguous, `4` private, `0x10` virtual, `0x40` has CHD pointer.

### Itanium typeinfo
| Class kind | Layout (64-bit) |
|---|---|
| No bases: `__class_type_info` | `{vptr, const char* name}` |
| One public non-virtual base at offset 0: `__si_class_type_info` | `{vptr, name, const __class_type_info* base}` |
| Anything else: `__vmi_class_type_info` | `{vptr, name, uint32 flags, uint32 base_count, {base_type*, long offset_flags}[base_count]}` |

- `vptr` = `&_ZTVN10__cxxabiv117__class_type_infoE + 16` (or `120__si_` / `121__vmi_`). In a dynamically linked binary these are imported symbols. Every relocation to them marks a typeinfo object, even when the binary is stripped:
  ```bash
  readelf -rW "$BIN" | grep -E '__cxxabiv1(17__class|20__si_class|21__vmi_class)_type_info'
  ```
- `name` points to the `_ZTS` string, which is the mangled type **without** `_Z`: `"7Derived"`, `"N2ns1DE"`. Demangle it with `echo _Z<name> | c++filt` or `c++filt -t <name>`.
- `offset_flags`: bit 0 virtual, bit 1 public, bits 8+ the signed offset. For a virtual base the offset is the vtable position of the vbase offset. Verified: `V : virtual A` gives `0xffffffffffffe803` = virtual|public, offset `-0x18`.
- Apple arm64 sets bit 63 of `name` for non-unique (hidden visibility) RTTI. Mask it off before you dereference it. Verified on macOS arm64: `0x80000001022385e8`.

---

## 5. Constructors, Destructors, Allocation
- A constructor calls base constructors, then stores the class's vptr(s) into `[this+off]`, then initializes members. The stored vtable address names the class.
- A destructor stores the vptr again at entry (reset to its own class), destroys members in reverse, then calls base destructors.
- `operator new(size)` immediately followed by a constructor call gives `sizeof(Class)`. MSVC `??2@YAPEAX_K@Z`, Itanium `_Znwm` (64-bit) / `_Znwj` (32-bit).
- Inlined constructors still store the vtable address. Search for code xrefs to each vtable.
- Exceptions: MSVC `_CxxThrowException(obj, _ThrowInfo*)`. The ThrowInfo → CatchableTypeArray → CatchableType chain names the thrown type (`??_R0` again). Itanium `__cxa_throw(obj, typeinfo*, dtor)` names it directly.

---

## 6. STL Layouts (64-bit Release Builds)

MSVC debug builds (`_ITERATOR_DEBUG_LEVEL` 1 or 2) add a `_Myproxy` container-proxy pointer at offset 0 of most containers. Everything below then shifts by 8.

### `std::string`
| Library | Size | Layout | Small-string test | SSO capacity |
|---|---|---|---|---|
| MSVC | 32 | `{union{char buf[16]; char* ptr}; size_t size@0x10; size_t cap@0x18}` | `cap < 16` → inline | 15 (`wstring` 7) |
| libstdc++ C++11 ABI | 32 | `{char* p; size_t len@8; union{char buf[16]; size_t cap}@0x10}` | `p == this+0x10` | 15 |
| libstdc++ old COW ABI | 8 | `char* p`. Header `{len, cap, refcount}` sits before `p`. | none | n/a |
| libc++ standard (Linux, Android, Apple x86_64) | 24 | long: `{cap \| 1 (bit 0 = long), size@8, data@0x10}`. short: byte 0 = `size << 1`, chars from +1 | `byte0 & 1` → long | 22 |
| libc++ alternate (Apple arm64) | 24 | long: `{data, size@8, cap@0x10 with bit 63 = long}`. short: chars from +0, byte 23 = size (bit 7 = long) | `byte23 & 0x80` → long | 22 |

Verified on Apple arm64 libc++: `"short"` = `68 6f 72 74 73 ...` with byte 23 = `0x05`. A 40-char string was `{ptr, 0x28, 0x8000000000000030}`.

### Other Containers
| Type | MSVC | libstdc++ | libc++ |
|---|---|---|---|
| `vector<T>` (24) | `{first, last, end}` | `{start, finish, end_of_storage}` | `{begin, end, cap}` |
| `unique_ptr<T>` | `T*` (8) | `T*` | `T*` |
| `shared_ptr<T>` (16) | `{T*, _Ref_count_base*}` | `{T*, _Sp_counted_base*}` | `{T*, __shared_weak_count*}` |
| control block | `{vptr, int uses@8, int weaks@0xC}` | `{vptr, int use@8, int weak@0xC}` | `{vptr, long shared_owners@8, long weak_owners@0x10}`, both stored as count − 1 |
| `map`/`set` | `{head*, size}` (16). Node: `{left, parent, right, char color, char isnil, value@0x20}` | `{cmp, header{int color, parent, left, right}@8, count@0x28}` (48). Node: `{color@0, parent@8, left@0x10, right@0x18, value@0x20}` | `{begin_node, root (end_node.left), size}` (24). Node: `{left@0, right@8, parent@0x10, bool black@0x18, value@0x20}` |
| `list<T>` | `{head*, size}` (16). Node `{next, prev, value}` | `{next, prev, size}` (24), sentinel inline | `{prev, next, size}` (24) |
| `unordered_map` | `{list (head,size), vector buckets, mask, maxidx, max_load}` (64) | `{buckets, bucket_count, before_begin.next, element_count, rehash_policy{float, next_resize}, single_bucket}` (56) | `{buckets, bucket_count, first_node, size, max_load}` (40) |
| `std::function` | 64 bytes. Impl pointer in the last slot (`+0x38`). | 32: `{storage[16], manager@0x10, invoker@0x18}` | 32: `{buffer[24], impl*@0x18}` |

libc++ `shared_ptr` counts verified on Apple arm64: two owners gave `shared_owners = 1`. Weak counts in libstdc++ and MSVC include one extra reference held by all strong owners together.

The libc++ map layout above was verified on Apple arm64 (`{begin, root, 1}` with one element). The other rows follow the library headers. Confirm on your sample by finding the size check (`cmp [obj+N], ...`) or the element count increment.

---

## 7. Scripts

### MSVC RTTI Scanner (Static, LIEF)
Verified on `clang-cl` x64 and x86 PEs: it found both `ns::D` vftables (`offset 0x0` and `0x10` on x64, `0x8` on x86) and the virtual-base layout of `V`.

```python
# msvc_rtti.py. uv run --with lief python -I msvc_rtti.py "$BIN"
import struct, sys
import lief

pe = lief.PE.parse(sys.argv[1])
base = pe.optional_header.imagebase
x64 = pe.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
secs = [(s.virtual_address, bytes(s.content)) for s in pe.sections]

def rd(rva, n):
    for va, d in secs:
        if va <= rva and rva + n <= va + len(d):
            return d[rva - va: rva - va + n]

def u32(rva):
    b = rd(rva, 4)
    return struct.unpack("<I", b)[0] if b else None

def ptr(field):                      # x64: RVA, x86: VA
    return field if x64 else field - base

def td_name(td_rva):
    b = rd(td_rva + (0x10 if x64 else 8), 256) or b""
    return b.split(b"\0", 1)[0].decode("latin-1")

cols = {}
for va, d in secs:
    for off in range(0, len(d) - 0x18, 4):
        sig, offset, cdoff, td, chd = struct.unpack_from("<IIIII", d, off)
        if sig != (1 if x64 else 0):
            continue
        rva = va + off
        if x64 and struct.unpack_from("<I", d, off + 0x14)[0] != rva:
            continue                  # pSelf must point back at the COL
        if not x64 and not (base <= td < base + 0x7fffffff and base <= chd < base + 0x7fffffff):
            continue
        name = td_name(ptr(td))
        if not name.startswith(".?A"):
            continue
        attrs, nbases, bca = u32(ptr(chd) + 4), u32(ptr(chd) + 8), u32(ptr(chd) + 12)
        if attrs is None or nbases is None or nbases > 512:
            continue
        bases = []
        for i in range(nbases):
            bcd = ptr(u32(ptr(bca) + 4 * i))
            mdisp = struct.unpack("<i", rd(bcd + 8, 4))[0]
            bases.append(f"{td_name(ptr(u32(bcd)))}@{mdisp:+#x}")
        cols[base + rva] = (name, offset, attrs, bases)

psz, fmt = (8, "<Q") if x64 else (4, "<I")
for va, d in secs:
    for off in range(0, len(d) - psz, psz):
        p = struct.unpack_from(fmt, d, off)[0]
        if p in cols:
            name, offset, attrs, bases = cols[p]
            print(f"vftable 0x{base + va + off + psz:x} {name} vptr_offset={offset:#x} "
                  f"chd_attrs={attrs:#x} bases={' '.join(bases[1:]) or '-'}")
```
Demangle a reported name with `llvm-undname '??_R0<name>@8'`, for example `llvm-undname '??_R0?AUD@ns@@@8'` → `struct ns::D 'RTTI Type Descriptor'`.

### Label MSVC Vtables In IDA (`ida-mcp` `execute_python`)
IDA 9 usually names vftables itself when RTTI is intact. Use this when it did not, or after an unpack.
```python
import ida_bytes, ida_ida, ida_nalt, ida_name, ida_segment, idautils

base = ida_nalt.get_imagebase()
is64 = ida_ida.inf_is_64bit()
named = 0
for n in range(ida_segment.get_segm_qty()):
    seg = ida_segment.getnseg(n)
    if seg.perm & ida_segment.SEGPERM_EXEC:
        continue
    for ea in range(seg.start_ea, seg.end_ea - 0x18, 4):
        if ida_bytes.get_dword(ea) != (1 if is64 else 0):
            continue
        if is64 and base + ida_bytes.get_dword(ea + 0x14) != ea:
            continue
        td = ida_bytes.get_dword(ea + 0x0C) + (base if is64 else 0)
        raw = ida_bytes.get_strlit_contents(td + (0x10 if is64 else 8), -1, ida_nalt.STRTYPE_C)
        if not raw or not raw.startswith(b".?A"):
            continue
        cls = raw.decode("latin-1")[4:].rstrip("@")
        ida_name.set_name(ea, f"COL_{cls}_{ida_bytes.get_dword(ea + 4):x}", ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
        for x in idautils.DataRefsTo(ea):
            vt = x + (8 if is64 else 4)
            ida_name.set_name(vt, f"vftable_{cls}_{ida_bytes.get_dword(ea + 4):x}", ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
            named += 1
print("vftables named:", named)
```
The suffix is the COL `offset`, so each vftable of a multiply-inherited class gets a distinct name. Ghidra users can run the bundled `RecoverClassesFromRTTIScript.java` (MSVC and GCC RTTI).

---

## 8. Recovering An Unknown Struct
Do not invent field types. Collect every access to the same pointer from the function, its callers, and its callees.

- A displacement names an offset and a width (`byte`, `dword`, `qword`).
- `malloc(N)`, `operator new(N)`, `alloca(N)`, or a stack slot of size `N` is a size observation, not a guess.
- A field passed to `strlen` or printed as `%s` is a string pointer. A field that is called is a function pointer. A field used with `++` or `lock xadd` is a counter or refcount. Offset 0 holding a vtable address is a vptr. `next` and `prev` at stable offsets are a list node.
- Three adjacent pointers where the code computes `(p1 - p0) / k` is a `vector` of `k`-byte elements.
- The struct size is the highest offset plus that field's width, rounded up only when a later access or allocation proves the padding.
- Mark every field `proposed` until the access is in the disassembly. One function's decompiler view is not enough when a caller writes an offset the callee never reads.

## 9. Verify
- A recovered vtable: the COL `offset` (MSVC) or `offset_to_top` (Itanium) matches the thunk delta and the constructor's store offset.
- A recovered class size: matches the `operator new` argument at an allocation site.
- An STL layout guess: the code that reads `size()` or tests SSO uses the offsets you assumed.
- A calling convention: callee-saved registers pushed in the prologue match the platform (`RDI`/`RSI` saved means Microsoft x64).

## 10. Boundaries And Anti-Patterns
- Do not mix conventions. On Microsoft x64 `RDI`/`RSI` are callee-saved, not arguments.
- Do not assume vptr at offset 0 means the object start. Secondary vptrs sit inside the object. Check `offset` / `offset_to_top`.
- Do not read a `std::string` as a pointer without the SSO test for that library.
- Do not apply release STL layouts to an MSVC debug build.
- Do not treat MSVC vbptr/vbtable entries or Itanium vbase offsets as function slots.
- Do not dereference an Apple arm64 typeinfo name pointer without masking bit 63.
