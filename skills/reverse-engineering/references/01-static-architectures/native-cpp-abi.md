# Native C/C++ ABI, Calling Conventions & Data Structures

## 1. Title & Overview
- **Domain**: Native compiled binaries (C and C++ compiled with MSVC, GCC, and Clang targeting x86-64, ARM64, and x86-32 architectures).
- **Scope**: Reversing calling conventions (System V AMD64, Microsoft x64, ARM64 AAPCS, cdecl, stdcall, thiscall), extracting and typing virtual method tables (vtables), decoding Runtime Type Information (MSVC RTTI vs Itanium C++ ABI typeinfo), reconstructing C++ Standard Template Library (STL) container layouts (`std::string`, `std::vector`, `std::map`, `std::unique_ptr`, `std::shared_ptr`), and analyzing multiple/virtual inheritance `this`-pointer adjustment thunks.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing native non-managed binaries exhibiting object-oriented or structured C/C++ compiled constructs:

### Binary Signatures & Section Clues
- **PE Binaries (MSVC)**:
  - Sections: `.rdata` contains pointer tables followed by RTTI descriptors; `.pdata` contains exception handling function tables.
  - Mangled symbol prefixes: `?` (e.g., `?method@Class@@QEAAXXZ`), decorated vtable symbols `??_7<Class>@@6B@`.
  - Type descriptor strings in `.data` or `.rdata`: `.?AV<ClassName>@@` (e.g., `.?AVbad_alloc@std@@`, `.?AVMyClass@@`).
- **ELF & Mach-O Binaries (GCC / Clang - Itanium ABI)**:
  - Mangled symbol prefixes: `_Z` (e.g., `_ZN5Class6methodEv`), vtable references `_ZTV<name>`, typeinfo references `_ZTI<name>`, typeinfo names `_ZTS<name>`.
  - Sections: `.rodata` contains vtables with null-delimited mangled names immediately preceding typeinfo nodes.
- **Assembly Indicators**:
  - Indirect virtual dispatch calls: `mov rax, [rdi]; call qword ptr [rax + 0x18]` (Itanium) or `mov rax, [rcx]; call qword ptr [rax + 0x20]` (MSVC).
  - Base class `this` adjustments before dispatch: `add rdi, -0x10` or `sub rcx, 0x10` preceding a virtual method call or within an adjustor thunk.

---

## 3. Tooling & CLI/MCP Actions
- **Headless IDA Pro MCP / Disassembler**:
  - `open_binary`: Load target binary into the analysis session.
  - `get_procedure`: Retrieve disassembly of prospective virtual dispatch sites and constructors.
  - `get_pseudocode`: Generate decompiler pseudocode for member functions.
  - `set_local_type` / `apply_type`: Inject class vtable structs and class layouts into Hex-Rays / local types.
- **CLI & Symbol Utilities**:
  - GCC/Clang symbol demangling: `c++filt -_ <mangled_symbol>`
  - MSVC symbol demangling: `undname -f <mangled_symbol>`
  - Section symbol dumping:
    ```bash
    # Linux / ELF: Find Itanium RTTI symbols
    readelf -Ws <binary> | grep -E '_ZTV|_ZTI|_ZTS'
    # Windows / PE: Dump export names and symbol table
    dumpbin /exports /symbols <binary.exe>
    # String scan for MSVC RTTI descriptors
    strings -a -t x <binary.exe> | grep '\.\?AV'
    ```

---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 Calling Convention Normalization & Parameter Mapping
When analyzing decompiled or disassembled code, parameter registers and stack frames differ sharply based on target platform:

| Calling Convention | Architecture | Integer / Pointer Arguments | Float / SIMD Arguments | `this` Pointer | Return Value | Shadow / Stack Reservation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **System V AMD64** | Linux / macOS x86-64 | `RDI, RSI, RDX, RCX, R8, R9` | `XMM0 - XMM7` | `RDI` (first arg) | `RAX` (int), `XMM0` (float) | None (128-byte red zone below `rsp`) |
| **Microsoft x64** | Windows x86-64 | `RCX, RDX, R8, R9` | `XMM0 - XMM3` | `RCX` (first arg) | `RAX` (int), `XMM0` (float) | 32-byte caller-allocated shadow store |
| **ARM64 (AAPCS64)** | Linux / Android / iOS / Win | `X0 - X7` | `V0 - V7` (D0-D7/S0-S7) | `X0` (first arg) | `X0` (or `X8` for large structs) | None |
| **x86-32 __thiscall** | Windows MSVC x86 | Stack (right to left) | Stack | `ECX` | `EAX` | Callee cleans stack |
| **x86-32 __cdecl** | Linux / Windows x86 | Stack (right to left) | Stack | Stack (first pushed) | `EAX` / `ST0` | Caller cleans stack |

#### Workflow:
1. Identify the host OS and compiler from the binary header.
2. In MSVC x64, account for the mandatory 32-byte shadow space (`[rsp + 0x00]` through `[rsp + 0x18]`). Function prologues commonly spill incoming argument registers (`RCX, RDX, R8, R9`) back into their home locations in the caller's frame (`[rsp + 0x08]`, `[rsp + 0x10]`, etc.).
3. Identify constructor methods: Look for functions receiving a pointer in the `this` register (`RCX` or `RDI` or `X0`), writing immediate addresses (vtable pointers) into `[this + 0x00]`, and returning `this`.

---

### 4.2 Vtable Pointer Array Extraction & Virtual Dispatch Recovery
Virtual method tables are arrays of function pointers placed into read-only data sections (`.rodata` in ELF, `.rdata` in PE).

#### Memory Structure:
- Each polymorphic C++ class containing virtual methods has an associated vtable.
- The object instance stores a hidden pointer (`vptr`) at offset `0x0` pointing into the vtable method slot array.
- In single inheritance:
  ```text
  Object Layout:
  [+0x00] vptr -------------------> Vtable in .rodata/.rdata:
  [+0x08] member_1                   Slot 0: &Class::Method0
  [+0x10] member_2                   Slot 1: &Class::Method1
                                     Slot 2: &Class::Method2
  ```

#### Recovery Workflow:
1. Search `.rdata` or `.rodata` for sequential clusters of valid executable code pointers (`.text`).
2. Identify cross-references (`xrefs`) to the start of this pointer array:
   - If referenced from inside a function that stores the address to `*(arg0 + 0)`, that function is a constructor (`ClassName::ClassName`) or destructor.
3. Trace indirect calls in callers:
   ```nasm
   mov     rax, [rcx]           ; Load vtable pointer from object
   call    qword ptr [rax+10h]  ; Call 3rd virtual function (Slot 2, index 0x10/8 = 2)
   ```
4. Define a C-structure in the disassembler representing the vtable:
   ```c
   struct ClassName_Vtbl {
       void (*Method0)(ClassName* this);
       int  (*Method1)(ClassName* this, int a);
       void (*Method2)(ClassName* this, const char* str);
   };
   ```
5. Apply `ClassName*` to the `this` argument register across candidate call sites.

---

### 4.3 RTTI Structure Reconstruction: MSVC vs Itanium ABI

#### A. MSVC Complete Object Locator
On MSVC, preceding the first virtual method pointer in the vtable (at index `-1`, i.e., `vtable - 8` on x64), there is a pointer to the `_RTTICompleteObjectLocator` structure.

```text
MSVC Structure Hierarchy:
vtable address ---> [ Slot 0: &Method0 ]
[vtable - 0x08] ---> Pointer to _RTTICompleteObjectLocator

struct _RTTICompleteObjectLocator (x64 / 32-bit RVAs):
  +0x00: uint32_t signature;           // 0 = 32-bit absolute, 1 = 64-bit relative RVAs
  +0x04: uint32_t offset;              // Offset of this vptr within complete object
  +0x08: uint32_t cdOffset;            // Constructor displacement offset
  +0x0C: int32_t  pTypeDescriptor;     // ImageBase-relative RVA to TypeDescriptor
  +0x10: int32_t  pClassDescriptor;    // ImageBase-relative RVA to _RTTIClassHierarchyDescriptor
  +0x14: int32_t  pSelf;               // ImageBase-relative RVA back to complete object locator

struct TypeDescriptor:
  +0x00: void* pVFTable;               // &type_info::`vftable'
  +0x08: void* spare;                  // Reserved runtime pointer
  +0x10: char  name[];                 // Mangled type name: ".?AVClassName@@"
```

#### B. Itanium C++ ABI (GCC / Clang)
Under Itanium ABI, the vtable pointer points directly to the first virtual function slot. Offsets `-1` and `-2` contain explicit type and offset information:
- `vtable[-1]` (`vtable - 0x08` on 64-bit): Pointer to `abi::__class_type_info` (or derivative `abi::__si_class_type_info`, `abi::__vmi_class_type_info`).
- `vtable[-2]` (`vtable - 0x10` on 64-bit): `offset_to_top` (signed integer representing distance from this subobject vptr to the complete object beginning).

```text
Itanium Layout:
[vtable - 0x10] -> ptrdiff_t offset_to_top
[vtable - 0x08] -> Pointer to std::type_info (e.g. abi::__si_class_type_info)
vtable base   ---> [ Slot 0: &VirtualMethod0 ]
                   [ Slot 1: &VirtualMethod1 ]

abi::__si_class_type_info structure:
  +0x00: void* vtable;                 // Pointer to vtable of abi::__si_class_type_info
  +0x08: const char* type_name;        // Pointer to mangled string: "_ZTS9ClassName"
  +0x10: abi::__class_type_info* base; // Pointer to parent base class type_info
```

---

### 4.4 Multiple Inheritance & `this`-Pointer Adjustment Thunks
When a class inherits from multiple base classes, an instance possesses multiple vtable pointers (`vptrs`), one for each base with virtual methods:

```text
class Derived : public BaseA, public BaseB { ... };

Derived Object Layout:
  +0x00: BaseA vptr --------> Derived's BaseA vtable
  +0x08: BaseA members
  +0x10: BaseB vptr --------> Derived's BaseB vtable (Offset: +0x10)
  +0x18: BaseB members
  +0x20: Derived members
```

#### Adjustor Thunk Mechanics:
If `Derived` overrides a virtual method defined in `BaseB`, calling it through a `BaseB*` passes a pointer pointing at `object + 0x10`. The overridden method expects the full `Derived*` at offset `0x00`. The compiler emits an **adjustor thunk**:
```nasm
; System V x86-64 adjustor thunk
Derived::BaseB_Thunk_Method:
    add     rdi, -0x10          ; Adjust 'this' from BaseB subobject to Derived root
    jmp     Derived::Method     ; Jump directly to actual implementation

; MSVC x64 adjustor thunk
[thunk]:Derived::BaseB_Thunk_Method`adjustor{16}':
    sub     rcx, 10h            ; Adjust 'this' pointer from BaseB to Derived
    jmp     Derived::Method
```
**Reversing Action**: When decompiling, if a function simply adds or subtracts a small constant from `rcx`/`rdi` and immediately branches, mark it as an adjustor thunk. Identify the delta to determine the exact subobject offset in the composite struct.

---

### 4.5 STL Container Memory Layout Recognition

#### 1. `std::string` (Small String Optimization / SSO)
Implementations maintain an internal inline buffer for small strings to avoid heap allocation:
- **MSVC (64-bit)**: Total size 32 bytes (`0x20`).
  ```text
  +0x00: union {
             char  _Buf[16];        // Used when _Mysize < 16
             char* _Ptr;            // Pointer to heap buffer when _Mysize >= 16
         } _Bx;
  +0x10: uint64_t _Mysize;          // Current string character count
  +0x18: uint64_t _Myres;           // Allocated capacity (15 for SSO buffer)
  ```
  *Indicator*: If `_Myres >= 16`, string text resides at `*(ptr + 0x00)`; if `_Myres < 16`, text resides directly at `ptr + 0x00`.
- **libstdc++ (GCC, 64-bit)**: Total size 32 bytes (`0x20`).
  ```text
  +0x00: char* _M_dataptr;          // Points to _M_local_buf (+0x10) or heap memory
  +0x08: size_t _M_length;          // String length
  +0x10: union {
             char _M_local_buf[16]; // SSO storage buffer
             size_t _M_allocated_cap;
         };
  ```

#### 2. `std::vector<T>`
Consistently implemented across MSVC, GCC, and Clang as a **3-pointer layout** (total size 24 bytes on 64-bit):
```text
+0x00: T* _Myfirst / _M_start;            // Pointer to first allocated element
+0x08: T* _Mylast  / _M_finish;           // Pointer past the last valid element
+0x10: T* _Myend   / _M_end_of_storage;   // Pointer past end of allocated memory buffer
```
- Element Count: `(Mylast - Myfirst) / sizeof(T)`
- Element Capacity: `(Myend - Myfirst) / sizeof(T)`

#### 3. Smart Pointers
- **`std::unique_ptr<T>`**: 8 bytes. Holds the raw heap pointer `T*` directly (assuming default stateless deleter).
- **`std::shared_ptr<T>`**: 16 bytes.
  ```text
  +0x00: T* _Ptr;                         // Pointer to managed object instance
  +0x08: std::_Ref_count_base* _Rep;      // Pointer to heap control block
  ```
  The control block holds:
  - `+0x08`: 32-bit strong reference counter (`use_count`)
  - `+0x0C`: 32-bit weak reference counter (`weak_count`)
  - `+0x10`: Custom deleter and allocator storage or embedded `T` instance (if allocated via `std::make_shared`).

---

## 5. Concrete Code & Script Examples

### Automated MSVC RTTI Parser & Vtable Labeler (IDAPython)
```python
import ida_bytes
import ida_name
import ida_segment
import idc

def parse_msvc_rtti(image_base):
    """Scan .rdata for _RTTICompleteObjectLocator structures and label vtables."""
    rdata_seg = ida_segment.get_segm_by_name(".rdata")
    if not rdata_seg:
        print("[-] .rdata segment not found.")
        return

    ea = rdata_seg.start_ea
    end_ea = rdata_seg.end_ea

    while ea < end_ea - 0x18:
        # Check signature: 1 = 64-bit relative RVA, 0 = 32-bit absolute
        sig = ida_bytes.get_dword(ea)
        if sig == 1:
            offset = ida_bytes.get_dword(ea + 0x04)
            cd_offset = ida_bytes.get_dword(ea + 0x08)
            type_desc_rva = ida_bytes.get_dword(ea + 0x0C)
            hierarchy_rva = ida_bytes.get_dword(ea + 0x10)

            # Validate RVAs within binary boundaries
            if 0 < type_desc_rva < (end_ea - image_base):
                td_ea = image_base + type_desc_rva
                # TypeDescriptor begins with vftable pointer (8 bytes), then spare (8 bytes), then mangled name
                name_str = idc.get_strlit_contents(td_ea + 0x10)
                if name_str and name_str.startswith(b".?AV"):
                    demangled = idc.demangle_name(name_str.decode('utf-8', errors='ignore'), 0)
                    class_name = demangled if demangled else name_str.decode('utf-8', errors='ignore')
                    
                    # Label the Complete Object Locator
                    col_name = f"RTTI_COL_{class_name}"
                    ida_name.set_name(ea, col_name, ida_name.SN_NOWARN)

                    # Look for references to this Complete Object Locator (points to vtable slot -1)
                    for xref in idautils.XrefsTo(ea):
                        vtable_slot_minus1 = xref.frm
                        vtable_start = vtable_slot_minus1 + 0x08
                        vt_name = f"vftable_{class_name}"
                        ida_name.set_name(vtable_start, vt_name, ida_name.SN_NOWARN)
                        print(f"[+] Labeled Vtable at 0x{vtable_start:X} for {class_name}")

        ea += 0x04

# Run in IDA Pro
image_base = ida_nalt.get_image_base()
parse_msvc_rtti(image_base)
```

---

## 5.1 Recovering An Unknown Struct
Do not invent field types. Collect every access to the same pointer from the function, its callers, and its callees.

- A displacement names an offset and a width (`byte`, `dword`, `qword`).
- `malloc(N)`, `alloca(N)`, or a stack slot of size `N` is a size observation, not a guess.
- A field passed to `strlen` or printed as `%s` is a string pointer. A field that is called is a function pointer. A field used with `++` is a counter. Offset 0 holding a table of code pointers is a vtable. `next` and `prev` at stable offsets are a list node.
- The struct size is the highest offset plus that field's width, rounded up only when a later access or allocation proves the padding.
- Mark every field `proposed` until the access is in the disassembly. One function's decompiler view is not enough when a caller writes an offset the callee never reads.

## 6. Boundaries & Anti-Patterns
- **Do not mix calling conventions between MSVC and System V**: In MSVC x64, `RDI` and `RSI` are non-volatile registers preserved by the callee; in System V AMD64, `RDI` and `RSI` are volatile parameter registers. Treating `RDI` as an argument register on Windows leads to flawed function signatures.
- **Do not assume vtable slot 0 is the start of the object allocation**: When multiple inheritance is involved, secondary vtables occur at non-zero offsets within the object layout. Always check the Complete Object Locator's `offset` field or Itanium's `offset_to_top` to locate the true base address.
- **Do not read `std::string` buffers without checking capacity**: Slicing the first 8 bytes of a `std::string` as a pointer will cause memory dereference errors if small string optimization is active (`capacity < 16`). Always check `_Myres` / capacity field first.
- **Beware of virtual base classes (Diamond Inheritance)**: MSVC uses virtual base tables (`vbtable`) with displacement offsets stored at `[this + offset]`, while Itanium incorporates negative virtual base offsets into the primary vtable. Never treat virtual base pointers as simple virtual method pointers.
