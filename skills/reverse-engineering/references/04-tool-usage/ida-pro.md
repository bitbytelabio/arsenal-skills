# IDA Pro Reverse Engineering Guide — OMP Native Integration & Official Hex-Rays Workflows

- **Domain**: IDA Pro 9.x headless automation, OMP Native IDA device (`xd://ida`), official Hex-Rays Model Context Protocol server (`HexRaysSA/ida-mcp`), modern IDAPython APIs (`ida_*`), and cross-platform remote debugging orchestration (`dbgsrv/`).
- **Scope**: Dual integration modes (OMP native `xd://ida` with instant `read` views vs official Hex-Rays `ida-mcp` stdio daemon), 7 concrete reverse engineering workflows (auto-analysis, xrefs/string tracing, Hex-Rays decompilation, type recovery/structs, C++ vtable/hierarchy recovery, binary patching, and containerized remote debugging), 4 complete IDAPython automation scripts, and operational best practices.

---

## 1. Overview & Architecture

Modern automated reverse engineering with IDA Pro avoids interactive graphical bottlenecks and fragile wrapper tools. The ecosystem centers around two primary integration models: **OMP Native IDA Integration** (`xd://ida`) and the **Official Hex-Rays `ida-mcp` Server** (`HexRaysSA/ida-mcp`).

```
+---------------------------------------------------------------------------------------------------+
|                               IDA Pro Autonomous Integration Matrix                               |
+------------------------------+----------------------------------+---------------------------------+
| Dimension                    | OMP Native IDA (`xd://ida`)      | Official Hex-Rays `ida-mcp`     |
+------------------------------+----------------------------------+---------------------------------+
| Implementation / Upstream    | Harness Native Daemon Supervisor | `HexRaysSA/ida-mcp` (Official)  |
| Runtime Engine               | Headless IDA DB daemon           | `idalib` Python 3.11+ bindings  |
| Transport Channel            | Direct OMP internal IPC          | JSON-RPC over stdio / HTTP      |
| Storage & Concurrency        | `~/.omp/agent/idbs/<sha16>-<name>`| Local `.i64` companion files    |
| Multi-Agent Collaboration    | Shared DB access, lock-free      | Single-process exclusive lock   |
| Disassembly / Pseudocode View| Instant `read` selectors         | JSON-RPC tool call responses    |
| Database Mutation Method     | `write xd://ida` structured JSON | MCP Tool calling protocol       |
+------------------------------+------------------------------+-------------------------------------+
```

### 1.1 OMP Native IDA Integration (`xd://ida`)
OMP runs persistent headless IDA database daemons named `omp.ida.<id>` that isolate database operations from direct client process lifetimes.

- **Storage Location**: Databases are maintained in `~/.omp/agent/idbs/<sha16>-<name>/`, where `<sha16>` is the hex hash of the original binary content and `<name>` is the sanitized binary basename.
- **Lock-Free Multi-Agent Concurrency**: Multiple subagents and parallel analysis threads can read disassembly, pseudocode, and cross-references concurrently against the active daemon without database collision or lock contention errors (`.idb`/`.i64` lock files are handled entirely inside the background daemon).
- **Autosave Engine**: Daemons automatically flush dirty database pages to disk after ~10 seconds of idle time and immediately upon an explicit save action.
- **Zero-Latency `read` Selectors**: Code and metadata can be inspected instantly without calling tool roundtrips:
  - `read bin:main`: Retrieve Hex-Rays decompiled C pseudocode for symbol `main`.
  - `read bin:sub_401000:asm`: Disassemble instructions starting at address `0x401000`.
  - `read bin:imports`: Retrieve dynamic import tables (symbols, libraries, ordinals).
  - `read bin:exports`: Retrieve exported functions and addresses.
  - `read bin:strings`: Enumerate detected ASCII, UTF-8, and UTF-16 string literals.
  - `read bin:xrefs:sub_401000`: Enumerate all inbound and outbound cross-references for target symbol or address.
- **Structured Database Mutations (`write xd://ida`)**: Apply modifications to the persistent database using structured JSON commands:
  ```json
  // Rename a function or label
  {"action": "rename", "address": "0x401050", "name": "decrypt_payload"}

  // Set regular or repeatable comments
  {"action": "comment", "address": "0x401082", "comment": "AES-256-CBC S-box initialization", "repeatable": true}

  // Set function prototype declaration
  {"action": "set_type", "address": "0x401050", "decl": "int __fastcall decrypt_payload(const uint8_t *src, size_t len, uint8_t *dst)"}

  // Define a new function boundary
  {"action": "make_function", "address": "0x402100"}

  // Execute arbitrary headless IDAPython code snippet
  {"action": "exec", "code": "import ida_bytes; print(hex(ida_bytes.get_dword(0x401000)))"}

  // Persist changes to disk and flush dirty cache
  {"action": "save"}

  // Safely close database and terminate daemon worker
  {"action": "close", "save": true}
  ```

### 1.2 Official Hex-Rays `ida-mcp` Server (`HexRaysSA/ida-mcp`)
The official Hex-Rays MCP server is built directly on top of modern `idalib` Python bindings, providing full programmatic parity with the IDA Pro 9.x core engine.

- **Core Prerequisites**:
  - IDA Pro 9.4+ installed with a valid `idalib` license.
  - Python 3.11+ virtual environment with `idalib` installed.
- **Environment Configuration**:
  ```bash
  export IDADIR="/Applications/IDA Pro 9.4/idabin"
  export IDAPYTHON_VENV_EXECUTABLE="$(pwd)/.venv/bin/python"
  export IDA_NEXUS_IDALIB_ONLY=1
  ```
- **Execution Transport**:
  ```bash
  # Launch stdio transport for agent MCP routing
  ida-mcp stdio --agent=omp-re --idle-timeout=900 /path/to/binary_or_idb

  # Launch streamable HTTP transport for remote access
  ida-mcp http --host 127.0.0.1 --port 8737 /path/to/target.i64
  ```

---

## 2. Concrete Reverse Engineering Workflows in IDA Pro

### Workflow 1: Headless Database Initialization & Auto-Analysis
When analyzing a new binary, IDA Pro generates a new `.i64` database and starts asynchronous auto-analysis passes (compiler FLIRT signatures, type propagation, jump table resolution, function boundary discovery).

1. **Open Binary & Wait for Analysis**:
   In headless or daemon mode, never query functions before auto-analysis settles. In IDAPython:
   ```python
   import ida_auto
   import ida_ida

   # Block until all analysis passes (flirt, stack, type, tail) complete
   ida_auto.auto_wait()
   print(f"[+] Auto-analysis complete. Image Base: {hex(ida_ida.inf_get_min_ea())}")
   ```
2. **Locate Compiler Entry Points**:
   Enumerate entrypoints to identify runtime initialization wrappers vs user entry functions:
   ```python
   import ida_entry
   import ida_funcs
   import ida_name

   entry_count = ida_entry.get_entry_qty()
   for idx in range(entry_count):
       ord_val = ida_entry.get_entry_ordinal(idx)
       ea = ida_entry.get_entry(ord_val)
       name = ida_entry.get_entry_name(ord_val)
       print(f"Entry {idx}: {name} at {hex(ea)}")
   ```
   On ELF x86_64, `_start` sets up arguments and calls `__libc_start_main(main, argc, argv, ...)`. The first argument (placed in `rdi` on System V AMD64) is the real application `main`.
   On Windows PE, look for `WinMain`, `wWinMain`, or parse the CRT initialization routine (`__tmainCRTStartup`).

### Workflow 2: Cross-Reference & String Tracing
Critical malware components (C2 URLs, decryption keys, API tokens, configuration blocks) are anchored by string literals and global constants.

1. **Querying Detected Strings**:
   Using OMP native view:
   ```bash
   read bin:strings
   ```
   Using IDAPython to search for regex or key terms:
   ```python
   import idautils
   import ida_bytes
   import re

   pattern = re.compile(r"c2|token|key|https?://", re.IGNORECASE)
   str_list = idautils.Strings()
   for s in str_list:
       text = str(s)
       if pattern.search(text):
           print(f"Found match: '{text}' at {hex(s.ea)}")
   ```
2. **Enumerating Inbound References (`xrefs_to`)**:
   Trace which functions reference a specific string or global data buffer:
   ```python
   import ida_xref
   import ida_funcs

   def trace_string_xrefs(target_ea):
       xref = ida_xref.get_first_dref_to(target_ea)
       while xref != ida_ida.BADADDR:
           func = ida_funcs.get_func(xref)
           func_name = ida_funcs.get_func_name(xref) if func else "GLOBAL"
           print(f"  Referenced from {hex(xref)} in {func_name}")
           xref = ida_xref.get_next_dref_to(target_ea, xref)
   ```
3. **Tracing Call Paths to Network/Crypto Sinks**:
   Trace callers backwards from imported crypto/socket APIs (`WSAStartup`, `connect`, `CryptDecrypt`, `AES_cbc_encrypt`) to identify dispatcher logic and payload handlers.

### Workflow 3: Hex-Rays Decompilation & Control Flow Recovery
Hex-Rays generates high-level C ASTs (`cfunc_t`) that can be analyzed and annotated directly.

1. **Decompiling Functions**:
   Using OMP view:
   ```bash
   read bin:sub_401050
   ```
   Using IDAPython:
   ```python
   import ida_hexrays

   if ida_hexrays.init_hexrays_plugin():
       cfunc = ida_hexrays.decompile(0x401050)
       if cfunc:
           print(str(cfunc))
   ```
2. **Renaming Variables and Functions**:
   Replace auto-generated symbols (`sub_401050`, `v14`, `a1`) with descriptive names:
   ```python
   import ida_name

   # Rename function
   ida_name.set_name(0x401050, "parse_c2_command", ida_name.SN_CHECK)
   ```
   Via OMP native mutation:
   ```json
   {"action": "rename", "address": "0x401050", "name": "parse_c2_command"}
   ```
3. **Setting Regular and Repeatable Comments**:
   Add inline documentation for future analysis:
   ```python
   import ida_bytes

   # Regular comment (visible at this exact address)
   ida_bytes.set_cmt(0x401080, "Command 0x05 = Download & Execute payload", False)

   # Repeatable comment (visible across all xref callsites)
   ida_bytes.set_cmt(0x401050, "C2 packet handler dispatcher", True)
   ```
   Via OMP native mutation:
   ```json
   {"action": "comment", "address": "0x401050", "comment": "C2 packet handler dispatcher", "repeatable": true}
   ```

### Workflow 4: Type Recovery & Struct Reconstruction
Applying formal C prototypes and structure layouts simplifies complex memory pointer arithmetic into clean member dereferences (e.g., transforming `*(DWORD*)(rbx + 0x24)` into `session->socket_handle`).

1. **Applying C Function Prototypes (`Y` key)**:
   In GUI mode, the analyst highlights a function and presses `Y`. In automated mode:
   ```python
   import ida_typeinf

   decl = "int __fastcall parse_c2_packet(const uint8_t *buffer, size_t length, connection_state_t *state);"
   tif = ida_typeinf.tinfo_t()
   til = ida_typeinf.get_idati()

   # Parse C declaration
   res = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
   if res:
       ida_typeinf.apply_tinfo(0x401050, tif, ida_typeinf.TINFO_DEFINITE)
       print("[+] Prototype successfully applied.")
   ```
   Via OMP native mutation:
   ```json
   {
     "action": "set_type",
     "address": "0x401050",
     "decl": "int __fastcall parse_c2_packet(const uint8_t *buffer, size_t length, void *state)"
   }
   ```
2. **Applying Struct Offsets to Pointers / Registers (`T` key)**:
   When decompilation shows raw offsets (`*(a1 + 32)`), apply the reconstructed struct type to the variable:
   ```python
   # Apply struct type info to a local variable or register operand
   tif = ida_typeinf.tinfo_t()
   til = ida_typeinf.get_idati()
   tif.get_named_type(til, "connection_state_t")
   # Apply to target variable or address
   ida_typeinf.apply_tinfo(var_ea, tif, ida_typeinf.TINFO_DEFINITE)
   ```

### Workflow 5: C++ Vtable & Class Hierarchy Recovery
Object-oriented C++ binaries implement runtime polymorphism using Virtual Method Tables (vtables). In decompiled output, unresolved virtual calls appear as opaque indirect calls: `call qword ptr [rax + 0x18]`.

1. **Locating Vtables in `.rdata` / `.rodata`**:
   Vtables consist of contiguous arrays of function pointers located in read-only data sections, preceded by RTTI (Run-Time Type Information) Complete Object Locators on MSVC or Typeinfo pointers on GCC/Clang.
2. **Reconstructing Virtual Method Layout**:
   Define a C structure representing the vtable:
   ```c
   struct ICommandDispatcher_vtable {
       void (__fastcall *QueryInterface)(void *this, const char *iid, void **ppv);
       uint32_t (__fastcall *AddRef)(void *this);
       uint32_t (__fastcall *Release)(void *this);
       int (__fastcall *ExecuteCommand)(void *this, uint32_t cmd_id, const uint8_t *data);
   };

   struct ICommandDispatcher {
       struct ICommandDispatcher_vtable *vptr;
       uint32_t session_id;
       char c2_host[64];
   };
   ```
3. **Resolving Virtual Call Sites**:
   Assign `ICommandDispatcher *` to the `this` pointer register (`rcx` on Windows x64, `rdi` on Linux AMD64). Hex-Rays will resolve `call [rax + 0x18]` to `dispatcher->vptr->ExecuteCommand(dispatcher, cmd_id, data)`.

### Workflow 6: Binary Patching
Automated reversing often requires neutralizing anti-debugging routines, integrity checks, or certificate validation functions.

1. **Bypassing Conditional Checks**:
   Change conditional jumps (`jz` `0x74`, `jnz` `0x75`) to unconditional jumps (`jmp` `0xEB` or `0xE9`) or `nop` instructions (`0x90`).
   ```python
   import ida_bytes

   patch_ea = 0x4015A0

   # Replace 2-byte conditional jump (74 12 -> 90 90) with NOPs
   ida_bytes.patch_bytes(patch_ea, b"\x90\x90")

   # Or force an unconditional jump
   ida_bytes.patch_byte(patch_ea, 0xEB)
   print(f"[+] Patched instruction at {hex(patch_ea)}")
   ```
2. **Applying Patches to Binary File**:
   In IDAPython, `patch_byte` modifies the `.idb` memory database. To commit patches to the original executable on disk:
   ```python
   import ida_segment

   # Commit IDB patches to the underlying physical file
   # Note: Must ensure file write permissions exist
   ida_bytes.save_file(open("/path/to/patched_binary", "wb"), 0)
   ```

### Workflow 7: Remote Debugging Architecture (`dbgsrv/`)
To inspect live register states, unpack obfuscated binaries, or bypass complex anti-debug logic without executing untrusted code on the host, deploy IDA's native remote debug servers inside an isolated environment.

```
+------------------------------------+                         +-----------------------------------+
| Host Analysis Machine              |                         | Isolated Sandbox / UTM Guest / VM |
|                                    |                         |                                   |
|   +----------------------------+   |   TCP :23946 (IDA IPC)  |   +---------------------------+   |
|   | IDA Pro 9.x                |---|------------------------>|   | linux_server64 / win64_...|   |
|   | (OMP Daemon / GUI Engine)  |   |                         |   | (Listening 0.0.0.0:23946) |   |
|   +----------------------------+   |                         |   +-------------+-------------+   |
|                                    |                         |                 | ptrace / DbgUi  |
|                                    |                         |   +-------------v-------------+   |
|                                    |                         |   | Target Process / Malware  |   |
+------------------------------------+                         |   +---------------------------+   |
                                                               +-----------------------------------+
```

1. **Server Binary Matrix** (Bundled in `$IDADIR/dbgsrv/`):
   - `linux_server64`: 64-bit Linux ELF targets.
   - `win64_remote.exe`: 64-bit Windows PE targets.
   - `android_server64`: 64-bit Android AArch64 native processes.
   - `armlinux_server64`: 64-bit Linux AArch64 embedded targets.
2. **Deploying Inside Docker (Linux Target)**:
   ```bash
   docker run --rm -d \
     --name ida_dbg_container \
     --cap-add=SYS_PTRACE \
     --security-opt seccomp=unconfined \
     -p 23946:23946 \
     -v "$(pwd)/samples":/samples \
     ubuntu:24.04 \
     /samples/dbgsrv/linux_server64 -p23946
   ```
3. **Connecting Host IDA**:
   In IDA Pro: Select `Debugger` -> `Switch Debugger` -> `Remote Linux / Windows Debugger`. Set Host to `127.0.0.1` and Port to `23946`. Set software/hardware breakpoints, trigger target process execution, and inspect dynamic memory pages.

---

## 3. Modern IDAPython Automation Scripting

All modern IDAPython automation must use the official `ida_*` and `idautils` modules. Legacy `idc` functions (`idc.MakeCode`, `idc.MakeName`, `idc.SetType`) are deprecated.

### Script 1: Batch Function Complexity Analysis & Triage
Analyzes instruction volume, basic block counts, and inbound references to prioritize critical application logic over boilerplate CRT routines.

```python
import ida_funcs
import ida_gdl
import idautils

def analyze_complexity():
    print("[*] Starting Batch Function Complexity Triage...")
    triage_results = []

    for ea in idautils.Functions():
        pfn = ida_funcs.get_func(ea)
        if not pfn:
            continue

        name = ida_funcs.get_func_name(ea)
        # Skip library or compiler-generated thunks
        if pfn.flags & ida_funcs.FUNC_LIB or pfn.flags & ida_funcs.FUNC_THUNK:
            continue

        # Count total instructions
        insn_count = len(list(idautils.FuncItems(ea)))

        # Build FlowChart for Basic Block metrics
        fc = ida_gdl.FlowChart(pfn)
        bb_count = fc.size

        # Inbound call cross references
        xrefs_in = len(list(idautils.CodeRefsTo(ea, 0)))

        # Complexity score: weighted metric
        score = (insn_count * 0.4) + (bb_count * 2.0) + (xrefs_in * 1.5)
        triage_results.append((name, ea, insn_count, bb_count, xrefs_in, score))

    # Sort descending by complexity score
    triage_results.sort(key=lambda x: x[5], reverse=True)

    print(f"{'Function Name':<30} {'Address':<12} {'Insns':<8} {'Blocks':<8} {'Xrefs':<8} {'Score':<8}")
    print("-" * 78)
    for name, ea, insns, bbs, xrefs, score in triage_results[:15]:
        print(f"{name:<30} {hex(ea):<12} {insns:<8} {bbs:<8} {xrefs:<8} {score:<8.1f}")

if __name__ == "__main__":
    analyze_complexity()
```

### Script 2: Automated String Decryptor Tracing & Labeling
Scans for tight XOR decoding loops, extracts ciphered string buffers, emulates decryption, and applies repeatable comments.

```python
import ida_bytes
import ida_name
import ida_xref
import idautils

def locate_and_label_xor_strings(decryptor_func_ea, xor_key):
    """
    Finds all callers of a string decryptor routine:
    void decrypt(uint8_t *enc_buf, size_t len);
    """
    print(f"[*] Tracing references to decryptor at {hex(decryptor_func_ea)}")
    xrefs = idautils.CodeRefsTo(decryptor_func_ea, 0)

    for caller_ea in xrefs:
        # Search backwards for argument assignments (e.g. lea rdi, [enc_str])
        curr_ea = caller_ea
        buffer_ea = None

        for _ in range(8):
            curr_ea = ida_bytes.prev_head(curr_ea, 0)
            # Find data references originating from this setup instruction
            drefs = list(idautils.DataRefsFrom(curr_ea))
            if drefs:
                buffer_ea = drefs[0]
                break

        if buffer_ea:
            # Read encrypted bytes
            raw_len = ida_bytes.get_byte(buffer_ea)  # Assume length prefix
            enc_data = ida_bytes.get_bytes(buffer_ea + 1, raw_len)
            if enc_data:
                decrypted = bytes([b ^ xor_key for b in enc_data]).decode('latin-1', errors='ignore')
                print(f"[+] Decrypted string at {hex(buffer_ea)}: '{decrypted}'")
                
                # Label data buffer and set repeatable comment at callsite
                ida_name.set_name(buffer_ea, f"dec_str_{hex(buffer_ea)[2:]}", ida_name.SN_CHECK)
                ida_bytes.set_cmt(caller_ea, f"Decrypted: \"{decrypted}\"", True)

if __name__ == "__main__":
    # Example decryptor function address and key
    # locate_and_label_xor_strings(0x402500, 0x5A)
    pass
```

### Script 3: AST Traversal Using Hex-Rays Decompiler API (`ctree_visitor_t`)
Traverses decompiled C abstract syntax trees to locate dangerous function calls (such as `system`, `execve`, or custom memory allocators) and verify their argument patterns.

```python
import ida_hexrays
import ida_funcs

class SecurityAuditVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.findings = []

    def visit_expr(self, e):
        # Check if the expression is a function call
        if e.op == ida_hexrays.cot_call:
            target_name = "indirect"
            if e.x.op == ida_hexrays.cot_obj:
                target_name = ida_funcs.get_func_name(e.x.obj_ea)

            # Detect format string or shell execution sinks
            if target_name in ["system", "popen", "sprintf", "strcpy"]:
                arg_count = len(e.a) if hasattr(e, 'a') else 0
                self.findings.append((e.ea, target_name, arg_count))

        return 0  # 0 to continue traversal

def audit_function_ast(func_ea):
    if not ida_hexrays.init_hexrays_plugin():
        print("[-] Hex-Rays decompiler is not available")
        return

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return

    visitor = SecurityAuditVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)

    if visitor.findings:
        print(f"[!] Vulnerable/Critical sinks in {ida_funcs.get_func_name(func_ea)} ({hex(func_ea)}):")
        for call_ea, sink, args in visitor.findings:
            print(f"    {hex(call_ea)}: {sink}(...) with {args} arguments")

if __name__ == "__main__":
    # audit_function_ast(0x401000)
    pass
```

### Script 4: Struct Creation and Member Layout Definition
Programmatically creates C structures, adds typed fields with specific displacements, and registers them in the IDA database type library.

```python
import ida_typeinf

def create_network_message_struct():
    til = ida_typeinf.get_idati()
    struct_name = "cmd_packet_t"

    c_decl = """
    struct cmd_packet_t {
        uint32_t magic_header;
        uint16_t command_id;
        uint16_t flags;
        uint32_t payload_size;
        uint8_t  payload_data[512];
        uint32_t crc32_checksum;
    };
    """

    tif = ida_typeinf.tinfo_t()
    res = ida_typeinf.parse_decl(tif, til, c_decl, ida_typeinf.PT_TYP)
    if not res:
        print(f"[-] Failed to parse C declaration for {struct_name}")
        return False

    # Save type into type library
    res = tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)
    if res:
        print(f"[+] Struct '{struct_name}' successfully defined in local type library.")
        return True
    else:
        print(f"[-] Failed to register struct '{struct_name}' in til.")
        return False

if __name__ == "__main__":
    create_network_message_struct()
```

---

## 4. Operational Best Practices & Troubleshooting

1. **Handling Large Binaries (>50MB)**:
   - *Problem*: Auto-analysis on massive binaries causes high CPU/RAM utilization and execution timeouts.
   - *Solution*: Set analysis limits before opening. In batch scripts, disable background flix or demangler if memory-constrained:
     ```python
     import ida_auto
     # Set auto-analysis queue flags to selective mode
     ida_auto.set_ida_state(ida_auto.st_Work)
     ```
   - Limit string searches to specific sections (`.rodata`, `.rdata`) instead of traversing entire memory mappings.
2. **Session & Database Management**:
   - In both OMP native daemons and `ida-mcp`, ensure changes are explicitly persisted and databases are closed when done:
     ```json
     {"action": "close", "save": true}
     ```
   - Releasing databases frees file locks and system RAM, preventing corrupted `.i64` states.
3. **Headless Execution Rules & Anti-Patterns**:
   - **Never invoke blocking UI dialogs**: Functions such as `ida_kernwin.ask_str`, `ask_file`, or `ask_yn` will cause headless workers to hang indefinitely awaiting interactive GUI input.
   - **Never conflate raw physical offsets with Virtual Addresses (EA)**: Ensure all address parameters passed to `set_type`, `rename`, or `comment` are mapped Virtual Addresses (`ea = image_base + section_offset`).
   - **Always verify decompiler availability before AST traversal**: Call `ida_hexrays.init_hexrays_plugin()` prior to calling `ida_hexrays.decompile()` to prevent unhandled segmentation crashes.
