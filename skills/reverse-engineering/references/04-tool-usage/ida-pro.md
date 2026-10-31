# IDA Pro 9.x: `ida-mcp`, Headless Batch, idalib, ida-domain, Hex-Rays APIs

- **Domain**: IDA Pro 9.x driven by agents through the official Hex-Rays MCP server (`HexRaysSA/ida-mcp`), headless `idat` batch runs, `idalib` (`import idapro`), and the `ida-domain` API.
- **Scope**: tool surface and timeouts, headless pipelines, scripted analysis (strings, xrefs, imports, decompilation, ctree and microcode), types and structs, renaming and comments at scale, patch export, signatures and type libraries, pitfalls.
- **Verified**: every IDAPython snippet below ran headless on IDA Professional 9.4 (macOS arm64) against a small test Mach-O. `ida-domain` 0.5.1 and `idapro` 0.0.11 were checked in the IDA venv. API names that moved in 9.x are called out in section 10.

---

## 1. Choose the entry point

| Need | Use | Why |
|---|---|---|
| Agent works interactively on one or more databases | `ida-mcp` (`open_database` + `execute_python`) | Persistent globals, shared with the IDA GUI, leases per agent |
| Run one script over many binaries | `idat -A -S"script.py" -L log` | No server, exit code from `ida_pro.qexit(n)` |
| Python program owns the loop (CI, diffing, corpus) | `idalib` (`import idapro`) | IDA as a library inside your own interpreter |
| Readable high-level API | `ida-domain` (`Database.open`) | Pythonic wrappers; same object is `db` inside `execute_python` |
| Live debugging | [ida-mcp-remote-debugging.md](ida-mcp-remote-debugging.md) | `ida-mcp` has no debugger tool |

Static first. Open the database, recover names, types, and call paths, then debug only what static analysis cannot settle.

---

## 2. Official `ida-mcp` server

The server is built on IDA Nexus (`ida-nexus`) and `ida-domain`. It runs headless idalib workers or attaches to a database open in the IDA GUI. Requirements: IDA 9.4+, idalib, Python 3.11+, `uv`. Disable other IDA MCP servers so the agent does not mix tool sets.

```bash
uvx ida-hcli mcp install                       # installs the GUI plugin and offers agent plugins
claude plugin marketplace add HexRaysSA/claude-marketplace
claude plugin install ida-mcp@HexRaysSA
```

Generic stdio registration and the HTTP transport:

```bash
uvx ida-mcp stdio --agent=re-agent                         # label shows in the dashboard
uvx ida-mcp stdio --agent=re-agent --database /abs/target  # open and activate at startup
uvx ida-mcp http --host 127.0.0.1 --port 8737 --path-prefix ""   # Streamable HTTP at /mcp
uvx ida-mcp dashboard --open                               # inspect session logs
uvx ida-mcp logs                                           # export logs for troubleshooting
```

| Flag / variable | Effect |
|---|---|
| `--database PATH` | Open an executable or IDB at startup and make it current |
| `--agent NAME` | Agent label in the session trace |
| `--idle-timeout SECONDS` / `IDA_MCP_IDLE_TIMEOUT` | Release idle idalib leases. Default: no timeout. `0` disables |
| `IDA_NEXUS_IDALIB_ONLY=1` | Keep workers in the server's Python env. Skips `idat` workers and IDA-installed plugins/packages |

### 2.1 Tools (six; no debugger tool)

| Tool | Parameters | Notes |
|---|---|---|
| `open_database` | `path`, `set_current=True`, `load_options={processor, file_type, image_base, entry_point}`, `gui=False` | Open timeout 300 s. `load_options` apply only when a new worker spawns. Use `gui=true` only when the user asks for the GUI |
| `execute_python` | `code`, `instance_id=None`, `timeout=360` | `db` (ida-domain `Database`) and `ida_domain` are global. Imports, variables, and functions persist for the agent's lease. A trailing expression is returned. A defined `run(db)`, `execute(db)`, or `main(db)` runs automatically when there is no trailing expression. The timeout excludes the initial auto-analysis wait |
| `reference` | `query` | Searches the installed ida-domain API reference. Same data as `ida-nexus reference "<query>"` |
| `list_databases` | none | Open GUI and headless databases with instance ids |
| `save_database` | `instance_id=None` | Writes the `.i64` |
| `close_database` | `instance_id=None` | Releases this session's lease. Final lease on a worker cancels orphaned Python and waits for shutdown. GUI databases stay open |

### 2.2 Working rules

- Call `reference(query)` before guessing an ida-domain method. The ida-domain API changes between releases (`get_function_by_name` is deprecated in 0.5.x; use `get_by_name`).
- Keep each `execute_python` call bounded. Iterate in chunks (for example 200 functions per call) and stash progress in a global.
- Write bulk output to files and return only a summary. Pseudocode for a whole binary does not fit in context.
- Save after every batch of renames or types. A worker crash loses unsaved changes.
- One writer per `.i64`. Do not open the same database with `idat`, idalib, and `ida-mcp` at once.

```python
# execute_python call 1: define helpers once; they persist for the lease
import os, ida_hexrays, ida_funcs, idautils
OUT = "/abs/work/pseudo"
os.makedirs(OUT, exist_ok=True)
DONE = set()

def export_batch(n=200):
    count = 0
    for ea in idautils.Functions():
        if ea in DONE:
            continue
        DONE.add(ea)
        f = ida_funcs.get_func(ea)
        if f.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
            continue
        cf = ida_hexrays.decompile(ea)
        if cf is not None:
            open(f"{OUT}/{ea:x}_{ida_funcs.get_func_name(ea)}.c", "w").write(str(cf))
        count += 1
        if count >= n:
            break
    return len(DONE)
```

```python
# execute_python call 2..N: returns the trailing expression
export_batch(200)
```

---

## 3. Headless batch with `idat`

`idat` lives in the app bundle. Set it once:

```bash
IDA="/Applications/IDA Professional 9.4.app/Contents/MacOS"   # Linux: ~/ida-pro-9.4 ; Windows: C:\Program Files\IDA Professional 9.4
"$IDA/idat" -A -S"/abs/script.py arg1 arg2" -L/abs/run.log /abs/target
echo $?                                    # exit code passed to ida_pro.qexit(n)
```

| Switch | Meaning |
|---|---|
| `-A` | Autonomous: no dialogs. Always use with `-S` |
| `-S"script.py args"` | Run script after the database opens. Args land in `idc.ARGV` (`ARGV[0]` is the script path) |
| `-L<file>` | Log file (no space after `-L`) |
| `-c` | Delete any old database and disassemble anew |
| `-o<file>` | Output database path (implies `-c`) |
| `-B` | Batch: analyze, write `.i64` and `.asm`, exit. No script needed |
| `-a` / `-a-` | Disable / enable auto-analysis |
| `-p<proc>` | Processor module (`-parm`, `-pmetapc`) |
| `-T<type>` | Force loader by file-type prefix; `-TZIP:classes.dex` selects an archive member |
| `-b<hex>` | Load address in paragraphs (16-byte units) |
| `-P+` / `-P-` | Compressed / unpacked database |
| `-d<directive>` / `-D<directive>` | Config directive for first / second pass |

Script skeleton. `auto_wait()` is mandatory before reading functions. `qexit` is mandatory or `idat` waits forever.

```python
import json, os
import ida_auto, ida_ida, ida_nalt, ida_pro, idc

ida_auto.auto_wait()
info = {
    "proc": ida_ida.inf_get_procname(),
    "is_64bit": ida_ida.inf_is_64bit(),
    "min_ea": hex(ida_ida.inf_get_min_ea()),
    "imagebase": hex(ida_nalt.get_imagebase()),
    "input": ida_nalt.get_input_file_path(),
    "argv": idc.ARGV,
}
out = idc.ARGV[1] if len(idc.ARGV) > 1 else "/tmp/info.json"
json.dump(info, open(out, "w"), indent=2)
ida_pro.qexit(0)
```

Batch over a corpus. One database per input; logs per input:

```bash
for f in /abs/corpus/*; do
  "$IDA/idat" -A -c -o"/abs/dbs/$(basename "$f").i64" -S"/abs/triage.py /abs/out/$(basename "$f").json" -L"/abs/logs/$(basename "$f").log" "$f"
done
```

---

## 4. idalib and ida-domain

### 4.1 idalib (`import idapro`)

Install once per Python environment, then import `idapro` before any `ida_*` module.

```bash
pip install "$IDA"/idalib/python/idapro-*.whl
python "$IDA/idalib/python/py-activate-idalib.py" -d "$IDA"
```

```python
import sys
import idapro                                   # must be the first IDA import
rc = idapro.open_database(sys.argv[1], run_auto_analysis=True)   # 0 on success
assert rc == 0, rc
import ida_auto, ida_funcs, idautils, ida_hexrays
ida_auto.auto_wait()
print([ida_funcs.get_func_name(ea) for ea in idautils.Functions()])
idapro.close_database(save=False)               # default is save=True
```

`idapro.open_database(file_name, run_auto_analysis, args=None, enable_history=False)` accepts `idat`-style switches in `args` (for example `"-parm -b100"`).

### 4.2 ida-domain

`pip install ida-domain` (it uses the activated idalib). Inside `execute_python` the opened database is already `db`.

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

opts = IdaCommandOptions(auto_analysis=True, new_database=True)
with Database.open("/abs/target", opts, save_on_close=False) as db:
    print(db.architecture, db.bitness, hex(db.base_address), db.format)
    main = db.functions.get_by_name("_main")
    print("\n".join(db.functions.get_pseudocode(main).to_text()))
    print([db.functions.get_name(c) for c in db.functions.get_callees(main)])
    for s in db.strings:
        print(hex(s.address), str(s))
    for c in db.xrefs.get_callers(db.functions.get_by_name("_system").start_ea):
        print(hex(c.ea))
```

Other entry points worth knowing: `db.xrefs.to_ea/from_ea/calls_to_ea/reads_of_ea/writes_to_ea`, `db.names.set_name`, `db.comments.set_at`, `db.types.parse_declarations/apply_declaration_at/get_by_name`, `db.functions.get_microcode`, and `PseudocodeFunction.find_calls(target_name=...)`.

---

## 5. Recon snippets (IDAPython)

### 5.1 Entries, imports, strings, xrefs

```python
import re
import ida_entry, ida_nalt, ida_funcs, idautils

for i in range(ida_entry.get_entry_qty()):
    o = ida_entry.get_entry_ordinal(i)
    print("entry", ida_entry.get_entry_name(o), hex(ida_entry.get_entry(o)))

for i in range(ida_nalt.get_import_module_qty()):
    mod = ida_nalt.get_import_module_name(i)
    def cb(ea, name, ordinal, mod=mod):
        print("import", mod, name or f"#{ordinal}", hex(ea))
        return True                               # keep enumerating
    ida_nalt.enum_import_names(i, cb)

pat = re.compile(r"token|key|https?://", re.I)
for s in idautils.Strings():
    text = str(s)
    if pat.search(text):
        print(hex(s.ea), repr(text))
        for x in idautils.XrefsTo(s.ea):
            print("   from", hex(x.frm), ida_funcs.get_func_name(x.frm), idautils.XrefTypeName(x.type))
```

`XrefsTo` also reports references from load commands and headers; `get_func_name` returns `None` there. Filter on it.

### 5.2 Callers of a sink, transitively

```python
import ida_name, ida_funcs, idautils, idc

def callers(ea):
    return {ida_funcs.get_func(x).start_ea for x in idautils.CodeRefsTo(ea, 0) if ida_funcs.get_func(x)}

def paths_to(sink_name, depth=4):
    sink = ida_name.get_name_ea(idc.BADADDR, sink_name)
    frontier, seen = {sink}, {sink}
    for d in range(depth):
        nxt = set()
        for f in frontier:
            for c in callers(f) - seen:
                print("  " * d, ida_funcs.get_func_name(c), "->", ida_funcs.get_func_name(f))
                nxt.add(c)
        seen |= nxt
        frontier = nxt

paths_to("_system")      # Mach-O names carry a leading underscore; ELF/PE do not
```

On Mach-O and ELF, the import thunk (`_system` stub) is a function; callers point at the thunk. On PE, calls go through the IAT pointer: start from `idautils.DataRefsTo(iat_ea)`.

### 5.3 Triage ranking

```python
import ida_funcs, ida_gdl, idautils

rows = []
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    if f.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
        continue
    blocks = ida_gdl.FlowChart(f).size
    insns = sum(1 for _ in idautils.FuncItems(ea))
    callers = sum(1 for _ in idautils.CodeRefsTo(ea, 0))
    rows.append((insns * 0.4 + blocks * 2 + callers * 1.5, ida_funcs.get_func_name(ea), hex(ea), insns, blocks, callers))
for r in sorted(rows, reverse=True)[:20]:
    print("%7.1f %-32s %s insns=%d bbs=%d callers=%d" % r)
```

`FUNC_LIB` is set by FLIRT. Apply signatures first (section 8) so library code drops out of the ranking.

---

## 6. Hex-Rays decompiler

### 6.1 Decompile and export

```python
import ida_hexrays, ida_lines

assert ida_hexrays.init_hexrays_plugin(), "no decompiler for this processor/license"
hf = ida_hexrays.hexrays_failure_t()
cf = ida_hexrays.decompile(0x100000518, hf)
if cf is None:
    print("failed", hf.code, hf.str)          # 9.4 returns None on failure; it does not raise
else:
    print(str(cf))                             # clean C text
    lines = [ida_lines.tag_remove(l.line) for l in cf.get_pseudocode()]   # display lines
```

`get_pseudocode()` lines include argument-name annotations (`system(a1: ...)`). Use `str(cfunc)` for files. Export every function in batches (section 2.2) and grep the files instead of pulling pseudocode into context.

### 6.2 ctree visitor: find calls and their arguments

```python
import ida_hexrays, ida_name, ida_funcs, idautils

SINKS = {"_system", "_popen", "_strcpy", "_sprintf", "_memcpy"}

class CallFinder(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.hits = []
    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call and e.x.op == ida_hexrays.cot_obj:
            name = ida_name.get_name(e.x.obj_ea)
            if name in SINKS:
                self.hits.append((e.ea, name, [a.dstr() for a in e.a]))
        return 0                                   # continue traversal

for ea in idautils.Functions():
    cf = ida_hexrays.decompile(ea)
    if cf is None:
        continue
    v = CallFinder()
    v.apply_to(cf.body, None)
    for call_ea, name, args in v.hits:
        print(ida_funcs.get_func_name(ea), hex(call_ea), name, args)
```

`e.a` is the argument list (`carglist_t`); `a.dstr()` prints each argument as C. Use `CV_PARENTS` instead of `CV_FAST` when you need `self.parents` to walk up to the enclosing `if` or loop.

### 6.3 Microcode

Microcode is the decompiler IR. Use it when the ctree hides data flow (obfuscation, MBA, flattening) or to read call arguments after register allocation.

```python
import ida_hexrays, ida_funcs, ida_lines

pfn = ida_funcs.get_func(0x100000518)
hf = ida_hexrays.hexrays_failure_t()
mba = ida_hexrays.gen_microcode(ida_hexrays.mba_ranges_t(pfn), hf, None,
                                ida_hexrays.DECOMP_WARNINGS, ida_hexrays.MMAT_GLBOPT1)
vp = ida_hexrays.qstring_printer_t(None, True)
mba._print(vp)
print(ida_lines.tag_remove(vp.s))
for i in range(mba.qty):
    ins = mba.get_mblock(i).head
    while ins:
        if ins.opcode == ida_hexrays.m_call:
            print(hex(ins.ea), ins.dstr())
        ins = ins.next
```

Maturity levels run `MMAT_GENERATED` → `MMAT_PREOPTIMIZED` → `MMAT_LOCOPT` → `MMAT_CALLS` → `MMAT_GLBOPT1..3` → `MMAT_LVARS`. Early levels keep raw registers; `MMAT_LVARS` has local variables. Deobfuscation plugins (gooMBA ships with 9.x; d810-ng is third party) hook `optinsn_t`/`optblock_t` at these levels.

---

## 7. Types, names, comments

### 7.1 Declare types and apply prototypes

```python
import ida_typeinf, idc

# Several declarations at once into Local Types. Returns the error count.
errors = idc.parse_decls("""
struct conn { int fd; unsigned short port; char host[64]; int (*cb)(struct conn *, int); };
""", ida_typeinf.HTI_DCL)
assert errors == 0

# One prototype -> tinfo_t -> apply. parse_decl returns the declared name or None.
tif = ida_typeinf.tinfo_t()
name = ida_typeinf.parse_decl(tif, None, "int __fastcall handler(struct conn *c, int cmd);", ida_typeinf.PT_SIL)
ida_typeinf.apply_tinfo(0x100000518, tif, ida_typeinf.TINFO_DEFINITE)

# Shortcut for a single address
idc.SetType(0x100000550, "int __fastcall check_key(const char *key);")

# Read a struct layout back
t = ida_typeinf.tinfo_t()
t.get_named_type(None, "conn")
udt = ida_typeinf.udt_type_data_t()
t.get_udt_details(udt)
for m in udt:
    print(m.name, m.offset // 8, str(m.type))     # offsets are in bits
```

Applying `struct conn *` to the first argument turned `*(unsigned __int16 *)(a1 + 4)` into `conn->port` in the test. Prototype first, then struct members, then re-decompile.

Build a struct field by field (for generated layouts):

```python
import ida_typeinf

udt = ida_typeinf.udt_type_data_t()
for fname, ftype in (("magic", "uint32_t"), ("cmd", "uint16_t"), ("flags", "uint16_t")):
    m = ida_typeinf.udm_t()
    m.name = fname
    ft = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(ft, None, f"{ftype} x;", ida_typeinf.PT_SIL)
    m.type = ft
    udt.push_back(m)
st = ida_typeinf.tinfo_t()
st.create_udt(udt)
assert st.set_named_type(None, "pkt_hdr_t", ida_typeinf.NTF_REPLACE) == ida_typeinf.TERR_OK
```

### 7.2 Rename functions, locals, set local types

```python
import ida_name, ida_hexrays, ida_typeinf

ida_name.set_name(0x100000518, "dispatch_cmd", ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
ida_name.force_name(0x1000004f8, "xor_decrypt")          # appends a suffix on collision
ida_hexrays.rename_lvar(0x100000518, "a1", "conn")       # function ea, old, new

# Change a local/argument type
cf = ida_hexrays.decompile(0x100000518)
lv = next(l for l in cf.get_lvars() if l.name == "cmd")
lsi = ida_hexrays.lvar_saved_info_t()
lsi.ll = lv
lsi.type = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(lsi.type, None, "unsigned int x;", ida_typeinf.PT_SIL)
ida_hexrays.modify_user_lvar_info(0x100000518, ida_hexrays.MLI_TYPE, lsi)
```

Rename at scale from a mapping file. Log failures; `set_name` returns `False` on invalid or duplicate names.

```python
import json, ida_name
for ea_hex, new in json.load(open("/abs/work/names.json")).items():
    if not ida_name.set_name(int(ea_hex, 16), new, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
        print("rename failed", ea_hex, new)
```

### 7.3 Comments

```python
import ida_bytes, ida_funcs
ida_bytes.set_cmt(0x100000530, "cmd 5 -> system(host)", False)      # regular
ida_bytes.set_cmt(0x1000004f8, "XOR 0x5a string decoder", True)      # repeatable: shows at referencing sites
ida_funcs.set_func_cmt(ida_funcs.get_func(0x100000518), "Command dispatcher", True)   # shows atop pseudocode
```

---

## 8. Signatures, type libraries, Lumina

| Mechanism | Purpose | API |
|---|---|---|
| FLIRT `.sig` (`$IDA/sig/<proc>/`) | Mark statically linked library functions (`FUNC_LIB`) | `ida_funcs.plan_to_apply_idasgn("name")`, then `ida_auto.auto_wait()`; count with `ida_funcs.get_idasgn_qty()` |
| Type libraries `.til` (`$IDA/til/<proc>/`) | Prototypes and structs for an SDK | `ida_typeinf.add_til("gnulnx_arm64", ida_typeinf.ADDTIL_DEFAULT)` |
| Headers | Project-specific types | `idc.parse_decls(open(path).read(), ida_typeinf.HTI_DCL)` |
| Lumina | Hex-Rays server returns names/types by function hash | Pull only. Pushing sends function metadata off-host. Do not push client or malware samples |
| `idaclang` / `tilib` (SDK tools) | Build a `.til` from headers | Run once per SDK, reuse across databases |

Build your own FLIRT signatures from a matching library version (`pelf`/`plb` + `sigmake` from the Hex-Rays SDK utilities) when the target statically links an uncommon library.

---

## 9. Patching and exporting patched bytes

```python
import ida_bytes, ida_loader, ida_nalt, idc

ea = 0x1000004f8
print(ida_bytes.get_bytes(ea, 4).hex(), hex(ida_loader.get_fileregion_offset(ea)))
ida_bytes.patch_bytes(ea, bytes.fromhex("c0035fd6"))     # arm64 RET; x86 NOPs are b"\x90"

# Write a patched copy. Only apply ranges you patched: IDA's own loader fixups
# (Mach-O chained fixups, relocations) also show up in visit_patched_bytes.
MINE = [(ea, ea + 4)]
patches = []
def cb(p_ea, fpos, org, val):
    if fpos != -1 and any(a <= p_ea < b for a, b in MINE):
        patches.append((fpos, val))
    return 0
ida_bytes.visit_patched_bytes(0, idc.BADADDR, cb)
src = ida_nalt.get_input_file_path()
data = bytearray(open(src, "rb").read())
for fpos, val in patches:
    data[fpos] = val
open(src + ".patched", "wb").write(data)
```

Re-sign patched Mach-O binaries (`codesign -f -s - file`) before running them on macOS. Patching is a dynamic-analysis aid; record the original bytes in notes.

---

## 10. 9.x API changes and pitfalls

| Old / wrong | 9.x |
|---|---|
| `idaapi.get_inf_structure()` | Removed. Use `ida_ida.inf_get_procname()`, `inf_is_64bit()`, `inf_get_min_ea()`, `inf_get_max_ea()`, `ida_nalt.get_imagebase()` |
| `ida_struct`, `ida_enum` modules | Removed in 9.0. Use `ida_typeinf` (`udt_type_data_t`, `udm_t`, `tinfo_t.create_udt`) or `idc.parse_decls` |
| `idc.MakeName`, `MakeCode`, `GetFunctionName` | Gone. Use `ida_name.set_name`, `ida_ua.create_insn`, `ida_funcs.get_func_name` |
| `ida_bytes.save_file(...)` for patches | Not a patch export. Use `visit_patched_bytes` (section 9) |
| `ida_hexrays.decompile()` raising on failure | Returns `None` in 9.4. Pass `hexrays_failure_t` for the reason. Still catch `DecompilationFailure` for portability |
| `ida_funcs.get_func(ea)` | Works in 9.4 but emits a `DeprecationWarning` (prefers `get_func_start` / `get_func_entry_info`). Harmless; filter warnings in logs |
| `linux_server64`, `armlinux_server64` | 9.x `dbgsrv/` names: `linux_server`, `armlinux_server`, `android_server`, `mac_server_arm`, `win64_remote.exe` |

Pitfalls:

- **Analysis not finished.** Call `ida_auto.auto_wait()` (or let `execute_python` wait) before enumerating. Partial analysis gives missing functions and wrong xrefs.
- **Mach-O names.** Symbols carry a leading underscore (`_main`, `_system`). Look them up with `ida_name.get_name_ea(idc.BADADDR, "_main")`.
- **Thunks vs real functions.** Import stubs are `FUNC_THUNK`. Skip them in exports and rankings.
- **UI calls in headless mode.** `ida_kernwin.ask_*`, `jumpto`, and `refresh_idaview_anyway` hang or no-op headless. Never call them in `execute_python` or `-A` scripts.
- **File offsets vs EAs.** Convert with `ida_loader.get_fileregion_offset(ea)` and `ida_loader.get_fileregion_ea(offset)`.
- **`ida-mcp` timeouts.** `execute_python` defaults to 360 s. A whole-binary decompile loop exceeds it on large targets. Batch it and pass a larger `timeout` only for known-long single steps.
- **Huge binaries.** Decompile lazily. Do not pre-decompile everything. Turn off analyzers you do not need with `-d` directives or analyze only the segments of interest.
- **`idalib` saves by default.** `idapro.close_database()` saves unless `save=False`.
- **Concurrent writers.** Two processes on one `.i64` corrupt it. Copy the database for parallel experiments.

---

## 11. Remote debugging

`ida-mcp` exposes no debugger tool. Load the bounded helper `ida/re_dbg.py` through `execute_python` and follow [ida-mcp-remote-debugging.md](ida-mcp-remote-debugging.md). Run the matching `dbgsrv/` server inside the disposable guest, never on the host. Guest setup: [utm-hypervisor.md](utm-hypervisor.md) and [../05-environment/ida-remote-debugging.md](../05-environment/ida-remote-debugging.md).

---

## 12. Verification checklist

- `"$IDA/idat" -A -S"script.py" -L log target; echo $?` returns the code passed to `qexit`.
- Log shows `The initial autoanalysis has been finished.` before your script output.
- Decompiled files exist for every non-thunk function you expected (`ls pseudo | wc -l`).
- After renames/types: `save_database()` (MCP) or exit `idat` normally, then reopen and confirm names persist.
- Patched copy differs from the original only at your patch offsets (`cmp -l orig orig.patched`).
