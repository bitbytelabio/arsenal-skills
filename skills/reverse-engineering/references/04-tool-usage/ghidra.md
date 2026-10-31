# Ghidra Headless, PyGhidra, and Ghidra MCP Bridges

- **Domain**: Ghidra 12.x batch analysis (`analyzeHeadless`), CPython scripting through PyGhidra, and MCP bridges (ReVa, GhidraMCP). REA is in [rea.md](rea.md).
- **Scope**: headless pipelines that export decompilation to files, PyGhidra library and script APIs, types and renames, processor and loader selection, BSim and Version Tracking awareness, pitfalls.
- **Verified**: `analyzeHeadless` and PyGhidra snippets ran on Ghidra 12.2 (Homebrew, macOS arm64, JDK 25) with PyGhidra 3.2.0. ReVa and GhidraMCP details come from their upstream READMEs and were not run.

---

## 1. Choose the entry point

| Need | Use |
|---|---|
| Import + analyze + export many binaries, no Python | `analyzeHeadless` with a Java `-postScript` |
| Same, with Python scripts | PyGhidra headless (`pyghidraRun -H` or `python -m pyghidra.ghidra_launch ... AnalyzeHeadless`) |
| Python program owns the loop | PyGhidra library: `pyghidra.start()`, `open_project`, `program_loader`, `program_context` |
| Agent asks questions interactively | ReVa or GhidraMCP over MCP (section 6) |
| Evidence-tracked answers across many formats | REA ([rea.md](rea.md)) |
| Processor IDA lacks or a second opinion on decompilation | Ghidra (any route above) |

Ghidra is the second decompiler next to IDA ([ida-pro.md](ida-pro.md)). Use it for architectures IDA does not license here (many embedded CPUs, SLEIGH-defined processors), for BSim similarity search, and to cross-check Hex-Rays output.

---

## 2. Install and locate

```bash
brew install ghidra                         # macOS; formula ships analyzeHeadless and pyghidraRun
GHIDRA_INSTALL_DIR="$(brew --prefix ghidra)/libexec"
ls "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$GHIDRA_INSTALL_DIR/support/pyghidraRun"
java -version                               # Ghidra 12.1 needs JDK 21+; 12.2 needs JDK 25+
```

Linux: unzip the release to `/opt/ghidra_<ver>_PUBLIC` and set `GHIDRA_INSTALL_DIR` to it. The JDK must match the host architecture (no x86_64 JDK under Rosetta).

Python version facts:

- PyGhidra (CPython 3 via JPype) is built in since Ghidra 11.3. PyGhidra 3.x requires Ghidra 12.0+.
- Since Ghidra 12.0, `.py` scripts without a `# @runtime` header run under PyGhidra. Jython scripts need `# @runtime Jython`.
- Since Ghidra 12.1, Jython is an optional extension (File > Install Extensions > Jython). `support/jythonRun` is gone.
- Plain `analyzeHeadless` cannot run `.py` scripts. It fails with `Ghidra was not started with PyGhidra` and still exits 0.

Install PyGhidra from the matching Ghidra build into a venv:

```bash
uv venv ~/.venvs/pyghidra
uv pip install --python ~/.venvs/pyghidra/bin/python --no-index \
  -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
```

---

## 3. `analyzeHeadless`

```text
analyzeHeadless <project_location> <project_name>[/<folder>]
  [-import <file|dir>+ | -process [<project_file>]]
  [-preScript <Name.ext> [args]*] [-postScript <Name.ext> [args]*]
  [-scriptPath "<p1>;<p2>"] [-propertiesPath "<p1>;<p2>"]
  [-scriptlog <file>] [-log <file>]
  [-overwrite] [-recursive [depth]] [-readOnly] [-deleteProject] [-noanalysis]
  [-processor <languageID>] [-cspec <compilerSpecID>] [-loader <Name> -loader-<arg> <val>]
  [-analysisTimeoutPerFile <s>] [-max-cpu <n>] [-librarySearchPaths "<p1>;<p2>"]
```

| Flag | Fact |
|---|---|
| `<project_location>` | Directory must already exist. A missing directory aborts with `Directory not found` |
| `-import` / `-process` | Mutually exclusive. `-process` reruns scripts or analysis on files already in the project. Quote wildcards: `-process '*.exe'` |
| `-postScript` | Script file name only, with extension. Repeat the flag for more scripts. Arguments follow the name |
| `-scriptPath` | `;`-separated. Escape `\$GHIDRA_HOME` / `\$USER_HOME` on Unix |
| `-overwrite` | Replace a same-named program on import. Without it, conflicts are skipped |
| `-readOnly` | Do not save changes back to the project |
| `-deleteProject` | Delete the project after the run. Only for projects created by this run |
| `-noanalysis` | Skip auto-analysis (use with `-process` on already analyzed programs) |
| `-max-cpu` | Cap analysis threads |
| `-analysisTimeoutPerFile` | Abort analysis of one file after N seconds; scripts still run |
| `-scriptlog` | Receives `println`/`printf` output. Python `print` goes to stdout |

### 3.1 One-shot import, analyze, export

`ExportDecomp.java` (put it in a scripts directory passed with `-scriptPath`):

```java
// Export decompiled C for every non-thunk function. Args: <out_dir>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.*;

public class ExportDecomp extends GhidraScript {
  @Override public void run() throws Exception {
    String[] a = getScriptArgs();
    File out = new File(a.length > 0 ? a[0] : "/tmp/decomp");
    out.mkdirs();
    DecompInterface ifc = new DecompInterface();
    ifc.openProgram(currentProgram);
    int n = 0;
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      if (f.isThunk() || f.isExternal()) continue;
      DecompileResults r = ifc.decompileFunction(f, 60, monitor);
      if (!r.decompileCompleted()) { printerr(f.getName() + ": " + r.getErrorMessage()); continue; }
      try (PrintWriter w = new PrintWriter(new File(out, f.getEntryPoint() + "_" + f.getName() + ".c"))) {
        w.print(r.getDecompiledFunction().getC());
      }
      n++;
    }
    ifc.dispose();
    println("exported " + n + " functions to " + out);
  }
}
```

```bash
GH="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
mkdir -p /abs/work/ghproj
"$GH" /abs/work/ghproj Target -import /abs/target -overwrite -max-cpu 4 \
  -analysisTimeoutPerFile 900 \
  -scriptPath /abs/work/ghscripts -postScript ExportDecomp.java /abs/work/decomp \
  -log /abs/work/analysis.log -scriptlog /abs/work/script.log
grep -E "REPORT|ERROR" /abs/work/analysis.log
```

Reuse the analyzed project later without re-analysis:

```bash
"$GH" /abs/work/ghproj Target -process target -noanalysis -readOnly \
  -scriptPath /abs/work/ghscripts -postScript ExportDecomp.java /abs/work/decomp2
```

### 3.2 Raw blobs and firmware

```bash
"$GH" /abs/work/ghproj Fw -import /abs/fw.bin -deleteProject \
  -processor ARM:LE:32:Cortex -loader BinaryLoader -loader-baseAddr 0x08000000 \
  -scriptPath /abs/work/ghscripts -postScript ExportDecomp.java /abs/work/fw_decomp
```

- `-processor` takes a language ID (`x86:LE:64:default`, `AARCH64:LE:64:v8A`, `ARM:LE:32:v8`, `MIPS:BE:32:default`, `PowerPC:BE:32:default`, `RISCV:LE:64:default`, `tricore:LE:32:default`). List them in `$GHIDRA_INSTALL_DIR/Ghidra/Processors/*/data/languages/*.ldefs`.
- `BinaryLoader` options: `-loader-baseAddr`, `-loader-blockName`, `-loader-fileOffset`, `-loader-length`.
- Ghidra's processor coverage beyond IDA's license tier is its main advantage for firmware. See [../01-static-architectures/firmware-iot.md](../01-static-architectures/firmware-iot.md) for base-address recovery.

---

## 4. PyGhidra

### 4.1 Python postScript (headless)

```python
# export_decomp.py -- Args: <out_dir>
# @runtime PyGhidra
import os
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

out = getScriptArgs()[0] if getScriptArgs() else "/tmp/decomp"
os.makedirs(out, exist_ok=True)
ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
ifc.openProgram(currentProgram)
mon = ConsoleTaskMonitor()
n = 0
for f in currentProgram.getFunctionManager().getFunctions(True):
    if f.isThunk() or f.isExternal():
        continue
    res = ifc.decompileFunction(f, 60, mon)
    if not res.decompileCompleted():
        println("FAIL %s %s" % (f.getName(), res.getErrorMessage()))
        continue
    with open(os.path.join(out, "%s_%s.c" % (f.getEntryPoint(), f.getName())), "w") as fh:
        fh.write(res.getDecompiledFunction().getC())
    n += 1
ifc.dispose()
println("exported %d functions to %s" % (n, out))
```

Run it through the PyGhidra launcher. Both forms start `AnalyzeHeadless` inside a JVM owned by CPython:

```bash
# Shortcut: uses python3 on PATH, which must have pyghidra installed
"$GHIDRA_INSTALL_DIR/support/pyghidraRun" -H /abs/work/ghproj Target -process target -noanalysis \
  -scriptPath /abs/work/ghscripts -postScript export_decomp.py /abs/work/decomp

# Explicit venv (verified)
~/.venvs/pyghidra/bin/python -m pyghidra.ghidra_launch --install-dir "$GHIDRA_INSTALL_DIR" \
  ghidra.app.util.headless.AnalyzeHeadless /abs/work/ghproj Target -process target -noanalysis \
  -scriptPath /abs/work/ghscripts -postScript export_decomp.py /abs/work/decomp
```

### 4.2 PyGhidra library (Python owns the loop)

`pyghidra.open_program()` and `pyghidra.run_script()` are deprecated in PyGhidra 3.x. Use `start` + `open_project` + `program_loader` + `program_context`.

```python
import sys, pyghidra
pyghidra.start()                                   # GHIDRA_INSTALL_DIR or install_dir=...
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType

binary, projdir = sys.argv[1], sys.argv[2]         # projdir must exist
with pyghidra.open_project(projdir, "Lib", create=True) as project:
    loader = pyghidra.program_loader().project(project).source(binary).name("prog")
    with loader.load() as results:
        results.save(pyghidra.task_monitor())
    with pyghidra.program_context(project, "/prog") as program:
        pyghidra.analyze(program, pyghidra.task_monitor(600))   # timeout in seconds
        fm = program.getFunctionManager()
        print(program.getLanguageID(), fm.getFunctionCount())
        ifc = DecompInterface()
        ifc.openProgram(program)
        f = next(fn for fn in fm.getFunctions(True) if fn.getName() == "_handler")
        print(ifc.decompileFunction(f, 60, pyghidra.task_monitor()).getDecompiledFunction().getC())
        print([str(r.getFromAddress()) for r in program.getReferenceManager().getReferencesTo(f.getEntryPoint())])
        with pyghidra.transaction(program, "rename"):
            f.setName("dispatch_cmd", SourceType.USER_DEFINED)
        program.save("rename", pyghidra.task_monitor())
        ifc.dispose()
```

Other PyGhidra 3 calls: `pyghidra.ghidra_script(path, project, program, script_args)` runs any GhidraScript and returns `(stdout, stderr)`; `walk_programs(project, cb)` visits every program; `consume_program` returns a program you must `release`; `analysis_properties(program)` toggles analyzers inside a transaction; `open_filesystem(path)` walks containers (zip, firmware) without extraction. A Python module that shadows a Java package is importable as `<name>_` (for example `pdb_`).

### 4.3 Types, signatures, comments

```python
import sys, pyghidra
pyghidra.start()
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CommentType

with pyghidra.open_project(sys.argv[1], "Lib") as project:
    with pyghidra.program_context(project, "/prog") as program:
        dtm = program.getDataTypeManager()
        with pyghidra.transaction(program, "types"):
            dt = CParser(dtm).parse("struct conn { int fd; unsigned short port; char host[64]; void *cb; };")
            dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
            f = next(x for x in program.getFunctionManager().getFunctions(True) if x.getName() == "dispatch_cmd")
            sig = FunctionSignatureParser(dtm, None).parse(f.getSignature(), "int dispatch_cmd(conn *c, int cmd)")
            ApplyFunctionSignatureCmd(f.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(program, pyghidra.task_monitor())
            program.getListing().setComment(f.getEntryPoint(), CommentType.PLATE, "dispatcher")
        program.save("types", pyghidra.task_monitor())
```

After the signature was applied, the decompiler printed `c->host` and `c->port` instead of raw offsets. Ghidra 12 uses the `CommentType` enum (`EOL`, `PRE`, `POST`, `PLATE`, `REPEATABLE`).

---

## 5. BSim, Version Tracking, function ID

| Feature | Use | Entry point |
|---|---|---|
| BSim | Find structurally similar functions across a corpus (library identification, patch diff, malware family links) | `support/bsim createdatabase / generatesigs / commitsigs / listfuncs`; H2 file DB (`file:/abs/db`) works locally without a server |
| Version Tracking | Port names, types, comments from an old analyzed build to a new one | GUI (Tools > Version Tracking); `VersionTrackingBSim` feature adds BSim correlators |
| Function ID (FID) | Ghidra's FLIRT equivalent | Analyzer "Function ID"; build `.fidbf` from known libraries with FID scripts |
| Program Diff | Byte/code differences between two programs in one project | GUI Program Diff |

For binary patch diffing, BinDiff/Diaphora on exported databases are the usual first choice. See [../03-objectives/vuln-research-patch.md](../03-objectives/vuln-research-patch.md).

---

## 6. MCP bridges for Ghidra

Both run inside Ghidra (GUI extension) and default to HTTP port 8080. Never run them at once on the same port.

| Project | Install | MCP transport | Headless |
|---|---|---|---|
| ReVa (`cyberkaida/reverse-engineering-assistant`) | Release zip for your Ghidra version via File > Install Extensions. Supports Ghidra 12.0+ | Streamable HTTP at `http://localhost:8080/mcp/message` | `uv tool install reverse-engineering-assistant`, then `mcp-reva` |
| GhidraMCP (`LaurieWired/GhidraMCP`) | Release zip via File > Install Extensions; enable `GhidraMCPPlugin` under File > Configure > Developer | Python bridge `bridge_mcp_ghidra.py` (`ghidra-mcp`) talks to the plugin at `http://127.0.0.1:8080/` | Bridge flags `--headless --binary --project` per README |

```bash
claude mcp add --scope user --transport http ReVa -- http://localhost:8080/mcp/message
claude mcp add ghidra -- uvx --from git+https://github.com/LaurieWired/GhidraMCP ghidra-mcp --ghidra-server http://127.0.0.1:8080/
```

Tool names differ per release. List them from the client after connecting. Do not hardcode them in prompts.

---

## 7. REA

REA (`rea-agents`) can drive Ghidra as its native provider and adds many target-free inspectors with Evidence records. It has its own guide: [rea.md](rea.md). REA 6.8.0 accepts only Ghidra 12.1.x, so it cannot use the Homebrew 12.2 install described above.

---

## 8. Pitfalls

- **Exit code 0 on script failure.** `analyzeHeadless` returns 0 when a postScript throws. Grep the log for `SCRIPT ERROR` and check that output files exist.
- **Python script under plain `analyzeHeadless`.** Fails with `Ghidra was not started with PyGhidra`. Use `pyghidraRun -H` or the `pyghidra.ghidra_launch` form.
- **Missing project directory.** Both `analyzeHeadless` and `open_project(create=True)` need the parent directory to exist.
- **Locked project.** A project open in the GUI is locked. Headless runs against it fail. Close the GUI or copy the project.
- **Re-import without `-overwrite`.** Skipped silently as a conflict. Use `-process` to rerun scripts on an existing program.
- **Wrong language on raw input.** Without `-processor`, raw blobs fail or load as data. Set processor, base address, and endianness explicitly.
- **Pseudocode is an observation.** Ghidra and Hex-Rays disagree on calling conventions and types. Cross-check critical lines against disassembly.
- **Port 8080.** ReVa, GhidraMCP, mitmproxy web UIs, and many dev servers compete for it.

---

## 9. Verification checklist

- `grep -E "Import succeeded|Analysis succeeded|SCRIPT ERROR" analysis.log` shows success and no script errors.
- Export directory has one `.c` per non-thunk function.
- Reopen with `-process <name> -noanalysis -readOnly` and confirm renamed symbols and applied types are present.
