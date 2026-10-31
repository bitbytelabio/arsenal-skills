# Scripts, Office Documents, And Other Non-PE Artifacts

## When To Open
Open this file when the artifact is a script or a document, not a compiled binary: `.bat`/`.cmd`, `.ps1`, `.vbs`/`.vbe`, `.js`/`.jse`, `.wsf`, `.hta`, `.lnk`, OLE or OOXML Office files with macros, Excel 4.0 (XLM) sheets, RTF, or OneNote. The goal is the final command, URL, or dropped payload, and the chain of layers that leads to it. Never run the artifact on the analysis host. Decode it as data.

Record every layer as its own evidence item (stage 0, 1, 2, ...) with its hash. A final payload without the intermediate stages is not reproducible.

Browser JavaScript and obfuscator.io-style bundles are in [browser-js-wasm.md](browser-js-wasm.md).

---

## 1. Identify

| First bytes / trait | Format | Start with |
|---|---|---|
| `D0 CF 11 E0 A1 B1 1A E1` | OLE2 (`.doc`, `.xls`, `.ppt`, `.msi`, `.msg`) | `oleid`, `olevba` |
| `PK\x03\x04` with `[Content_Types].xml` | OOXML (`.docm`, `.xlsm`, `.xlsb`) | `olevba` (reads `vbaProject.bin` inside) |
| `{\rtf` | RTF | `rtfobj` |
| `4C 00 00 00 01 14 02 00` | Windows shortcut `.lnk` | `lnkparse` |
| `E4 52 5C 7B 8C D8 A7 4D` | OneNote `.one` | `onedump.py` (Didier Stevens) |
| `#@~^` ... `^#~@` | Script Encoder (`.vbe`, `.jse`, or inside `.wsf`/`.hta`) | section 5 |
| `FF FE` / `FE FF` | UTF-16 text. Batch files in UTF-16 still run. | Convert, then read |
| `<HTA:APPLICATION` / `<job>` / `<package>` | HTA / WSF | Extract each `<script>` block |

```bash
file "$F"; xxd -l 16 "$F"
uv tool run --from oletools oleid "$F"          # macros? encryption? external links? flags per indicator
iconv -f UTF-16LE -t UTF-8 "$F" > "$F.utf8.txt"  # macOS/BSD iconv has no -o; redirect instead
```

The `oletools` commands below run with `uv tool run --from oletools <tool>` without a global install.

---

## 2. Batch / CMD

Common tricks: `set` fragments joined later (`%a%%b%`), substring slices (`%x:~5,1%`), substitution (`%x:abc=%`), carets (`p^ow^er^shell`), delayed expansion (`!v!`), UTF-16 or mixed code pages, `REM`/`::` floods, and `goto` mazes.

Static expander. It only rewrites text. It handles `set`, `%v%`, `%v:~s,l%` (negative values too), `%v:old=new%`, carets, comments, `&&` chains, and UTF-16 input. Tested on a sample using all of these.

```python
# bat_expand.py. python3 -I bat_expand.py sample.bat > expanded.txt
import re, sys

env = {}
raw = open(sys.argv[1], "rb").read()
text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("latin-1")

def expand(s):
    def sub(m):
        name, mod = m.group(1), m.group(2)
        val = env.get(name.lower())
        if val is None:
            return m.group(0)                      # unknown: leave it visible
        if mod and mod.startswith("~"):            # %v:~start,len%
            parts = [int(p) for p in mod[1:].split(",")]
            start = parts[0] if parts[0] >= 0 else len(val) + parts[0]
            if len(parts) == 1:
                return val[start:]
            ln = parts[1]
            return val[start:start + ln] if ln >= 0 else val[start:len(val) + ln]
        if mod and "=" in mod:                     # %v:old=new%
            old, new = mod.split("=", 1)
            return re.sub(re.escape(old), new.replace("\\", "\\\\"), val, flags=re.I)
        return val
    prev = None
    while prev != s:                               # nested expansion
        prev, s = s, re.sub(r"%([^%:\s]+)(?::([^%]*))?%", sub, s)
    return s

for line in re.split(r"\r?\n", text):
    for stmt in re.split(r"&&|&(?![^\"]*\"\s*$)", line):
        stmt = stmt.strip()
        m = re.match(r'(?i)^set\s+(/a\s+)?"?([^=\s"]+)=(.*?)"?$', stmt)
        if m and not m.group(1):
            env[m.group(2).lower()] = expand(m.group(3))
            continue
        out = expand(stmt).replace("^", "")
        if out and not re.match(r"(?i)^(rem\b|::)", out):
            print(out)
```

Limits: it follows lines in file order, not `goto`/`call` order. It does not evaluate `set /a`, `for /f`, or `!delayed!` variables. When the order matters, list labels and `goto` targets first (`grep -nE '^:|goto|call :' "$F"`) and expand per reachable block. `%~dp0`, `%random%`, and `%cd%` stay unexpanded on purpose.

---

## 3. PowerShell

### Layers
Typical stagers stack: `-EncodedCommand` (Base64 of UTF-16LE), `FromBase64String`, `GZipStream` or `DeflateStream` (raw Deflate, no header), XOR with a key, `[char]` arrays, string reversal, `-f` format reordering, `-join`, `-replace`, and `IEX` / `Invoke-Expression` / `& ($env:ComSpec[4,15,25]-join'')` / `.( $PSHOME[4]+$PSHOME[30]+'x')`.

Layer peeler. It finds the longest Base64 run, tries gzip, raw Deflate, and zlib, picks UTF-16LE or UTF-8, folds `[char]N` and `'a'+'b'`, and writes each layer. Tested on a three-layer chain (`-enc` → gzip → `DeflateStream`).

```python
# ps_layers.py. python3 -I ps_layers.py stage0.ps1 outdir/
import base64, binascii, gzip, os, re, sys, zlib

B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

def as_text(b):
    if len(b) > 1 and b[1::2].count(0) > len(b) // 4:        # UTF-16LE (-EncodedCommand)
        return b.decode("utf-16le", "replace")
    return b.decode("utf-8", "replace")

def unwrap(b):
    for fn in (gzip.decompress, lambda d: zlib.decompress(d, -15), zlib.decompress):  # gzip, raw Deflate, zlib
        try:
            return fn(b)
        except (OSError, zlib.error, EOFError):
            pass
    return b

def fold(s):
    s = re.sub(r"\[char\]\s*(0x[0-9a-f]+|\d+)", lambda m: repr(chr(int(m.group(1), 0))), s, flags=re.I)
    s = re.sub(r"'\s*\+\s*'", "", s)                          # 'ab'+'cd' -> 'abcd'
    return s

def next_layer(s):
    for c in sorted(B64.findall(s), key=len, reverse=True):
        try:
            raw = base64.b64decode(c + "=" * (-len(c) % 4), validate=True)
        except binascii.Error:
            continue
        out = as_text(unwrap(raw))
        if sum(ch.isprintable() or ch in "\r\n\t" for ch in out) > 0.9 * len(out):
            return out
    return None

src, outdir = open(sys.argv[1], encoding="utf-8", errors="replace").read(), sys.argv[2]
os.makedirs(outdir, exist_ok=True)
layer = 0
while True:
    src = fold(src)
    path = os.path.join(outdir, f"layer{layer}.ps1.txt")
    open(path, "w").write(src)
    print(f"layer {layer}: {len(src)} chars -> {path}")
    nxt = next_layer(src)
    if nxt is None or nxt == src or layer > 20:
        break
    src, layer = nxt, layer + 1
```

When a layer is XOR-encrypted, the key is in the same layer (`-bxor 0x5A`, `$k[$i % $k.Length]`). Decode it in Python and continue from the output. If the decoded bytes start with `MZ` or `\x7fELF`, stop: that is a binary payload. Hash it and triage it as a binary.

### AST Inventory And Constant Folding
PowerShell's own parser handles every quoting and escaping trick. The script below parses the file, lists commands (including dynamic ones like `& $cmd`) and .NET calls, and folds only expressions that contain no commands, no variables, no script blocks, and no .NET calls other than `[string]`, `[char]`, and `[convert]`. Folding runs in an empty runspace (no cmdlets, no providers) in ConstrainedLanguage mode with a 2-second limit. Tested with `pwsh` 7: it resolved `('x'+'e'+'i')[2..0] -join ''` → `iex`, `'{1}{0}' -f 'loadString','Down'` → `DownloadString`, and `[string]::Join('', [char[]](73,69,88))` → `IEX`, and it refused `[IO.File]::ReadAllText(...)`.

```powershell
# ps_ast.ps1. pwsh -NoProfile -NonInteractive -File ps_ast.ps1 -Path sample.ps1
using namespace System.Management.Automation.Language
param([Parameter(Mandatory)][string]$Path)
$tokens = $null; $errors = $null
$ast = [Parser]::ParseFile((Resolve-Path $Path), [ref]$tokens, [ref]$errors)
if ($errors.Count) { "parse errors: $($errors.Count) (first: $($errors[0].Message))" }

"== commands =="
$ast.FindAll({ $args[0] -is [CommandAst] }, $true) | ForEach-Object {
  $n = $_.GetCommandName(); if (-not $n) { $n = "<dynamic> " + $_.CommandElements[0].Extent.Text }
  "{0,5}: {1}" -f $_.Extent.StartLineNumber, $n } | Sort-Object -Unique

"== .NET member calls =="
$ast.FindAll({ $args[0] -is [InvokeMemberExpressionAst] }, $true) |
  ForEach-Object { "{0,5}: {1}.{2}" -f $_.Extent.StartLineNumber, $_.Expression.Extent.Text, $_.Member.Extent.Text } | Sort-Object -Unique

"== folded constants =="
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::Create()   # no cmdlets, no providers
$iss.LanguageMode = 'ConstrainedLanguage'
$rs = [runspacefactory]::CreateRunspace($iss); $rs.Open()
$allowed = '^\[(string|char|convert)\]::'
$ast.FindAll({ param($n) ($n -is [BinaryExpressionAst] -or $n -is [ConvertExpressionAst] -or $n -is [InvokeMemberExpressionAst]) -and
    $n.Parent -isnot [BinaryExpressionAst] }, $true) | ForEach-Object {
  $node = $_
  $bad = $node.FindAll({ param($c) ($c -is [CommandAst]) -or ($c -is [VariableExpressionAst]) -or ($c -is [ScriptBlockExpressionAst]) -or
      (($c -is [InvokeMemberExpressionAst]) -and ($c.Extent.Text -notmatch $allowed)) }, $true)
  if ($bad) { return }
  $ps = [powershell]::Create(); $ps.Runspace = $rs
  [void]$ps.AddScript($node.Extent.Text)
  $h = $ps.BeginInvoke()
  if ($h.AsyncWaitHandle.WaitOne(2000)) {
    try { $v = ($ps.EndInvoke($h) -join ''); if ($v.Length -gt 1) { "{0,5}: {1}  =>  {2}" -f $node.Extent.StartLineNumber, $node.Extent.Text, $v } } catch { }
  } else { $ps.Stop() }
  $ps.Dispose()
}
$rs.Close()
```

Folding evaluates fragments of the sample, even if constrained. Run it in the analysis VM or a throwaway container, not on a workstation. Substitute folded values back into the text and run the layer peeler again. Repeat until no layer changes.

Other tools: PSDecode (`PSDecode -dump -beautify -verbose .\evil.ps1`) and box-ps (`docker-box-ps.sh <script> <out.json>`) both execute the script with overridden cmdlets. PowerDecode needs `Set-ExecutionPolicy bypass` and also runs it. Use them only in the lab, and only when static peeling stalls. Unit42 PowerShellProfiler (`python PowerShellProfiler.py -f <file>`) is static.

### Indicators To Pull
`DownloadString`/`DownloadData`/`Invoke-WebRequest`/`Net.WebClient`/`BitsTransfer` (remote endpoint), `[Reflection.Assembly]::Load` (in-memory .NET payload), `VirtualAlloc` via `Add-Type` or delegates (shellcode), AMSI tampering (`AmsiUtils`, `amsiInitFailed`), `Set-MpPreference -ExclusionPath`, scheduled tasks and `Run` keys (persistence).

---

## 4. Office Macros

### VBA
```bash
uv tool run --from oletools olevba "$F"              # source + indicator table (XLM extracted by default; --no-xlm disables)
uv tool run --from oletools olevba --decode "$F"     # decoded Base64/hex/StrReverse/Dridex strings
uv tool run --from oletools olevba --deobf --reveal "$F"   # evaluate simple VBA expressions, show source with values substituted
uv tool run --from oletools olevba -a -j "$F"        # analysis only, JSON
uv tool run --from oletools olevba --show-pcode "$F" # P-code disassembly via pcodedmp
oledump.py "$F"                                       # stream list; 'M' = module with code, 'm' = module with only Attribute lines
oledump.py -s A3 -v "$F"                              # decompress the VBA source of stream A3
oledump.py -p plugin_vba_dco "$F"                     # Declare / CreateObject / Shell / CallByName summary
```

Read `AutoOpen`, `Document_Open`, `Workbook_Open`, `Auto_Open`, `*_Layout`, `*_Change`, and form control events first. Then follow `Shell`, `WScript.Shell.Run`, `CreateObject("MSXML2.XMLHTTP")`, `ADODB.Stream.SaveToFile`, `CallByName`, `Declare PtrSafe Function ... Lib "kernel32"` (direct API use), and form/document variables (`UserForm1.TextBox1.Text`, `ActiveDocument.Variables`, `CustomDocumentProperties`) that hide payload text outside the code.

### VBA Stomping (P-code vs Source)
Office runs compiled P-code when the document's VBA version matches the running Office. Stomping replaces the source with benign text or zeros and leaves the P-code.

1. Compare `olevba` source with `olevba --show-pcode` or `pcodedmp -d "$F"`. Different call names, strings, or a module with P-code but no source means stomped.
2. Rebuild source from P-code: `pcode2code "$F" -o recovered.vba` (pip `pcode2code`).
3. The `_VBA_PROJECT` stream holds the VBA version. Only matching Office builds execute the P-code. Other builds recompile the (fake) source, so sandbox results differ by Office version.

### Excel 4.0 (XLM) Macros
Formulas live in macro sheets, often `veryHidden`, with `Auto_Open` defined names. `EXEC`, `CALL`, `REGISTER`, `FORMULA` (self-writing cells), `CHAR()` concatenation.
```bash
uv tool run --python 3.11 --from XLMMacroDeobfuscator xlmdeobfuscator -f "$F" -n          # emulate formulas, print the resolved chain
uv tool run --python 3.11 --from XLMMacroDeobfuscator xlmdeobfuscator -f "$F" -x          # extract cells only, no emulation
uv tool run --python 3.11 --from XLMMacroDeobfuscator xlmdeobfuscator -f "$F" -n --export-json out.json
```
Python 3.11 is pinned because the current release imports `distutils`, which Python 3.12 removed. The emulator is Python code. It does not call Excel unless you pass `--with-ms-excel`. `-p` supplies a password. `--start-point` starts from a chosen cell when `Auto_Open` is missing.

### Other Document Vectors
| Vector | Tool | What to read |
|---|---|---|
| Embedded OLE objects / packages | `oleobj "$F"`, `rtfobj "$F"` | Dropped file names, `Package` streams with `.exe`/`.js`/`.hta` |
| Equation Editor exploits (CVE-2017-11882 family) in RTF | `rtfobj` | An `Equation.3` object. Its shellcode is the payload. |
| Remote template injection | `unzip -p "$F" word/_rels/settings.xml.rels` | `Target="http..."` with `TargetMode="External"` |
| DDE / DDEAUTO | `msodde "$F"` | The command field |
| OneNote | `onedump.py "$F"` | Embedded files (`.hta`, `.cmd`, `.js`) behind the "click to view" image |
| LNK | `uv tool run --from LnkParse3 lnkparse -a "$F"` | Target path, arguments (often `powershell -enc`), icon location, machine ID |

---

## 5. Windows Script Host: VBS, JS, WSF, HTA

### Script Encoder (`#@~^ ... ^#~@`)
The encoding is a fixed substitution with a checksum. Decode it, do not run it.
- Didier Stevens `decode-vbe.py encoded.vbe` (also accepts a literal string argument).
- `vbe-decoder.py encoded.vbe -o decoded.vbs` (JohnHammond/vbe-decoder).

There is no `scrdec` Python module on PyPI. `scrdec18.exe` is a Windows binary.

### VBScript
Patterns: `Execute`/`ExecuteGlobal`/`Eval` of a built string, `Chr()`/`ChrW()` chains with arithmetic (`Chr(80+3)`), `Replace()` of junk tokens, `StrReverse`, and arrays joined with `Join`. Replace each `Execute X` with `WScript.Echo X` only inside the lab VM. Statically, fold `Chr(N op M)` with a regex and evaluate `Replace`/`StrReverse` by hand in Python.

### JScript / WSH JavaScript
`eval`, `Function(...)()`, `new ActiveXObject("WScript.Shell")`, `GetObject("winmgmts:")`, string arrays with rotating index functions (obfuscator.io). Deobfuscate the JS with the tools in [browser-js-wasm.md](browser-js-wasm.md). `box-js` emulates WSH objects in Node and logs URLs and dropped files. It still executes the script, so run it only in the lab.

### HTA
`mshta.exe` runs HTA with full user rights and no browser sandbox. Extract each `<script language="VBScript|JScript">` block and treat it as above. Typical chain: `MSXML2.XMLHTTP` or `WinHttp.WinHttpRequest.5.1` download → `ADODB.Stream` `SaveToFile` → `WScript.Shell.Run`. Record the URL, the save path, and the run command.

---

## 6. Verify
- Every layer file decodes from the previous one with the recorded method. Re-run the peeler on stage 0 and compare hashes.
- A URL or command reported as final appears literally in the last layer, not only in your reconstruction.
- For stomped VBA, the P-code disassembly (not the visible source) contains the reported calls.
- For XLM, the resolved `EXEC`/`CALL` arguments match between `-x` cell extraction and the emulated chain.

## 7. Boundaries And Anti-Patterns
- Do not run `powershell`, `cscript`, `wscript`, `mshta`, Office, or `cmd /c` on the sample outside the lab VM.
- Do not report a decoded layer as final while it still contains Base64 runs, `IEX`, `Execute`, or `eval`.
- Do not trust `olevba` source alone. Check P-code.
- Do not lose intermediate layers. Each one is evidence.
- Do not treat a script as benign because static decoding stalls. Record the stall and the last layer reached.
