# Non-PE & Script Artifact Deobfuscation Cookbook

## Title & Overview
- **Domain**: Deobfuscation, static extraction, and dynamic unwinding of non-PE script artifacts, multi-layer payloads, and malicious document formats.
- **Scope**: Production reverse engineering workflows for Batch/CMD scripts, PowerShell loaders, Office macros (VBA Stomping, XLM / Excel 4.0), and Windows Script Host components (.vbs, .wsf, .hta).

---

## 1. Batch / CMD Script Deobfuscation

Adversaries abuse `cmd.exe` string-slicing, environment variable concatenation, and character escaping to evade pattern-matching static engines.

### 1.1 Variable Concatenation & Caret Stripping
- **Pattern**:
  ```bat
  SET a=p&& SET b=o&& SET c=w&& SET d=er&& SET e=sh&& SET f=ell
  %a%%b%%c%%d%%e%%f% -c ^e^c^h^o ^h^e^l^l^o
  ```
- **Analysis Workflow**:
  1. Do NOT execute untrusted batch files directly in standard terminals.
  2. Perform line-by-line variable table expansion via Python parser or headless string substitution.
  3. Strip carets (`^`) and quotation anomalies used to break keyword recognition.
  4. Record the final unrolled command stream into Evidence (`E-batch-deobf`).

### 1.2 UTF-16 LE Encoding & BOM Manipulation
- **Pattern**: The file begins with bytes `0xFF 0xFE` (UTF-16 LE BOM). Static text viewers often show null bytes (`\x00`) or display garbled characters while `cmd.exe` executes the file seamlessly.
- **Remediation**:
  ```bash
  # Check file magic bytes
  head -c 2 script.bat | xxd
  # Output: 00000000: fffe
  
  # Convert UTF-16 LE to clean UTF-8
  iconv -f UTF-16LE -t UTF-8 script.bat -o script_utf8.bat
  ```

### 1.3 Dead-Code Flooding & GOTO Trampolines
- **Pattern**: Scripts insert hundreds of lines containing `REM`, `::`, or unreferenced `:label` tags combined with convoluted `GOTO` jumps to inflate file size and break human comprehension.
- **Remediation Workflow**:
  1. Parse the script as a directed control flow graph of labels and targets.
  2. Prune all dead code blocks unreachable from the entry line or prior `GOTO` branch.
  3. Strip redundant comment lines (`REM`, `::`).
  4. Save sanitized script to `clean_script.bat` and document in Evidence (`E-batch-deadcode`).

---

## 2. PowerShell Loader & Memory-Payload Unwinding

PowerShell scripts frequently act as multi-stage stagers employing nested layers of Base64 encoding, Gzip compression, character arrays, and string reversal.

### 2.1 Multi-Layer Base64 & Gzip Decompression
- **MANDATORY EVIDENCE CONTRACT**: Each discovered layer of decompression/decoding **MUST** be recorded as a distinct, serialized Evidence entry (`E-ps-decode-layer-1`, `E-ps-decode-layer-2`, etc.). Never skip directly to the final payload without capturing intermediate stagers.
- **Deobfuscation Script**:
  ```python
  #!/usr/bin/env python3
  """Multi-layer PowerShell Stager Decompressor."""
  import base64
  import gzip
  import io
  import re
  import sys

  def decompress_ps_layer(encoded_text, layer_num=1):
      # Extract Base64 string if wrapped inside script code
      b64_match = re.search(r'[A-Za-z0-9+/=]{40,}', encoded_text)
      if not b64_match:
          print(f"[*] Layer {layer_num}: No further Base64 strings found. Final payload reached.")
          return encoded_text
      
      raw_b64 = b64_match.group(0)
      decoded_bytes = base64.b64decode(raw_b64)
      
      # Test if content is Gzip compressed (Magic Header: 0x1F 0x8B)
      if decoded_bytes.startswith(b'\x1f\x8b'):
          with gzip.GzipFile(fileobj=io.BytesIO(decoded_bytes)) as gz:
              extracted = gz.read().decode('utf-8', errors='ignore')
      else:
          # Attempt UTF-16 LE decode (default PowerShell encoding)
          try:
              extracted = decoded_bytes.decode('utf-16le')
          except UnicodeDecodeError:
              extracted = decoded_bytes.decode('utf-8', errors='ignore')
              
      print(f"[+] Layer {layer_num} successfully decoded ({len(extracted)} chars).")
      # Write layer out for evidence tracking
      with open(f"ps_layer_{layer_num}.ps1", "w") as f:
          f.write(extracted)
          
      # Recursively inspect for deeper nested stagers
      return decompress_ps_layer(extracted, layer_num + 1)

  if __name__ == "__main__":
      with open(sys.argv[1], "r") as f:
          decompress_ps_layer(f.read())
  ```

### 2.2 String Slicing, Reversal & Array Reconstruction
- **Pattern**:
  ```powershell
  $cmd = (('x'+'e'+'i')[2..0] -join '') # Produces 'iex'
  & $cmd ([string]::Join('', ('tset'[-1..-4])))
  ```
- **Remediation**:
  1. Do NOT execute with `powershell.exe -ExecutionPolicy Bypass` on the host machine.
  2. Use PowerShell Abstract Syntax Tree (AST) analysis or safe offline string evaluation to fold constant expressions:
     ```powershell
     # In isolated sandbox PowerShell
     [System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$tokens, [ref]$errors)
     ```
  3. Replace invocation aliases (`IEX`, `&`, `.`, `Invoke-Expression`) with diagnostic print statements (`Write-Output`) inside an isolated, non-networked container.

---

## 3. Malicious Office Documents & Macros

Adversaries exploit legacy Microsoft Office formats (`.doc`, `.xls`, `.docm`, `.xlsm`) using VBA stomping, Excel 4.0 XML macros, and dynamic shellcode injection.

### 3.1 VBA Stomping (P-Code vs Source Desynchronization)
- **Concept**: A VBA macro document stores both source code text and compiled intermediate bytecode (**P-Code**). Modern Office versions execute the pre-compiled P-Code if the Office version matches the compiler version. Attackers deliberately purge or overwrite the VBA source code stream while leaving the malicious P-Code intact.
- **Detection & Extraction**:
  ```bash
  # 1. Inspect macro streams with oledump.py
  oledump.py target.docm
  # Stream marked 'M' contains macro code
  
  # 2. Extract VBA source code with olevba
  olevba target.docm
  # If olevba reports: "No VBA source code found" or code is benign dummy text:
  
  # 3. Disassemble P-Code directly with pcode2code or pcodedmp
  pcodedmp target.docm -d
  # Extracts actual compiled P-Code instructions, revealing True Execution Flow
  ```
- **Evidence Recording**: Log whether source code was stomped (`E-vba-pcode`), noting discrepancies between high-level text and P-Code opcodes.

### 3.2 Excel 4.0 / XLM Macros (Hidden Formula Invocations)
- **Concept**: Introduced in 1992, XLM macros reside in spreadsheet formula cells (`=EXEC(...)`, `=CALL(...)`, `=REGISTER(...)`) rather than separate VBA storage streams.
- **Workflow**:
  ```bash
  # 1. Scan for hidden XLM sheets and formulas
  olevba --xlm target.xlsm
  
  # 2. Deobfuscate nested XLM formula execution with XLMMacroDeobfuscator
  xlmdeobf -f target.xlsm -u
  # Traces cell formulas, resolves dynamic string concatenations (CHAR(65)&CHAR(66)),
  # and outputs the final reconstructed Win32 API calls.
  ```

### 3.3 Dynamic Character Concatenation & Self-Modifying Macros
- **Pattern**:
  ```vb
  Dim s As String
  s = Chr(87) & Chr(115) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)
  Set obj = CreateObject(s & ".Shell")
  ```
- **Remediation**:
  - Run offline static regex unrolling to compute ASCII ordinal equivalents (`Chr(x)` -> character).
  - Inspect macro documents for `ActiveDocument.VBProject.VBComponents(...).CodeModule.InsertLines` to detect runtime macro rewriting.

---

## 4. Windows Script Host (.vbs, .wsf, .hta)

Lightweight scripting engines (`wscript.exe`, `cscript.exe`, `mshta.exe`) are weaponized via encoding envelopes and active scripting COM objects.

### 4.1 Microsoft Script Encoder Decoding (.vbe, .jse)
- **Concept**: Files beginning with the signature `#@~^` are encoded using the Microsoft Script Encoder algorithm (`screnc`).
- **Decoding Workflow**:
  ```bash
  # Decode encoded VBScript / JScript files to clean text
  python3 -m scrdec encoded.vbe decoded.vbs
  ```

### 4.2 HTML Applications (.hta) & `mshta.exe` Execution
- **Concept**: `.hta` files execute with full system trust inside Internet Explorer’s legacy process engine, bypassing browser sandboxes.
- **Analysis Workflow**:
  1. Inspect the `<HTA:APPLICATION>` tag and embedded `<script language="VBScript">` or `<script language="JScript">` tags.
  2. Isolate long dynamic execution wrappers (e.g. `eval()`, `window.execScript()`).
  3. Extract remote stage downloaders (ActiveX `MSXML2.XMLHTTP` + `ADODB.Stream` saving binary payloads).
  4. Record URL indicators and dropped binary hashes in Evidence (`E-hta-download-chain`).
