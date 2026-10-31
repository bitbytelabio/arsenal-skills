# Static Artifact Analysis & Evidence Contract

## Title & Overview
- **Domain**: Automated static artifact evaluation, JSON schema conformance, and verifiable observation ledger generation.
- **Scope**: Producing schema-conformant JSON deliverables matching `analysis.schema.json` paired with an audited, cited `evidence.md` ledger, citing specific instruction addresses and hex dumps, bounding analysis to application code spans, and passing automated validation via `scripts/check_deliverables.py`.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Assignment requires delivering a structured schema JSON alongside an `evidence.md` observation ledger.
- Task explicitly requires static analysis only, strictly forbidding runtime detonation, dynamic debugging, or emulation.
- Deliverables must pass automated mechanical validation using `check_deliverables.py`.

---

## Tooling & CLI/MCP Actions

### Primary Analysis & Validation Scripts
- **Format Triage & Address Mapping**:
  - `uv run scripts/elf_triage.py <binary>`:
    Inspects ELF/PE headers, entry points, segment load deltas (`vma - file_offset`), and NX/PIE flags.
  - `uv run scripts/elf_symbols.py <binary>`:
    Separates user application symbols (`main`, custom handlers) from standard runtime glue code (`_start`, `__libc_csu_init`, CRT).
- **Automated Validation**:
  - `uv run scripts/check_deliverables.py --analysis <json_file> --evidence <evidence_file> --schema <schema_file>`:
    Enforces mechanical schema compliance, non-empty fields, address format (`0x...`), and static tool command citations.
- **Headless Decompilation**:
  - Headless IDA Pro MCP or Ghidra for extracting bounded procedure pseudocode.

---

## Core Methodologies & Step-by-Step Technical Workflow

### 1. Mechanical Deliverable Contract Requirements
The deliverable contract mandates two synchronized artifacts:
1. `output/analysis.json`: A bare JSON object (never enclosed in Markdown code fences ` ``` `) conforming strictly to `analysis.schema.json`.
2. `output/evidence.md`: A structured markdown observation ledger containing raw commands, exact instruction addresses (VMA), file offsets, and hex dumps proving every claim asserted in the JSON.

### 2. Strict Schema Field Specifications

The deliverable JSON must strictly adhere to the following field definitions:

```json
{
  "file_type": "ELF64",
  "encoded_strings": true,
  "decoded_c2": "http://192.168.1.100:8080/beacon",
  "c2_protocol": "http",
  "techniques": [
    "XOR string encoding with 1-byte rolling key",
    "Anti-debugging check via ptrace PTRACE_TRACEME"
  ],
  "encryption_details": {
    "algorithm": "AES-128-CBC",
    "key": "2b7e151628aed2a6abf7158809cf4f3c",
    "key_storage": "0x403000 (File Offset: 0x2000)"
  },
  "decoded_strings": [
    "/etc/shadow",
    "cmd.exe /c whoami"
  ],
  "anti_analysis": [
    "ptrace(PTRACE_TRACEME) return check at 0x401120"
  ]
}
```

#### Field Rules & Edge Cases:
- **`file_type`**: Normalized short token (e.g., `ELF64`, `ELF32`, `PE32+`, `PE32`, `Mach-O 64-bit`). Never output a verbose descriptive sentence.
- **`encoded_strings`**: Boolean `true` or `false`. Decide it at the decode site. `true` only when those bytes are readable text. A hex blob, a high-entropy buffer, or a label that looks easier to grade is not a decoded string.
- **`decoded_c2` & `c2_protocol`**: Must be updated as a paired set:
  - If a reachable remote-control endpoint exists: `decoded_c2` must be a non-empty string (`"http://10.0.0.1:443"`) and `c2_protocol` must be one transport token from the task schema's allowed set (commonly `http`/`tcp`/`dns`). Match the exact case the schema's `enum` uses; do not invent a case.
  - If no such endpoint exists or it is unreachable: both fields must be `null`.
- **`techniques`**: Observed behavior with an address in `evidence.md`. Linkage, a compiler, an executable-stack flag, and a section name are build properties, not techniques.
- **`decoded_strings`**: Verified text only. Do not place raw binary hex blobs or unverified garbage here. Use the type the task schema declares, array or object. The example in this file is an array and does not override the schema.
- **`anti_analysis`**: Array of verified anti-analysis or anti-debugging mechanisms. Explicitly note if an anti-analysis routine is unreachable from `main`.
- **`c2_protocol`**: A single transport token from the task schema's `enum`, not a sentence. Use the schema's exact spelling and case. Set it and `decoded_c2` together, or set both to `null`.
- **`decoded_c2`**: The endpoint reconstructed from bytes. `null` only after the application code has been walked and no outbound call and no embedded endpoint remain. "No plaintext in `strings`" is not that walk.
- **`injection_details`**: Only a cross-process primitive (remote thread, remote write, hollowing, APC). Same-process `fork`, `dup2`, or `execve` is not injection. Omit the field when it does not apply.
- **Schema example text**: Never copy an example value from the schema or from this file into the answer. A different file has different bytes.

### 2.1 Reconcile before stopping

1. `file_type` is a family token and matches the first clause of `file`.
2. `encoded_strings` is true only when an instruction you can name rebuilds a string (XOR, add/sub, base64, RC4, AES, a per-byte table). A high-entropy blob with no consumer does not count. Library and `.strtab` / `.debug_*` strings do not count. Plaintext at the use site (`mov` / `lea` of the literal) means false.
3. `encoded_strings: true` implies non-empty `decoded_strings` and an `encryption_details.key` that produces those values. Re-decode once from the file offsets and check they agree.
4. Each `techniques` entry has its own address in `evidence.md`. It is not a build property, not a second name for a call you already listed, and not a value already stored in `decoded_c2` or `encryption_details`.
5. Each JSON value appears in `evidence.md` with the command and an address or file offset, labeled `Observation:` for bytes and `Hypothesis:` for an inference. A negative names the command and the scope that was searched.
6. `output/` holds the two requested files. Re-read both after the last edit, then run `scripts/check_deliverables.py`. `PASS` checks shape. You still check that each value matches the bytes.

### 3. Citing Instruction Addresses, File Offsets, and Hex Dumps in `evidence.md`

`check_deliverables.py` enforces that `evidence.md`:
1. Is at least 200 characters in length.
2. Contains at least one explicit hexadecimal address or offset matching the regex `0x[0-9a-fA-F]+`.
3. Records at least one verified static command invocation. The checker matches these names: `file`, `strings`, `objdump`, `gobjdump`, `readelf`, `nm`, `xxd`, `openssl`. On macOS use `gobjdump` (GNU binutils) or `rabin2`/`otool` output transcribed alongside one of these names.
4. Contains textual traces corresponding to each claim in `techniques` and `anti_analysis`.

#### Required Structure for `evidence.md`
```markdown
# Static Analysis Evidence Ledger

## 1. File Metadata & Identification
- Command: `file sample.bin`
  ```text
  sample.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
  ```
- Command: `readelf -l sample.bin`
  - Base VMA: `0x00000000` (PIE)
  - Entry Point: `0x00001060` (File Offset: `0x00001060`)
  - Load Delta (`vma - file_offset`): `0x0`

## 2. Decoded Endpoint & String Recovery
- Function: `sub_11A0` (VMA: `0x000011A0`, File Offset: `0x000011A0`)
- Decompiled Logic:
  ```c
  // Reads 32 bytes from .rodata at 0x2008 and XORs with 0x5A
  for (i = 0; i < 32; i++) {
      out[i] = enc_buf[i] ^ 0x5a;
  }
  ```
- Command: `xxd -s 0x2008 -l 32 sample.bin`
  ```text
  00002008: 322e 3e3a 7f75 756b 6268 746b 6a68 746e  2.>:..ukbhtkjhtn
  00002018: 606a 606a 2038 3a3a 7538 3f3b 3524 5a5a  `j`j 8::u8?;5$ZZ
  ```
- Decoded Output: `http://192.168.1.100:8080/beacon`

## 3. Anti-Analysis Techniques
- Function: `check_debug` (VMA: `0x00001120`, File Offset: `0x00001120`)
- Disassembly snippet:
  ```assembly
  0x00001120:  mov    edi, 0x0        ; PTRACE_TRACEME
  0x00001125:  xor    esi, esi
  0x00001127:  xor    edx, edx
  0x00001129:  xor    r10d, r10d
  0x0000112c:  call   ptrace@plt
  0x00001131:  cmp    rax, -1
  0x00001135:  je     0x00001140      ; Exit if debugger detected
  ```
```

### 4. Running the Mechanical Deliverable Check

Execute the automated verification script before yielding:

```bash
uv run scripts/check_deliverables.py \
  --analysis output/analysis.json \
  --evidence output/evidence.md \
  --schema analysis.schema.json
```

Verify that the output strictly reports:
```text
RESULT: PASS (structure only; verify observations yourself)
```

---

## Boundaries & Anti-Patterns
- **Do not execute or emulate the target when a static contract is required**: Dynamic observation, hypervisors, and debuggers are strictly prohibited when operating under the static artifact contract.
- **Do not output Markdown fences in `analysis.json`**: The file must be valid, parseable JSON beginning with `{` and ending with `}`.
- **Do not report speculative or ungrounded claims**: Every technique, string, and `decoded_c2` entry in the JSON must cite the exact instruction address and command in `evidence.md`.
