# REA & Headless Ghidra Analysis Framework Reference

## 1. Title & Overview
- **Domain**: Automated headless multi-architecture decompilation, static structural binary reconstruction, and artifact inspection using `rea-agents` (`@6.4.0` / `@6.8.0`) and headless Ghidra.
- **Scope**: Command-line interface (CLI) execution, specialized artifact inspection tools (PE, ELF, Go, Rust, IL2CPP, Dart AOT, Android, WASM), JavaScript/Electron application reconstruction, and formal verification evidence workflows (Obligation Ledgers and Evidence Export).

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when:
- Performing batch or automated reverse engineering across Linux ELF, Windows PE, macOS Mach-O, WebAssembly, or embedded firmware without GUI overhead.
- Analyzing modern compiled languages with specialized runtimes: Go (recovering types, pclntab), Rust (demangling, panic unwinding), Unity IL2CPP (`global-metadata.dat`), or Flutter/Dart AOT snapshots (`libapp.so`).
- Reconstructing obfuscated or bundled Electron / JavaScript applications from ASAR packages.
- Tracking formal reverse engineering claims where every assumption, observed finding, and unknown must be retained in an audit ledger.

---

## 3. Tooling & CLI/MCP Actions

### REA CLI Package Execution
REA is executed natively via `rea` or through `npx`:
```bash
# Direct binary execution
rea --version

# On-demand execution with pinned release
npx -y rea-agents@6.4.0 <subcommand> [flags]
npx -y rea-agents@6.8.0 <subcommand> [flags]
```

### Core CLI Commands (`rea analyze`, `rea decompile`, `rea function`, `rea search`, `rea xrefs`)

| Command | Key Arguments | Purpose | Output Format |
|---|---|---|---|
| `rea analyze` | `<binary_path> [--engine ghidra] [--timeout 300]` | Ingests binary, identifies architecture/endianness, performs auto-analysis, and generates baseline artifact evidence. | JSON Evidence Record |
| `rea decompile` | `<binary_path> --target <addr_or_symbol>` | Invokes headless Ghidra decompiler to produce normalized C pseudocode for the target function. | UTF-8 C Pseudocode |
| `rea function` | `<binary_path> --target <addr_or_symbol> [--include-cfg]` | Extracts detailed function dossier: basic blocks, register allocation, local variables, and cyclomatic complexity. | JSON Function Dossier |
| `rea search` | `<binary_path> --pattern <regex_or_literal> [--kind string\|bytes]` | Scans binary sections for literal strings, regex patterns, or instruction byte signatures. | JSON Match Offsets |
| `rea xrefs` | `<binary_path> --target <addr> [--direction to\|from]` | Queries cross-reference graph for inbound callers/readers or outbound call sites/data references. | JSON Xref List |

---

## 4. Inspection Tool Suite

REA provides target-free and offline inspection engines that analyze binary metadata and language-specific runtime structures without requiring a full disassembler database:

### 1. `inspect-binary-layout`
- **Target**: Linux ELF binaries.
- **Mechanism**: Parses ELF headers, Program Headers (PT_LOAD, PT_DYNAMIC), Section Headers, dynamic relocations (`.rela.plt`, `.rela.dyn`), and static security mitigations (NX, PIE, Canaries, RELRO).
- **CLI Example**:
  ```bash
  rea inspect-binary-layout ./target_elf --json > layout.json
  ```

### 2. `inspect-pe-imports` & `inspect-pe-resources`
- **Target**: Windows PE32 / PE32+ (x86, x64, ARM64).
- **Mechanism**: Analyzes Import Directory Tables, Delayed Import Tables, Export Tables, and the PE Resource Tree (`RT_MANIFEST`, `RT_VERSION`, icon groups, dialogs). Decodes UTF-16 strings, code pages, and embedded payload hashes.
- **CLI Example**:
  ```bash
  rea inspect-pe-imports ./target.exe --json
  rea inspect-pe-resources ./target.exe --json
  ```

### 3. `inspect-elf-notes`
- **Target**: Linux ELF executables, shared libraries, and core crash dumps.
- **Mechanism**: Parses ELF Note segments (`PT_NOTE`, `.note.gnu.build-id`, `.note.ABI-tag`, crash registers, signal data).
- **CLI Example**:
  ```bash
  rea inspect-elf-notes ./crash.core --json
  ```

### 4. `inspect-go-binary`
- **Target**: Stripped or unstripped Go executables (ELF, PE, Mach-O).
- **Mechanism**: Locates and parses the Go runtime metadata structure `runtime.pclntab` (PC Line Table). Recovers original function names, source file paths, line numbers, and interface type definitions even in stripped binaries.
- **CLI Example**:
  ```bash
  rea inspect-go-binary ./target_go_service --json
  ```

### 5. `inspect-rust-binary`
- **Target**: Compiled Rust binaries.
- **Mechanism**: Demangles Rust v0 and legacy symbol hashing (`_RNv...` and `_ZN...`), parses panic string tables, unwind tables (`.eh_frame`), and identifies bundled crates via Cargo metadata embedded in strings.
- **CLI Example**:
  ```bash
  rea inspect-rust-binary ./rust_daemon --json
  ```

### 6. `inspect-il2cpp-metadata`
- **Target**: Unity IL2CPP mobile/desktop builds.
- **Mechanism**: Correlates the compiled native binary (`libil2cpp.so` or `GameAssembly.dll`) with the metadata file (`global-metadata.dat`). Recovers Class definitions, method signatures, field offsets, and string literals.
- **CLI Example**:
  ```bash
  rea inspect-il2cpp-metadata --binary ./libil2cpp.so --metadata ./global-metadata.dat --json
  ```

### 7. `inspect-dart-aot`
- **Target**: Flutter / Dart AOT compilation snapshots (`libapp.so`).
- **Mechanism**: Parses the Dart AOT Snapshot header, heap objects, and code tables to extract Dart classes, method entrypoints, and string tables.
- **CLI Example**:
  ```bash
  rea inspect-dart-aot ./libapp.so --json
  ```

### 8. `inspect-android-package`
- **Target**: Android APK, APKS, AAB, and raw DEX files.
- **Mechanism**: Reads `AndroidManifest.xml` (permissions, exported activities, intent filters, services), parses DEX class pools, identifies native `.so` libraries, and flags debuggable/backup flags.
- **CLI Example**:
  ```bash
  rea inspect-android-package ./target_app.apk --json
  ```

### 9. `inspect-wasm-artifact`
- **Target**: WebAssembly modules (`.wasm`).
- **Mechanism**: Parses WASM binary format sections: Type, Function, Table, Memory, Global, Export, Start, Element, Code, and Custom sections (Name section for recovered function names).
- **CLI Example**:
  ```bash
  rea inspect-wasm-artifact ./core_logic.wasm --json
  ```

---

## 5. JavaScript / Electron Static Reconstruction

REA reconstructs Electron applications and bundled Node.js packages by unpacking archives, restoring AST representations, and analyzing IPC communications.

### Core Analysis Commands
1. **Analyze Application Structure**:
   ```bash
   rea analyze-javascript-application /path/to/app.asar --json > app-evidence.json
   ```
2. **Export Extracted Web Scripts**:
   ```bash
   rea export-web-scripts /path/to/app.asar --output-dir ./extracted_scripts/
   ```
3. **Recover Original JavaScript / TypeScript Sources**:
   ```bash
   rea recover-javascript-sources /path/to/app.asar --extract-source-maps --output-dir ./recovered_src/
   ```

### Technical Workflow for Electron Reversal
1. **ASAR Unpacking & Module Indexing**:
   - The CLI parses the ASAR header (JSON string specifying file offsets and byte lengths).
   - Module boundaries are cataloged with roles: `entrypoint`, `preload`, `renderer`, `background`.
2. **IPC Channel Mapping**:
   - Identifies `ipcRenderer.send`, `ipcRenderer.invoke`, and matching `ipcMain.on`, `ipcMain.handle` listeners.
   - Generates a bidirectional IPC communication matrix identifying exposed native desktop capabilities.
3. **Source Map Recovery**:
   - If `.map` files or inline `//# sourceMappingURL=data:application/json;base64,...` are present, REA decodes the VLQ-encoded mappings and restores the original directory structure and variable names.

---

## 6. Evidence Workflows & Reconstruction Obligation Ledger

REA enforces a rigorous evidence model to prevent hallucinated conclusions during automated reversing.

### Evidence Model Principles
- **Normalized Result**: Every inspection returns an `evidence_id` (e.g. `ev_7f9c2a1e`) tied to immutable file hashes.
- **Observation vs Inference**: Facts directly read from bytes are tagged as `observation`; deduced abstractions are tagged as `inference`.
- **Preservation of Unknowns**: If a symbol cannot be resolved or an architecture cannot be decompiled, REA records an explicit `unknown` instead of omitting or guessing.

### The Reconstruction Obligation Ledger
When reversing a proprietary protocol, binary algorithm, or proprietary file format, REA tracks progress using an Obligation Ledger:
```bash
# Initialize reconstruction ledger from analysis evidence
rea build-reconstruction-obligation-ledger \
  --evidence app-evidence.json \
  --scope "NetworkProtocolVerification" \
  --output ledger.json
```

**Ledger Fields**:
- `claim_id`: Unique identifier for the behavioral claim (e.g. `AUTH-001`).
- `specification`: Formal description of the claimed behavior (e.g. "Payload is encrypted using AES-256-GCM with a dynamic salt derived from timestamp").
- `status`: `unverified` | `supported` | `refuted` | `blocked`.
- `supporting_evidence`: List of `evidence_id` and memory addresses grounding the claim.
- `unresolved_questions`: Explicit ambiguities remaining to be verified.

### Evidence Export
Consolidate findings into a portable evidence bundle for downstream verification or audit compliance:
```bash
rea evidence-export \
  --ledger ledger.json \
  --include-pseudocode \
  --include-artifacts \
  --output final_evidence_bundle.tar.gz
```

---

## 7. Concrete Step-by-Step Technical Workflow

### End-to-End Triage of a Stripped Go Binary
```bash
# 1. Inspect binary layout and mitigation policies
rea inspect-binary-layout ./target_service --json > layout.json

# 2. Extract Go pclntab metadata and symbols
rea inspect-go-binary ./target_service --json > go_meta.json

# 3. Locate entrypoint and main package functions from go_meta.json
cat go_meta.json | jq '.functions[] | select(.name | contains("main."))'

# 4. Decompile target cryptographic or protocol handling function
rea decompile ./target_service --target "main.handleEncryptedPayload" > handle_payload.c

# 5. Extract cross-references to key encryption tokens
rea xrefs ./target_service --target "main.aesKey" --direction to --json > xrefs.json

# 6. Build evidence ledger to verify protocol claims
rea build-reconstruction-obligation-ledger \
  --evidence go_meta.json \
  --scope "PacketEncryption" \
  --output protocol_ledger.json
```

---

## 8. Boundaries & Anti-Patterns
- **Do not treat Ghidra pseudocode as compiling C source**: Pseudocode is an analysis observation; register allocation artifacts and pointer arithmetic must be cross-checked against raw disassembly.
- **Do not re-run expensive decompilation for paginated inspection**: When an `evidence_id` is already generated, use `inspect-analysis-view` to query specific modules or symbols rather than re-triggering Ghidra.
- **Do not confuse static differences with dynamic execution paths**: In multi-module applications, the presence of code does not prove it is reachable; dynamic confirmation via tracing is required before marking obligations as `supported`.
