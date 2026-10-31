---
name: reverse-engineering
description: Reverse a shipped binary, package, firmware image, or offline capture. Start with the file header and one matching architecture note. Open a decompiler, dynamic, or lab guide only after that, and only when the task allows it.
metadata:
  version: "66"
---

# Reverse Engineering

Unified reverse engineering skill coordinating format pre-triage, static decompilation, dynamic binary instrumentation, and objective-driven analysis across native and managed targets.

Use this skill when an analytical claim or task depends on analyzing a compiled binary, executable package, firmware image, network capture, or memory dump.

## First actions

This skill is text. No extension runs beside it, so these steps are the same in any agent that can read the file.

The task constraint and the task schema win over every later section, including this file. A static task does not execute, emulate, debug, or contact a host named in the sample.

1. Read the schema, then identify the file with `file` and a bounded header. An ELF file offset is the VMA minus the `PT_LOAD` that covers it. A PE file offset uses that section's own `PointerToRawData`. Disassemble one symbol range after that. Do not dump a whole section. Command bounds are Rule 3.
2. Load one architecture reference from the table below, after the bytes show the format. A path saved in a ledger is not that identification. Rule 2.
3. When the task asks for `analysis.json` and `evidence.md`, open the static artifact contract before drafting either file. That contract owns field meaning. Do not add a second report skill that overrides the schema.
4. Write both files, re-read them after the last edit, and run `scripts/check_deliverables.py` before stopping. A successful write does not show that the JSON parses.
5. Open a dynamic, lab, fuzzing, or mobile section only when the task allows execution. Those sections are under "When the task allows execution".

## Core Reverse Engineering Rules (Pure RE)

Every reverse engineering workflow, regardless of target architecture or execution environment, is strictly governed by 11 binding rules. These operational constraints are authoritative and must be adhered to at every step:

1. **[Triage-First Gate](rules/01-triage-first.md)**:
   - **Mandate**: Invoking any decompiler (IDA Pro, Ghidra), disassembler, or dynamic debugger before a triage manifest (`uv run scripts/auto_triage.py "$ARTIFACT"` JSON plus format headers, saved under `triage` in `re_state.json`) is strictly prohibited.
   - **Enforcement**: Immediate rejection of premature decompilation; triage manifest must confirm SHA-256, format, architecture, toolchain/runtime markers, entropy and packer indicators, and the import/export surface (or its recorded parse failure).

2. **[Progressive Disclosure](rules/02-progressive-disclosure.md)**:
   - **Mandate**: After triage, load strictly the single matching domain reference recommended by the scanner.
   - **Hierarchy**: `01-static-architectures/` (single runtime) $\rightarrow$ `02-dynamic-instrumentation/` (strictly when dynamic analysis is required and authorized) $\rightarrow$ `03-objectives/` (strictly for deliverables and evidence validation).
   - **Prohibition**: Never preload multiple references simultaneously without explicit multi-runtime evidence (e.g. Unity IL2CPP).

3. **[Context Hygiene](rules/03-context-hygiene.md)**:
   - **Mandate**: Dumping raw decompiler pseudocode, large disassembly blocks, full memory maps, or raw trace logs exceeding 300–400 lines into the main conversational context window is strictly forbidden.
   - **Discipline**: Offload full output to `.re_scratch/<func_name>.c` or `.re_scratch/<func_name>.asm`. Retain only the prototype, prologue (50 lines), epilogue (50 lines), critical strings/constants, and direct callees in context. Delegate massive subroutines to bounded subagents. Ghidra projects cannot live under a dot-prefixed directory; keep them in `re_ghidra/` and export into `.re_scratch/`.

4. **[Static ↔ Dynamic Loop](rules/04-static-dynamic-loop.md)**:
   - **Mandate**: Static analysis is foundational and must precede dynamic execution. Transition to dynamic analysis strictly when blocked by heavy packing/encryption (entropy > 7.2), ephemeral runtime values (decrypted buffers, dynamic APIs), or falsifiable hypothesis validation.
   - **Discipline**: Dynamic analysis is an ephemeral probe. Upon capturing runtime data, immediately teardown tracing, re-anchor captured values to static disassembly, rename symbols, define structs, and persist findings to `re_state.json`.

5. **[Dynamic Analysis Discipline](rules/05-dynamic-discipline.md)**:
   - **Mandate**: Dynamic execution runs in non-interactive batch or script mode only: `gdb -batch -x`, `lldb --batch -s`, `frida -l hook.js -q -t 30 --kill-on-exit`, the Frida Python API with a timer, or `ida/re_dbg.py` through ida-mcp. An interactive prompt waiting for input (bare gdb, lldb, cdb, or Frida REPL, x64dbg GUI clicking) is forbidden.
   - **Hard Timeouts**: Every dynamic invocation has a wall-clock bound: `timeout 30 ...` on Linux, Homebrew `timeout`/`gtimeout` or a Python `subprocess` timeout on macOS, `Wait-Job -Timeout` on Windows.
   - **Frida Discipline**: Scripts hook named targets, report through `send()`, call `Interceptor.detachAll()`, then `send({type: "done"})`; the harness detaches and kills (a script cannot exit the process). Under Frida 17, `Java`/`ObjC` exist only in the CLI or when the bridge is bundled. Prefer lightweight memory patching or OEP dumping over prolonged anti-debug stepping.

6. **[State Management](rules/06-state-management.md)**:
   - **Mandate**: Maintain an authoritative JSON state ledger (`re_state.json`) throughout the engagement. Persist state after every significant step rather than relying on volatile conversational context.
   - **Ledger Scope**: Triage manifest summary, active hypotheses with confidence scores, named symbols, recovered struct definitions, critical entry points/dispatchers, and scratch file inventories.

7. **[Hypothesis-Driven Analysis](rules/07-hypothesis-driven.md)**:
   - **Mandate**: Blind line-by-line reading of subroutines without an orienting hypothesis is strictly forbidden.
   - **Discipline**: State an explicit 1–2 sentence falsifiable hypothesis before deep-diving any function: *"This function is hypothesized to be [purpose] because [specific indicators: string xref, callee signature, argument pattern, constants]"*. If the shape matches a field case, test that row first. Conclude by explicitly confirming or refuting the hypothesis based on verified evidence.

8. **[Naming & Documentation](rules/08-naming-documentation.md)**:
   - **Mandate**: Immediately rename generic symbols (`sub_140001020`, `FUN_00401050`, `a1`, `v4`) to domain-accurate semantic identifiers (`decrypt_config`, `verify_license_key`, `p_cipher_buf`) upon determining their purpose.
   - **Documentation**: Declare explicit struct types and add concise inline comments explaining magic constants, bitwise masks, and cryptographic primitives.

9. **[Prohibited Anti-Patterns](rules/09-anti-patterns.md)**:
   - **Strictly Prohibited**:
     1. Direct decompilation of packed binaries (entropy > 7.2) without unpacking.
     2. Preloading references for unverified runtimes "just in case".
     3. Dumping 300+ lines of raw assembly or decompiled code into prompt context.
     4. Running binary or dynamic commands without hard process timeouts.
     5. Disregarding compiler markers (Go `pclntab`, Rust panic handlers, C++ RTTI).
     6. Executing an untrusted sample outside containment, or with live egress.
     7. Treating an exit code of 0, empty output, or a silent scanner as a negative result.
     8. Making capability-negative claims based on packed or sparse import tables.

10. **[Subagent Delegation](rules/10-subagent-delegation.md)**:
    - **Mandate**: Delegate complex, high-volume tasks to dedicated subagents: decompiler output exceeding 400 lines, complex nested data structures/vtables, and heavy algorithmic/crypto reconstruction.
    - **Contract**: Provide clear file boundaries (`.re_scratch/`), specific goals, and explicit non-goals. Subagents return only structured summaries (prototype, logic summary, constants, conclusion) without context flooding.

11. **[Evidence Sufficiency](rules/11-evidence-sufficiency.md)**:
    - **Mandate**: Separate observation, inference, and unknown. Pseudocode is not the instruction. A single decompiler reading stays `candidate`. `validated` needs two independent observations (prefer static plus dynamic, or an equivalence check). A silent tool and a zero exit code are not negatives. Three actions or two stage switches with no new observation is a deadlock: record the dead end and replan.
    - **Negatives**: No sandbox behavior is not "benign" when anti-debug or anti-VM is plausible. A sparse surface is not "no capability" until the thin-surface checks in Rule 1 are recorded. Do not label an ordinary target as malware unless the user asked or the observations show it.



## Pre-Triage & Runtime Detection

Run the automated triage scanner on the target artifact. `scripts/` is relative to this skill's directory (the directory of this `SKILL.md`), not the sample workspace. Lab setup scripts are in that same directory.
```bash
uv run scripts/auto_triage.py "$ARTIFACT"
uv run scripts/elf_triage.py "$ARTIFACT"      # ELF: PT_LOAD map, VMA -> file offset
uv run scripts/elf_symbols.py "$ARTIFACT"     # ELF: entry and symbol spans
```
The triage scanner inspects file magic, sections, and runtime strings to output a normalized JSON classification and recommend the matching domain reference below.

## Progressive Disclosure Reference Architecture

To prevent context window saturation, analysis guidance is partitioned into four hierarchical categories. **Load only the specific reference file required for the identified target architecture, dynamic execution mode, analysis objective, or tool workflow.**

This skill covers reversing domains: native, Go, Rust, .NET, Android, iOS and macOS, Unity, Flutter, React Native, browser JS and extensions, firmware and debug ports, malware containment, protocols, crypto, patch diffing, and fuzzing used as a reversing oracle. It does not absorb penetration testing, Active Directory, cloud or Kubernetes, exploit development, EDR evasion, wireless, email, or SSO. It also does not strip license checks to avoid paying, build cheats for online games, or make malware harder for a defender to recognize. Documenting how a check works is in scope. Unity IL2CPP samples still use the IL2CPP reference.

### 1. Static Architectures (`references/01-static-architectures/`)

| Detected Format / Signatures | Target Architecture & Runtime | Progressive Reference |
|---|---|---|
| ELF / PE / Mach-O with standard C++ RTTI (`.?AV`, `_ZTV`, vtables) | Native C/C++ (MSVC / GCC / Clang ABI, STL) | [01-static-architectures/native-cpp-abi.md](references/01-static-architectures/native-cpp-abi.md) |
| `rust_eh_personality`, `core::panicking`, `.dep-v0`, fat pointers | Native Rust (Fat pointers, Option niche, demangling) | [01-static-architectures/native-rust.md](references/01-static-architectures/native-rust.md) |
| `.gopclntab`, `runtime.morestack`, Go 1.17+ register ABI | Native Go (pclntab recovery, moduledata, goroutines) | [01-static-architectures/native-golang.md](references/01-static-architectures/native-golang.md) |
| `IMAGE_COR20_HEADER`, `BSJB`, JAR, or CIL metadata | Managed .NET & JVM (CIL, JNI, P/Invoke). Android APK decision order is the next row. | [01-static-architectures/managed-dotnet-jvm.md](references/01-static-architectures/managed-dotnet-jvm.md) |
| `.apk`, `.aab`, `AndroidManifest.xml`, `classes.dex` | Android APK (jadx, apktool, packers, handoff to `.so`) | [01-static-architectures/android-apk.md](references/01-static-architectures/android-apk.md) |
| `global-metadata.dat` (`0xFAB11BAF`) + `libil2cpp.so`/`GameAssembly.dll` | Unity IL2CPP (`scripts/il2cpp_tools.py`: il2cpp-dumper-rs, Il2CppInspectorRedux, frida-il2cpp-bridge, Zygisk-Il2CppDumper) | [01-static-architectures/unity-il2cpp.md](references/01-static-architectures/unity-il2cpp.md) |
| Mach-O with `__objc_classlist`, Swift 5 `$s`, IPA package | Apple iOS & macOS Native (ObjC runtime, Swift ABI) | [01-static-architectures/mobile-ios.md](references/01-static-architectures/mobile-ios.md) |
| Web bundles, `app.asar`, WASM (`\0asm`), JS AST | Browser JS & WebAssembly (AST deobf, Wasm-to-C) | [01-static-architectures/browser-js-wasm.md](references/01-static-architectures/browser-js-wasm.md) |
| Flash dumps (`.bin`), SquashFS (`hsqs`), U-Boot (`0x27051956`) | Embedded Firmware & IoT (MIPS/ARM, carving, RTOS) | [01-static-architectures/firmware-iot.md](references/01-static-architectures/firmware-iot.md) |
| `libapp.so`, `libflutter.so`, `isolate_snapshot_data`, Dart AOT | Flutter & Dart AOT (Blutter, snapshot hashes, BoringSSL bypass) | [01-static-architectures/flutter-dart.md](references/01-static-architectures/flutter-dart.md) |
| Hermes bytecode magic `\xC6\x1F\xBC\x03`, `.hbc`, `index.android.bundle` | React Native & Hermes Bytecode (hbctool, hermes-dec, bridges) | [01-static-architectures/react-native-hermes.md](references/01-static-architectures/react-native-hermes.md) |
| CRX magic `Cr24`, `.crx`, `.xpi`, `manifest.json` (`manifest_version`) | Browser Extensions (Chrome MV2/MV3, Firefox, IPC messaging) | [01-static-architectures/browser-extensions.md](references/01-static-architectures/browser-extensions.md) |
| OLLVM/Hikari signatures, control-flow flattening, MBA expressions, anti-debug | Deobfuscation & Anti-Analysis (OLLVM, MBA, Anti-Debug, Anti-VM) | [01-static-architectures/deobfuscation-anti-analysis.md](references/01-static-architectures/deobfuscation-anti-analysis.md) |
| Scripts (.ps1, .bat, .cmd, .vbs, .hta, .wsf) & Office Macros (.docm, .xlsm, OLE) | Non-PE & Script Artifact Deobfuscation (PowerShell, Batch, VBA, WSH) | [01-static-architectures/script-nonpe-analysis.md](references/01-static-architectures/script-nonpe-analysis.md) |
| PyInstaller, Nuitka, Node SEA, Godot `.pck`, Unreal `.pak`, NSIS, Inno, AppImage, or a runtime exe whose logic is a container | Runtimes, engines, and installers. Find the container before disassembling the engine. | [01-static-architectures/runtimes-and-packagers.md](references/01-static-architectures/runtimes-and-packagers.md) |
### 2. Dynamic Instrumentation (`references/02-dynamic-instrumentation/`)

*Use only when dynamic analysis is authorized and executable inside an isolated research VM:*

| Dynamic Technique / Scenario | Target Scope | Progressive Reference |
|---|---|---|
| Native instruction stepping, breakpoints, register inspection | Debugger Workflows (GDB, LLDB, WinDbg, x64dbg) | [02-dynamic-instrumentation/debugger-workflows.md](references/02-dynamic-instrumentation/debugger-workflows.md) |
| Passive function tracing, Java/ObjC hooking, API monitoring | Dynamic Binary Instrumentation (Frida scripts) | [02-dynamic-instrumentation/frida-hooking.md](references/02-dynamic-instrumentation/frida-hooking.md) |
| Packed sections (`UPX0`), high entropy, runtime crypters | Dynamic Unpacking, OEP Detection & Memory Dumping | [02-dynamic-instrumentation/unpacking-memory-dump.md](references/02-dynamic-instrumentation/unpacking-memory-dump.md) |
| Which input reaches a parser, or obfuscation has made the decompiler untrustworthy | Staged deep fuzzing to test a hypothesis and recover logic | [02-dynamic-instrumentation/fuzzing-for-reversing.md](references/02-dynamic-instrumentation/fuzzing-for-reversing.md) |
| HTTP/S APIs, WebSockets, TLS decryption, backend-contract recovery, or a multi-stage client/server channel (desktop, CLI, VM, container, or mobile) | mitmproxy mode choice, CA trust, capture, API map, and lab-only mocks or replay | [02-dynamic-instrumentation/network-traffic-proxy.md](references/02-dynamic-instrumentation/network-traffic-proxy.md) |
| DNS, TCP or UDP sessions, TLS metadata, beacon timing, or a stream the proxy cannot see | Wireshark and tshark from the frame up, then the proxy or the protocol reference | [02-dynamic-instrumentation/network-traffic-proxy.md](references/02-dynamic-instrumentation/network-traffic-proxy.md) |
| Malware detonation, a sandbox report, Docker/VM containment, remote debuggers | Containment, then read the report by its rows rather than by family reputation | [02-dynamic-instrumentation/malware-sandbox-isolation.md](references/02-dynamic-instrumentation/malware-sandbox-isolation.md) |
| Mobile SSL/TLS unpinning (Android OkHttp/TrustManager/WebView/Cronet, iOS SecTrust/NSURLSession, Flutter BoringSSL) | Mobile SSL Pinning Bypass & Proxy Interception | [02-dynamic-instrumentation/network-traffic-proxy.md](references/02-dynamic-instrumentation/network-traffic-proxy.md) |
| Mobile pre-flight verification, KernelSU root emulator, vphone-cli research VM | Mobile environment gate, then host and lab setup | [05-environment/host-and-lab-setup.md](references/05-environment/host-and-lab-setup.md) |
### 3. Objectives & Deliverables (`references/03-objectives/`)

| Analysis Objective | Target Scope | Progressive Reference |
|---|---|---|
| Patch comparison, 1-day vulnerability analysis, CVE research | Vulnerability Research, Patch Analysis & Binary Diffing | [03-objectives/vuln-research-patch.md](references/03-objectives/vuln-research-patch.md) |
| Proprietary protocols, Protobuf, gRPC, network telemetry | Binary Protocol & Network Serialization Recovery | [03-objectives/protocol-recovery.md](references/03-objectives/protocol-recovery.md) |
| Encrypted blobs, S-Boxes, custom crypto, key derivation | Cryptographic Identification & Algorithm Recovery | [03-objectives/algorithm-recovery.md](references/03-objectives/algorithm-recovery.md) |
| Schema-conformant JSON output paired with `evidence.md` | Static Artifact Analysis & Evidence Contract | [03-objectives/static-artifact-contract.md](references/03-objectives/static-artifact-contract.md) |
| A recognizable shape: secret already in the file, real work outside `main`, a per-byte oracle, a custom VM, a lying ELF header, or a decompiler/width mismatch | Field case patterns distilled from shipped reversing cases | [03-objectives/case-patterns.md](references/03-objectives/case-patterns.md) |
| Desktop Qt, WPF, WinForms, Electron, or a native GUI with local storage, IPC, or an updater | Thick-client trust boundary, then the architecture reference for the binary | [03-objectives/thick-client.md](references/03-objectives/thick-client.md) |

### 4. Tool Usage & Deep Execution Guides (`references/04-tool-usage/`)

| Tool & Execution Environment | Scope & Capabilities | Progressive Reference |
|---|---|---|
| IDA Pro 9.x through official Hex-Rays `ida-mcp` | `open_database` + `execute_python` (IDAPython / `ida-domain`), save and close, dbgsrv | [04-tool-usage/ida-pro.md](references/04-tool-usage/ida-pro.md) |
| Driving IDA's remote debugger from an agent through official `ida-mcp` | Bounded `ida/re_dbg.py` helper loaded with `execute_python`: start/attach, step, trace breakpoints, live memory | [04-tool-usage/ida-mcp-remote-debugging.md](references/04-tool-usage/ida-mcp-remote-debugging.md) |
| REA Ghidra Server & Headless Analyzers | Reverse Engineering Assistant (REA), Ghidra headless scripts, decompilation caching | [04-tool-usage/rea-ghidra.md](references/04-tool-usage/rea-ghidra.md) |
| Frida Dynamic Instrumentation Runtime | JavaScript/TypeScript instrumentation, Stalker, memory scanning, Java/ObjC bridges | [04-tool-usage/frida.md](references/04-tool-usage/frida.md) |
| IPSW Apple Firmware Tooling | iOS/macOS kernel cache extraction, DFU images, dyld shared cache extraction, symbols | [04-tool-usage/ipsw.md](references/04-tool-usage/ipsw.md) |
| UTM Hypervisor & Virtualization Orchestration | QEMU/Apple Virtualization framework, ARM64/x86_64 guest VMs, headless guest automation | [04-tool-usage/utm-hypervisor.md](references/04-tool-usage/utm-hypervisor.md) |
| JSHook MCP Browser & Dynamic JS Engine | `@jshookmcp/jshook` 0.4.x (about 735 tools in 36 domains, loaded through `search_tools`/`describe_tool`/`call_tool`), CDP debugging, hooks, network capture, AST deobfuscation | [04-tool-usage/jshook-mcp.md](references/04-tool-usage/jshook-mcp.md) |

### 5. Host And Lab Setup (`references/05-environment/`)

Load this only when the machine or the lab is missing a tool, a rooted device, a proxy CA, or a VM snapshot. It is not an architecture reference.

| Need | Scope | Reference |
|---|---|---|
| Detect the host, install an allowlisted tool, root an Android emulator, install the proxy CA, snapshot UTM, or provision a guest | Host and lab setup | [05-environment/host-and-lab-setup.md](references/05-environment/host-and-lab-setup.md) |

---

## When the task allows execution

Open this section only after the first actions, and only when the task permits running the sample. A static task stops before this section.

## Mandatory Operational Safety Rules & Containment Boundaries

**CRITICAL SAFETY MANDATE**: Any malware analysis, suspicious untrusted binary, runtime crypter/packer, or ANY dynamic analysis/execution MUST NEVER execute directly on the host machine.

All execution, dynamic tracing, unpacking, and instrumentation MUST run exclusively inside strictly isolated execution targets:

1. **Isolated Docker Container**:
   - Baseline: `docker run --rm --network none --cap-drop=ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,exec,size=512m --memory 2g --pids-limit 256 -v "$PWD/sample:/sample:ro" <image>`.
   - A debugger needs `--cap-add=SYS_PTRACE`. Docker's default seccomp profile already allows `ptrace` on kernel 4.8+; use `--security-opt seccomp=unconfined` only when a tool still fails, and record it.
   - Docker on macOS runs inside a Linux VM, so a container is not a Windows or macOS sandbox. Use a VM for PE and Mach-O samples.
   - Network isolation: `--network none`, or an `--internal` bridge that only reaches a fake-net sink container.
2. **Disposable Virtual Machine**:
   - Hypervisor containment: Headless UTM (`utmctl`) on Apple Silicon macOS, KVM/QEMU on Linux, or VMware on Windows.
   - Remote debugger bridge: the guest runs the IDA debug server for its platform (`linux_server`, `armlinux_server`, `win64_remote.exe`, `mac_server_arm`, `android_server`; default port 23946) or `gdbserver`/`lldb-server` on a port you choose. The host debugger connects over the host-only network. UTM "Shared Network" has no port forwarding; use "Emulated VLAN" forwarding or the guest IP. Details: [IDA remote debugging](references/05-environment/ida-remote-debugging.md) and [ida-mcp remote debugging](references/04-tool-usage/ida-mcp-remote-debugging.md).
3. **Network Containment**:
   - Isolated host-only or fake-net sinks (`inetsim`, `mitmproxy`).
   - Non-routable interfaces and DNS sinkholing.
   - ZERO live internet egress for untrusted malware samples.
4. **Snapshot & Auto-Rollback**:
   - Create a clean snapshot before the first run: `uv run scripts/setup_utm.py snapshot-create "$VM" clean` (wraps `utmctl snapshot create "$VM" --name clean`, UTM 5.0.8+).
   - Roll back after capture or on process exit: `uv run scripts/setup_utm.py snapshot-restore "$VM" clean` (`utmctl snapshot restore "$VM" --snapshot clean`). For a one-off run, `uv run scripts/setup_utm.py start-disposable "$VM"` discards guest writes.
   - Older UTM without `utmctl snapshot`: stop the VM and use `uv run scripts/setup_utm.py qcow2-snapshot` (qemu-img on qcow2 disks, QEMU backend only).
5. **Egress Mode**:
   - Record `egress` in `re_state.json` before the first command that can emit a packet: `offline`, `lab_only`, or `authorized_target_only`.
   - Static triage does not resolve recovered domains, and an untrusted sample does not get live internet egress. `offline` and `lab_only` stay inside the containment rules above.

---

## Core Methodologies & Field-Tested Behavior Gates

### 1. User Feasibility Gate
- **Continue when the next step is determined**: Follow [Rule 11](rules/11-evidence-sufficiency.md). One legal next action is taken and handed off in the ledger. Ask only at a real branch or a blocked step.
- **Obey user objective, do not blindly obey execution order**: If the user instructs step X (e.g., "inspect imports") but an obvious blocker exists (e.g., sample is packed and static IAT is garbled/encrypted):
  1. State the exact blocker in one concise sentence.
  2. Propose the recommended sequence (e.g., unpack first, or pivot directly to dynamic API breakpoint monitoring in VM).
  3. Request user confirmation before proceeding.
- **Forced execution handling**: If the user explicitly forces the step on a packed binary, perform the dump and record the evidence, but MUST mark `quality=unreadable` or `quality=packed`. NEVER draw negative capability claims (e.g., "no network capability") from a garbled or encrypted table.
- **Equivalence preservation**: Re-doing step X means re-doing step X (or completing its agreed prerequisite). Do not substitute an unrelated task.

### 2. Import Table Hard Gate & Equivalent Anchors
- **Native PE / ELF / Mach-O**: Must inspect imports (`E-imports` / `E-triage-imports`) via `rabin2 -i`, IDA imports, or decompiler before completing triage or entering dynamic stages.
- **DLL / SYS / Shared Libraries**: Must inspect both imports and exports in parallel (`E-imports` + `E-exports`). The export table is the primary external attack surface and entrypoint.
- **Managed .NET / JVM**: Do not bypass because of "no traditional PE IAT". Must inspect metadata assembly references, P/Invoke imports, and external method tokens (`E-imports` semantic slot).

### 3. Clean Import Warning & Dynamic Resolution Suspect
- If an import table appears suspiciously clean (containing only basic system DLLs like `ntdll.dll` / `kernel32.dll` with few or no business APIs), suspect dynamic runtime resolution via `LoadLibrary` + `GetProcAddress` or API hashing.
- Annotate suspicion in triage evidence and pivot to dynamic API monitoring; never conclude that the sample lacks network or file capabilities based on a sparse static import table.

### 4. High-Risk API Combinations
Filter baseline OS noise (`CreateFile`, `ReadFile`) and prioritize high-risk malicious clusters:
- **Process Injection Cluster**: `FindWindowA/W` / `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`.
- **Ransomware / Wiper Cluster**: `CryptEncrypt` / `CryptAcquireContext` + recursive `FindFirstFile` / `FindNextFile` + `DeleteFile` / `MoveFileWithProgress`.
- **Network & Persistence Cluster**: `InternetOpen` / `WinHttpOpen` / `URLDownloadToFile` + `RegSetValueEx` / `CreateService`.

### 5. IAT Repair Iron Rules & Self-Check Crash Bypass
- **IAT Repair Iron Rule**: When unpacking PE binaries, rebuild imports with Scylla (x86 and x64; also built into x64dbg) or with `pe-sieve /imp 3` on a live process. ImportREC is a legacy 32-bit fallback. If the automated repair tool errors, produces a non-functional binary, or encounters encrypted/VM-protected imports:
  1. Immediately terminate static IAT reconstruction.
  2. Record `E-iat-repair-fail` with tool error details.
  3. Transition immediately to dynamic memory analysis: set API breakpoints or hardware breakpoints in VM to capture resolved APIs at runtime.
- **Self-Check Crash Bypass**: If an unpacked binary crashes immediately upon launch due to embedded file integrity / CRC32 / size checks:
  1. Halt manual binary patching.
  2. Record `E-self-check-crash`.
  3. Transition to dynamic debugging in VM: set breakpoints on `CreateFile`, `GetFileSize`, and hashing routines to locate and bypass the validation check.

### 6. 4-Stage Dynamic Debugger Breakpoint Sequence
When attaching or launching untrusted binaries in a sandboxed debugger (x64dbg / GDB / WinDbg / LLDB):
1. **Stage 1: TLS Callback Breakpoint**: Intercept Thread Local Storage callbacks executed before the main entry point.
2. **Stage 2: Entry Point (EP) Breakpoint**: Halt at the binary OEP/EP.
3. **Stage 3: Sensitive API Breakpoints**: Set software/hardware breakpoints on high-risk APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `WinHttpSendRequest`, `RegSetValueEx`).
4. **Stage 4: ExitProcess / Termination Fallback**: Break on process termination routines (`ExitProcess`, `NtTerminateProcess`, `exit`).
5. **On ExitProcess Dump**: If the process triggers an evasion exit, DO NOT simply restart the debugger. Immediately dump process memory (`dump_memory.py` / MiniDumpWriteDump) to extract decrypted strings, unpacked payloads, and runtime state.

### 7. Timeboxing Heuristics
- **Static Deep-Dive Timebox**: Limit initial static deep-dive to ~15 minutes without finding key paths before transitioning to dynamic instrumentation in VM.
- **Dynamic Instruction Step Timebox**: Limit single-stepping to ~200 instructions without progress before pausing to reset anchors via static string references and cross-references.

### 8. Mobile Environment Pre-Flight Gate & Remediation
Lab provisioning lives in [host and lab setup](references/05-environment/host-and-lab-setup.md). Scripts are in this skill's `scripts/` directory.
- **Mandatory Rooted Environment Pre-Flight Check**:
  Before attempting any mobile dynamic analysis, Frida runtime hooking, memory inspection, or SSL pinning bypass, the agent MUST explicitly verify the presence of an active rooted mobile environment:
  - **Android Target**: Execute `adb shell su -c id`.
    - If the output contains `uid=0(root) gid=0(root)`, root access is confirmed.
    - If `su` is not found, returns permission denied, or returns a non-zero UID, the environment is unrooted.
  - **iOS Target**: Execute `frida-ls-devices` and verify connectivity to the iOS research VM via `vphone-cli status` or SSH (`ssh -p 2222 root@localhost id`).
    - If a jailbroken guest or research VM responds with root access, proceed.
    - If an unrooted iOS Simulator (`xcrun simctl`) or non-jailbroken physical device is detected, dynamic runtime instrumentation is blocked.
- **Mandatory Automated Remediation Bridge**:
  If the target mobile environment is unrooted or absent, the agent MUST NOT attempt unrooted dynamic execution or produce empty analysis reports. Follow [host and lab setup](references/05-environment/host-and-lab-setup.md) and provision an authorized rooted environment:
  - **Android KernelSU Emulator**:
    Invoke the end-to-end setup script to spin up a Google Play arm64-v8a emulator with KernelSU GKI root:
    ```bash
    uv run scripts/setup_android_emulator.py setup-all
    ```
    This script automates downloading the official Google Play arm64-v8a system image, replacing the kernel with KernelSU GKI Linux `Image`, installing KernelSU Manager APK, performing cold boot, waiting for boot completion, and verifying root (`uid=0`).
  - **iOS Rooted Research VM (`vphone-cli`)**:
    On macOS Apple Silicon (`arm64`), follow [host and lab setup](references/05-environment/host-and-lab-setup.md) and spin up a virtual iPhone PCC research VM with the Jailbreak firmware patch (`JB=1`):
    ```bash
    vphone-cli host preflight
    vphone-cli run --profile research-jb
    ```
- **Proxy CA Installation & HTTP Proxy Configuration**:
  Intercepting mobile TLS traffic requires injecting the proxy CA certificate into the system trust store:
  - Run the CA helper from this skill's `scripts/` directory:
    ```bash
    # Verify CA presence and calculate subject hash (<hash>.0)
    uv run scripts/setup_proxy_ca.py status

    # Install CA directly into Android system store via KernelSU OverlayFS module
    uv run scripts/setup_proxy_ca.py install-android

    # Route Android traffic through host mitmproxy instance (default: 10.0.2.2:8080)
    uv run scripts/setup_proxy_ca.py set-android-proxy --host 10.0.2.2 --port 8080

    # Install CA into iOS Simulator / Research VM trust store
    uv run scripts/setup_proxy_ca.py install-ios-sim
    ```
- **Pinning, only after the CA is trusted and a flow still fails**: Read the failure first. A TLS alert after a CONNECT with the system CA installed points at app-level pinning. The decision table, hook targets, and Flutter workflow are in [network-traffic-proxy.md](references/02-dynamic-instrumentation/network-traffic-proxy.md). `uv run scripts/setup_proxy_ca.py export-frida-scripts` writes the starter Frida scripts.

  | Stack | Where the trust decision is | Hook |
  |---|---|---|
  | Android platform TLS | `com.android.org.conscrypt.TrustManagerImpl` | `checkTrustedRecursive` / `verifyChain` return the chain unchanged |
  | OkHttp 3/4 | `okhttp3.CertificatePinner` | `check(String, List)` and OkHttp 4 `check$okhttp` return early |
  | WebView | `WebViewClient.onReceivedSslError` | call `handler.proceed()` |
  | Cronet / Chromium net | native BoringSSL in `libcronet*.so` | native verifier hook, as for Flutter |
  | iOS Security.framework | `SecTrustEvaluateWithError` | set `*error = NULL`, return `true` |
  | iOS URLSession delegate | `URLSession:didReceiveChallenge:completionHandler:` | call the handler with `UseCredential` and `credentialForTrust:` |
  | Flutter (Android/iOS) | static BoringSSL in `libflutter.so` / `Flutter.framework` | force `ssl_crypto_x509_session_verify_cert_chain` to return `1`; Java and ObjC hooks never see Dart sockets, which also ignore the system proxy |

  A hook that forces a return is an experiment. Record which hooks ran and on which host.


## Tool Selection & Capabilities Index

For a full matrix of CLI options, tool strengths, and fallback engines across IDA Pro, Ghidra, radare2, `jshookmcp` (`@jshookmcp/jshook`) for browser/JS reversing, physical memory acquisition tools (Microsoft AVML for Linux, Velocidex WinPmem for Windows), and professional deobfuscation toolchains (JavaScript AST pipelines & `webcrack`, Java/Android `jadx` & `simplify`, .NET `de4dot` & `dnlib`, C/C++ `d810-ng`, `angr`, Z3 MBA simplifier, `VTIL`, `NoVmp`), consult the [Tools Catalog](references/tools-catalog.md).

## Helper Scripts

Executable helper scripts located in `scripts/`:
- `auto_triage.py`: File magic, runtime and packer markers, entropy, SHA-256, and a bounded import/export surface (LIEF). Prints JSON and names the matching reference.
- `dump_memory.py`: Live process memory segment extractor for Linux (`/proc/<pid>/mem`) and macOS core dumper.
- `elf_triage.py`: Program header, segment LOAD delta, and section VMA inspector for ELF binaries.
- `elf_symbols.py`: Application entrypoint and symbol boundary classifier.
- `check_deliverables.py`: Automated JSON schema and evidence ledger verification script.
- `detect_host.py`: Host OS, package manager, and allowlisted tool probe. Installs only when asked.
- `setup_android_emulator.py`: KernelSU-rooted Play emulator.
- `setup_proxy_ca.py`: mitmproxy CA export and install for Android and the iOS Simulator, and the Android proxy setting. Desktop, VM, and runtime trust stores are in the proxy reference.
- `setup_utm.py`: UTM snapshots, disposable start, and QCOW2 helpers.
- `setup_vm.py`: Guest Ansible catalogs for Windows, Linux, and macOS. `setup_windows_vm.py` is the Windows wrapper.
- `ansible/`: Playbooks and tool catalogs used by `setup_vm.py`. Run `setup_vm.py deps --install` once on the host before the first playbook.
- `il2cpp_tools.py`: Unity IL2CPP inputs (`extract`), static dumps (`dump --engine dumper|inspector|both`), and runtime dumps (`bridge-dump`, `zygisk-build`, `zygisk-pull`). All upstream prompts are disabled.
- `ida/il2cpp_import.py`: Applies an il2cpp-dumper-rs `script.json` + `il2cpp.h` to an IDB through `execute_python`, without the upstream file dialogs.
- `ida/re_dbg.py`: IDAPython helper for bounded remote debugging through `ida-mcp` `execute_python`. It runs inside IDA, not through uv.

Every file in `scripts/` is a uv inline script. Run it as `uv run scripts/<name>.py`; uv installs the dependencies listed in the script header.
