# Reverse Engineering Tools Catalog & Capability Index

- **Domain**: Comprehensive tooling index, capabilities, command invocations, and selection matrix for reverse engineering across static decompilers, dynamic instrumentation, managed runtimes, hypervisors, and specialized utilities.
- **Scope**: Systematic cross-referencing to the tool guides in `04-tool-usage/`, the architecture references in `01-static-architectures/`, the dynamic workflows in `02-dynamic-instrumentation/`, and the objective guides in `03-objectives/`. Clear operational guidance on headless vs interactive tool execution, containment boundaries, and sandboxing infrastructure.
---

## Tool Selection Matrix

| Artifact / Research Objective | Primary Tool | Secondary / Fallback | Reference & Implementation Route |
|---|---|---|---|
| **Headless Native Decompilation (PE/ELF/Mach-O)** | IDA Pro through the official Hex-Rays `ida-mcp` | Ghidra via REA (`rea-agents`), Binary Ninja | [04-tool-usage/ida-pro.md](04-tool-usage/ida-pro.md) |
| **Multi-Architecture Headless RE** | Ghidra via REA CLI/MCP (`rea-agents@6.8.0`) | IDA Pro, radare2 | [04-tool-usage/rea-ghidra.md](04-tool-usage/rea-ghidra.md) |
| **Dynamic Binary Instrumentation (DBI)** | Frida (`frida-tools` CLI / REA Frida) | `frida-trace`, QEMU trace | [04-tool-usage/frida.md](04-tool-usage/frida.md) & [02-dynamic-instrumentation/frida-hooking.md](02-dynamic-instrumentation/frida-hooking.md) |
| **Apple Firmware & iOS Binaries** | `blacktop/ipsw` & `vphone-cli` Research VM | IDA Pro, `class-dump` | [04-tool-usage/ipsw.md](04-tool-usage/ipsw.md) & [01-static-architectures/mobile-ios.md](01-static-architectures/mobile-ios.md) |
| **VM Sandboxing & Snapshots** | UTM / QEMU via `utmctl` & `setup_utm.py` | Virtualization.framework, Docker | [04-tool-usage/utm-hypervisor.md](04-tool-usage/utm-hypervisor.md) |
| **Instruction-Level Debugging** | GDB (pwndbg/gef), LLDB, WinDbg | x64dbg (Windows GUI) | [02-dynamic-instrumentation/debugger-workflows.md](02-dynamic-instrumentation/debugger-workflows.md) |
| **Process Unpacking & User Memory Dumps** | `dump_memory.py`, Scylla, PE-sieve | `procdump`, `gcore` | [02-dynamic-instrumentation/unpacking-memory-dump.md](02-dynamic-instrumentation/unpacking-memory-dump.md) |
| **Fuzzing as a reversing oracle** | AFL++ (`-Q` or a persistent harness), libFuzzer | honggfuzz, WinAFL, Jackalope | [02-dynamic-instrumentation/fuzzing-for-reversing.md](02-dynamic-instrumentation/fuzzing-for-reversing.md) |
| **Physical Memory Acquisition & Forensics** | Microsoft AVML (Linux), Velocidex WinPmem (Windows) | `dump_memory.py`, LiME, LiMEide | [02-dynamic-instrumentation/unpacking-memory-dump.md](02-dynamic-instrumentation/unpacking-memory-dump.md) & [02-dynamic-instrumentation/malware-sandbox-isolation.md](02-dynamic-instrumentation/malware-sandbox-isolation.md) |
| **Network Traffic Proxy & Interception** | `mitmproxy` / `mitmdump`, `setup_proxy_ca.py` | `tshark`, `dumpcap`, Wireshark display filters via `tshark -Y` | [02-dynamic-instrumentation/network-traffic-proxy.md](02-dynamic-instrumentation/network-traffic-proxy.md) |
| **Vulnerability & Patch Diffing** | BinDiff | Ghidra BSim, Diaphora, radiff2 | [03-objectives/vuln-research-patch.md](03-objectives/vuln-research-patch.md) |
| **Protocol & Serialization Recovery** | `protoc --decode_raw`, `blackboxprotobuf`, `tshark` | `protodump`, `pbtk`, Kaitai Struct, Scapy, `grpcurl` | [03-objectives/protocol-recovery.md](03-objectives/protocol-recovery.md) |
| **Cryptographic Algorithm Recovery** | `yr`/`yara` with FindCrypt rules, `capa` | `signsrch`, Ghidra FindCrypt, Python `pycryptodome`, CyberChef | [03-objectives/algorithm-recovery.md](03-objectives/algorithm-recovery.md) |
| **Static Artifact Contract Validation** | `elf_triage.py`, `check_deliverables.py` | Headless IDA Pro / Ghidra | [03-objectives/static-artifact-contract.md](03-objectives/static-artifact-contract.md) |
| **C++ ABI / Vtables / Name Mangling** | IDA Pro / Ghidra C++ plugin | `c++filt`, demangler scripts | [01-static-architectures/native-cpp-abi.md](01-static-architectures/native-cpp-abi.md) |
| **Go Native Binaries** | `rea inspect-go-binary`, IDAGolangHelper | `redress` | [01-static-architectures/native-golang.md](01-static-architectures/native-golang.md) |
| **Rust Compiled Binaries** | `rea inspect-rust-binary`, `rustfilt` | IDA Pro Rust FLIRT | [01-static-architectures/native-rust.md](01-static-architectures/native-rust.md) |
| **Managed .NET / CIL Assemblies** | `ilspycmd`, `dnSpy` | `de4dot`, Ghidra | [01-static-architectures/managed-dotnet-jvm.md](01-static-architectures/managed-dotnet-jvm.md) |
| **Java / Android DEX / APK** | `jadx --deobf`, `apktool` | Smali, `androguard` | [01-static-architectures/android-apk.md](01-static-architectures/android-apk.md) |
| **Unity IL2CPP Bundles** | il2cpp-dumper-rs and Il2CppInspectorRedux via `scripts/il2cpp_tools.py dump` | frida-il2cpp-bridge (`bridge-dump`), Zygisk-Il2CppDumper (`zygisk-build`), `rea inspect-il2cpp-metadata` | [01-static-architectures/unity-il2cpp.md](01-static-architectures/unity-il2cpp.md) |
| **JavaScript / Electron / WebAssembly** | `jshookmcp` (`@jshookmcp/jshook`), `rea analyze-javascript-application`, `wasm2wat` | `npx @electron/asar extract`, `webcrack` | [04-tool-usage/jshook-mcp.md](04-tool-usage/jshook-mcp.md) & [01-static-architectures/browser-js-wasm.md](01-static-architectures/browser-js-wasm.md) |
| **Embedded Firmware / IoT** | `binwalk` (v3, `-e` extract, `-E` entropy), `unblob` | `ubi_reader`, `jefferson`, `sasquatch`, QEMU user/system, OpenOCD | [01-static-architectures/firmware-iot.md](01-static-architectures/firmware-iot.md) |
| **Malware Sandboxing & Isolation** | Docker (`--cap-drop=ALL`), UTM/QEMU (`utmctl`) | INetSim, mitmproxy sinkhole | [02-dynamic-instrumentation/malware-sandbox-isolation.md](02-dynamic-instrumentation/malware-sandbox-isolation.md) |
| **OLLVM Deobfuscation & Anti-Analysis** | `d810-ng`, `obpo-plugin`, Z3 SMT | `ollvm-unflattener`, `ollvm-breaker` | [01-static-architectures/deobfuscation-anti-analysis.md](01-static-architectures/deobfuscation-anti-analysis.md) |
| **C / C++ Native Deobfuscation & Devirtualization** | `d810-ng`, `angr` deflat, Z3 MBA simplifier | `VTIL`, `NoVmp`, Triton | [01-static-architectures/deobfuscation-anti-analysis.md](01-static-architectures/deobfuscation-anti-analysis.md) |
| **JavaScript & Web Bundle Deobfuscation** | `jshookmcp` (AST transforms & JSVMP devirtualization), `webcrack`, Babel AST | JSVMP CDP tracer, `wakaru` (Rust CLI); `synchrony`/`deobfuscator` only as a last resort, it breaks current javascript-obfuscator output | [04-tool-usage/jshook-mcp.md](04-tool-usage/jshook-mcp.md), [01-static-architectures/browser-js-wasm.md](01-static-architectures/browser-js-wasm.md) & [01-static-architectures/browser-extensions.md](01-static-architectures/browser-extensions.md) |
| **Java / Android Bytecode Deobfuscation** | `jadx` deobf, `simplify` | `dex-oracle`, Frida string dumping, Smali | [01-static-architectures/android-apk.md](01-static-architectures/android-apk.md) |
| **C# / .NET Deobfuscation & Devirtualization** | `de4dot`, `de4dot-cex` | `dnlib` automated cleaning, KoiVM devirtualizer, `AsmResolver` | [01-static-architectures/managed-dotnet-jvm.md](01-static-architectures/managed-dotnet-jvm.md) |
| **Non-PE / Script Artifact Deobfuscation** | `oledump.py`, `olevba`, `xlmdeobf`, AST tools | `scrdec`, PowerShell Parser | [01-static-architectures/script-nonpe-analysis.md](01-static-architectures/script-nonpe-analysis.md) |
---

## Headless vs Interactive Tool Execution

Autonomous agents operate under strict constraints regarding user interaction, screen rendering, and process timeouts. Choosing the correct execution modality is vital:

### Headless Execution (Autonomous Agent Primary Mode)
- **Hex-Rays IDA Pro 9.x**:
  - Run only through the official Hex-Rays MCP server (`ida-mcp` via stdio or streamable HTTP): `open_database`, then IDAPython or `ida-domain` code in `execute_python`.
  - Automate batch tasks using IDAPython in headless mode: `ida -A -S"script.py" target.bin`.
  - See detailed workflows in [04-tool-usage/ida-pro.md](04-tool-usage/ida-pro.md).
- **Ghidra**:
  - Execute via REA (`rea-agents`) headless CLI commands (`rea analyze`, `rea decompile`) or Ghidra `analyzeHeadless`.
  - See detailed workflows in [04-tool-usage/rea-ghidra.md](04-tool-usage/rea-ghidra.md).
- **Network & Dynamic Proxies**:
  - Run `mitmdump` headlessly with Python script addons instead of the curses-based `mitmproxy` GUI.
  - Run `tshark` with `-T fields` or `--export-objects` instead of opening the Wireshark GUI.
- **Hypervisors & Sandboxes**:
  - Manage guest VMs via `utmctl` CLI or `setup_utm.py` without requiring GUI mouse/keyboard interactions.
  - See detailed workflows in [04-tool-usage/utm-hypervisor.md](04-tool-usage/utm-hypervisor.md).
- **Browser & Dynamic JS Reversing (`jshookmcp`)**:
  - Execute headlessly via `@jshookmcp/jshook` MCP server or standalone HTTP daemon (`http://127.0.0.1:3000/mcp`).
  - Uses token-efficient `MCP_TOOL_PROFILE=search` with meta-tools (`search_tools`, `describe_tool`, `call_tool`) to control CDP, dynamically hook JS, devirtualize JSVMP, and trace V8 TurboFan without browser UI.
  - See detailed workflows in [04-tool-usage/jshook-mcp.md](04-tool-usage/jshook-mcp.md).

### Interactive Execution (Human or Computer-Use Fallback)
- **x64dbg / Scylla**:
  - Utilized for Windows PE dynamic unpacking and visual IAT repair when complex anti-debugging mechanisms defeat automated CLI unpackers.
- **Wireshark GUI**:
  - Utilized for visual packet relationship inspection and interactive stream following when protocol framing is completely unknown.
- **IDA Pro GUI**:
  - Utilized via computer-use or human operator when interactive graph manipulation, complex manual structure definitions, or visual debugger stepping is required.

---

## Tool Capabilities & Invocation Reference

### 1. IDA Pro (official Hex-Rays `ida-mcp`)
- **Capabilities**: Industry-standard decompilation across x86, x64, ARM, ARM64, MIPS, PowerPC; FLIRT library signatures; full type propagation; remote debugging through `linux_server`, `armlinux_server`, `mac_server_arm`, and `win64_remote.exe`.
- **Primary Tool Reference**: [04-tool-usage/ida-pro.md](04-tool-usage/ida-pro.md); debugger sessions: [04-tool-usage/ida-mcp-remote-debugging.md](04-tool-usage/ida-mcp-remote-debugging.md)
- **Tools**: `open_database`, `execute_python`, `reference`, `list_databases`, `save_database`, `close_database`. Pseudocode, disassembly, strings, xrefs, renames, types, and comments are all IDAPython or `ida-domain` code inside `execute_python`; call `reference(query)` before guessing an `ida-domain` API.
- **Transports**:
  - Stdio: `ida-mcp stdio --agent=re-agent --idle-timeout=900 --database /path/to/binary_or_idb`
  - Streamable HTTP: `ida-mcp http --host 127.0.0.1 --port 8737 --database /path/to/target.i64`

### 2. REA Ghidra Multi-Architecture Suite (`rea-agents`)
- **Capabilities**: Automated headless decompilation, specialized binary layout inspection (`inspect-go-binary`, `inspect-rust-binary`, `inspect-il2cpp-metadata`), and JavaScript/Electron source recovery.
- **Primary Tool Reference**: [04-tool-usage/rea-ghidra.md](04-tool-usage/rea-ghidra.md)
- **CLI Invocations**:
  ```bash
  rea analyze "$BIN" --provider ghidra
  rea decompile-all "$BIN" --output "$OUT" --resume
  rea inspect-go-binary "$BIN" --format json
  ```

### 3. Frida Dynamic Binary Instrumentation Framework
- **Capabilities**: Real-time function hooking, memory reading/writing, object dumping, SSL/TLS certificate pinning bypass across Linux, Windows, macOS, Android, and iOS.
- **Primary Tool Reference**: [04-tool-usage/frida.md](04-tool-usage/frida.md) & [02-dynamic-instrumentation/frida-hooking.md](02-dynamic-instrumentation/frida-hooking.md)
- **CLI Invocations**:
  ```bash
  frida -U -f com.example.app -l hooks.js
  frida -p <pid> -l trace.js
  ```

### 4. Apple Firmware & iOS Reverse Engineering (`ipsw`)
- **Capabilities**: iOS/macOS firmware package analysis, kernelcache decryption, dyld shared cache splitting, kext extraction, and integration with `vphone-cli` rooted research VMs.
- **Primary Tool Reference**: [04-tool-usage/ipsw.md](04-tool-usage/ipsw.md) & [01-static-architectures/mobile-ios.md](01-static-architectures/mobile-ios.md)
- **CLI Invocations**:
  ```bash
  ipsw download --device iPhone15,2
  ipsw kernel dec <kernelcache>
  ipsw dyld split <dyld_shared_cache> <out_dir>
  ```

### 5. UTM Hypervisor & Snapshot Management (`utmctl`)
- **Capabilities**: Isolated VM sandboxing on Apple Silicon macOS, disposable VM runs, QCOW2 internal and CoW overlay snapshots, and automated remote port forwarding.
- **Primary Tool Reference**: [04-tool-usage/utm-hypervisor.md](04-tool-usage/utm-hypervisor.md)
- **CLI Invocations**:
  ```bash
  utmctl list
  utmctl start <vm_name>
  utmctl snapshot <vm_name> create <snap_name>
  ```

### 6. JADX (Java & Android Decompiler)
- **Capabilities**: High-fidelity decompilation of Dalvik `.dex` bytecode, APK packages, AAB bundles, and JAR files into readable Java source with automatic deobfuscation.
- **Primary Tool Reference**: [01-static-architectures/android-apk.md](01-static-architectures/android-apk.md). DEX and JNI internals: [01-static-architectures/managed-dotnet-jvm.md](01-static-architectures/managed-dotnet-jvm.md).
- **CLI Invocation**:
  ```bash
  jadx --deobf -d /tmp/apk_decompiled/ sample.apk
  ```

### 7. ILSpy & dnSpy (.NET CIL Decompilation)
- **Capabilities**: Decompilation of managed .NET PE assemblies directly into readable C# source code, metadata token inspection, and asset recovery.
- **Primary Tool Reference**: [01-static-architectures/managed-dotnet-jvm.md](01-static-architectures/managed-dotnet-jvm.md)
- **CLI Invocation**:
  ```bash
  ilspycmd -p -o /tmp/dotnet_src/ Assembly.dll
  ```

### 8. JSHook MCP (`@jshookmcp/jshook`)
- **Capabilities**: Over 600 specialized reverse engineering tools organized across 34 capability domains; lightweight search-first profile (`MCP_TOOL_PROFILE=search`, ~3k tokens) with discovery meta-tools (`search_tools`, `describe_tool`, `call_tool`, `coverage_report`); CDP browser automation and session management; dynamic function/method hooking and parameter/return value tampering; JSVMP (JavaScript Virtual Machine Protection) bytecode recording and devirtualization; AST deobfuscation pipelines (`JScramblerDeobfuscator`, `VMDeobfuscator`, `PackerDeobfuscator`); V8 TurboFan graph generation, deoptimization tracing, and allocation tracking; WebAssembly GC inspection, disassembly, and memory forensics (`HardwareBreakpoint`, `MemoryScanner`, `PointerChainEngine`); BoringSSL interceptor and WebSocket frame capture.
- **Primary Tool Reference**: [04-tool-usage/jshook-mcp.md](04-tool-usage/jshook-mcp.md) & [01-static-architectures/browser-js-wasm.md](01-static-architectures/browser-js-wasm.md)
- **MCP & Tool Invocations** (these are MCP tool calls, not JSON documents; the argument object of each call is JSON):
  ```text
  # 1. Search available tools by keyword/intent in search profile
  search_tools      arguments: {"query": "xhr breakpoint"}

  # 2. Inspect exact parameter schema before calling
  describe_tool     arguments: {"tool_name": "break_on_xhr"}

  # 3. Dynamic execution via meta-tool
  call_tool         arguments: {"tool_name": "break_on_xhr",
                                 "arguments": {"url_pattern": "/api/v1/auth"}}
  ```
  ```bash
  # Standalone HTTP daemon execution mode (optional for multi-client sharing)
  npx -y @jshookmcp/jshook@0.3.5 daemon --port 3000
  ```

### 9. BinDiff & Diaphora (Binary Differencing)
- **Capabilities**: Graph isomorphism matching of control flow graphs, AST-based function diffing, 1-day patch identification, and symbol name porting.
- **Primary Tool Reference**: [03-objectives/vuln-research-patch.md](03-objectives/vuln-research-patch.md)
- **CLI Invocation**:
  ```bash
  bindiff --primary=v1.BinExport --secondary=v2.BinExport --output_dir=/tmp/diff/
  ```

### 10. Microsoft AVML (Acquire Volatile Memory for Linux)
- **Capabilities**: Portable, static Rust binary for user-space volatile memory capture on Linux; automatically detects memory acquisition source (`/proc/kcore`, `/dev/crash`, or `/dev/mem`); supports inline LZ4/LiME compression and optional direct HTTP/blob upload without writing uncompressed raw dumps to disk.
- **Primary Tool Reference**: [02-dynamic-instrumentation/unpacking-memory-dump.md](02-dynamic-instrumentation/unpacking-memory-dump.md) & [02-dynamic-instrumentation/malware-sandbox-isolation.md](02-dynamic-instrumentation/malware-sandbox-isolation.md)
- **CLI Invocations & Modes**:
  ```bash
  # Acquire compressed LiME memory image (recommended standard mode)
  sudo avml --compress /tmp/mem.lime

  # Uncompressed raw physical memory acquisition
  sudo avml /tmp/mem.raw

  # Force explicit memory source (/proc/kcore vs /dev/crash)
  sudo avml --source /proc/kcore /tmp/mem.raw

  # Stream compressed acquisition directly to cloud storage URL
  sudo avml --compress --url "https://storage.blob.core.windows.net/evidence/mem.lime?sas_token..."
  ```

### 11. Velocidex WinPmem (Physical Memory Acquisition for Windows)
- **Capabilities**: High-performance physical RAM acquisition tool for Windows NT (x86 and x64); dynamically extracts and loads signed kernel driver (`winpmem.sys`); provides multiple acquisition modes (`MmMapIoSpace`, `\Device\PhysicalMemory`, and PTE page remapping) and Microsoft Crash Dump output generation.
- **Primary Tool Reference**: [02-dynamic-instrumentation/unpacking-memory-dump.md](02-dynamic-instrumentation/unpacking-memory-dump.md)
- **CLI Invocations & Modes**:
  ```cmd
  :: Mode 1: MmMapIoSpace kernel API acquisition (standard / legacy mode)
  winpmem.exe -o mem.raw --mode 1

  :: Mode 2: \\.\PhysicalMemory section object acquisition
  winpmem.exe -o mem.raw --mode 2

  :: Mode 3: Direct PTE remapping bypass (fastest, bypassing hypervisor/API restrictions)
  winpmem.exe -o mem.raw -m 3

  :: Generate Microsoft Crash Dump (PAGE_DUMP / crash.dmp) for WinDbg analysis
  winpmem.exe -o crash.dmp -m 3 --volume_mode 2

  :: Extract embedded winpmem driver without capturing memory
  winpmem.exe -e winpmem.sys
  ```
---

## Install Commands By Platform

Verify a tool is absent before installing (`command -v <tool>`). On this macOS host, `r2`/`rabin2`/`radiff2`/`rafind2`, `tshark`, `protoc`, `buf`, `mitmdump`, `frida`, `node`, `go`, `cargo`, `uv`, `yr` (yara-x) are already present. Prefer `uv tool install` / `uv run --with` for Python tools so nothing lands in the system interpreter.

| Tool | macOS (brew) | Linux (apt) | Python / other |
|---|---|---|---|
| radare2 suite | `brew install radare2` | `apt install radare2` | — |
| Wireshark CLI | `brew install wireshark` | `apt install tshark` | — |
| protobuf (`protoc`) | `brew install protobuf` | `apt install protobuf-compiler` | — |
| `buf` / `grpcurl` | `brew install bufbuild/buf/buf grpcurl` | download release | — |
| blackboxprotobuf | — | — | `uv run --with blackboxprotobuf python ...` |
| protodump | — | — | `go install github.com/arkadiyt/protodump/cmd/protodump@latest` |
| pbtk | — | — | `uv tool install pbtk` (needs `jad`, `dex2jar` for Java/JS) |
| Kaitai compiler (`ksc`) | `brew install kaitai-struct-compiler` | `apt install kaitai-struct-compiler` | runtime: `uv run --with kaitaistruct python ...` |
| Scapy | — | — | `uv run --with scapy python ...` |
| capa | — | — | `uv tool install flare-capa` → `capa` |
| FLOSS | — | — | `uv tool install flare-floss` → `floss` |
| yara-x (`yr`) | `brew install yara-x` | `cargo install yara-x-cli` | — |
| binwalk (v3) | `brew install binwalk` | `cargo install binwalk` | — |
| unblob | — | — | `uv tool install unblob` |
| mitmproxy | `brew install mitmproxy` | `apt install mitmproxy` | `uv tool install mitmproxy` |
| frida-tools | — | — | `uv tool install frida-tools` |
| jadx | `brew install jadx` | download release | — |
| ghidriff | — | — | `uv tool install ghidriff` (needs `GHIDRA_INSTALL_DIR`) |
| CyberChef | — | — | `npx cyberchef` or the hosted web app |

`signsrch` builds from source (no package); `findcrypt` for crypto scanning is a YARA ruleset, not a standalone binary (see below). BinDiff + BinExport are installed from the vendor release packages, not a package manager.

## Cryptographic Scanning Tools (Accurate Names)

- **FindCrypt is a ruleset, not a command.** Use the published YARA rules with the installed scanner: `yr scan findcrypt.yar <target>` (yara-x) or `yara findcrypt.yar <target>`. `capa` also flags crypto via its rule set: `capa <target>`. IDA's `findcrypt` and Ghidra's `findcrypt` are in-tool plugins.
- **`signsrch`** matches thousands of constant/S-box signatures; build from Luigi Auriemma's source.
- Do not reference a pip package named `findcrypt-yara`; it is a rules repository cloned next to the scanner.

---

## Sandboxing, Isolation & Remote Debugger Containment Matrix

Untrusted binaries and dynamic payloads **MUST NEVER** execute on bare-metal host workstations. All dynamic analysis must be routed through isolated containers or disposable virtual machines:

| Target Profile | Containment Layer | Network Topology | Debugger Architecture | Reference Route |
|---|---|---|---|---|
| **Linux ELF / Dynamic Loader / Stagers** | Hardened Docker Container (`--cap-drop=ALL`, seccomp, `--network none`, ro-mount) | Completely severed (`--network none`) or host-only bridge | `gdbserver --once 0.0.0.0:2345 ./target` / `linux_server -p23946` (`armlinux_server` for arm64) | [02-dynamic-instrumentation/malware-sandbox-isolation.md](02-dynamic-instrumentation/malware-sandbox-isolation.md) |
| **Windows PE / Crypter / Rootkit** | Disposable UTM VM (`utmctl`) on Apple Silicon / KVM on Linux | Host-only gateway + INetSim / mitmdump sinkhole | `win64_remote.exe -p23946` on guest; Host IDA connects remotely | [02-dynamic-instrumentation/malware-sandbox-isolation.md](02-dynamic-instrumentation/malware-sandbox-isolation.md) & [04-tool-usage/utm-hypervisor.md](04-tool-usage/utm-hypervisor.md) |
| **Android APK / Native .so** | QEMU/vPhone / Corellium Virtual Device | Sinkholed proxy (`mitmproxy` CA pinned) | `android_server -p23946` (arm64) after `adb forward tcp:23946 tcp:23946` | [02-dynamic-instrumentation/malware-sandbox-isolation.md](02-dynamic-instrumentation/malware-sandbox-isolation.md) & [04-tool-usage/frida.md](04-tool-usage/frida.md) |
| **Script / Office Macro (.vbs, .ps1, .docm)** | Isolated Python parser / headless sandbox container | Disconnected / Mock HTTP loopback | Python AST unrolling / `oledump` / `xlmdeobf` | [01-static-architectures/script-nonpe-analysis.md](01-static-architectures/script-nonpe-analysis.md) |

---

## Boundaries & Anti-Patterns
- **Zero Bare-Metal Execution**: Untrusted binaries, malware unpackers, or script stagers must never be launched natively on the host workstation. Always use disposable VMs with snapshot rollback (`utmctl snapshot restore`) or hardened Docker containers.
- **Do not open large binaries in interactive GUI tools during automated tasks**: Always invoke headless MCP or CLI tools to prevent session blocking and hangs.
- **Do not guess tool parameters or schemas**: Consult the cross-referenced tool guides in `04-tool-usage/` before issuing commands.
- **Do not install duplicate tools on workstations**: Verify local environment paths and VM states before attempting external tool installation.
