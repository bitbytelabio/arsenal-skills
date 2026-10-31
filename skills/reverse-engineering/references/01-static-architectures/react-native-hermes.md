# React Native & Hermes Bytecode Reverse Engineering

## 1. Title & Overview
- **Domain**: React Native mobile applications targeting Android (APK/AAB) and iOS (IPA).
- **Scope**: Extracting packaged JavaScript bundles (`index.android.bundle`, `main.jsbundle`), identifying Hermes Bytecode (HBC) versions and header structures, disassembling and reassembling HBC with `hbctool`, disassembling/decompiling with `hermes-dec` (`hbc-disassembler`/`hbc-decompiler`) and the `hermes_rs` Rust library, auditing plain Metro bundles and source maps, and tracing React Native native module bridges.
- APK decode order (jadx/apktool, manifest, splits, signing) is in [android-apk.md](android-apk.md). iOS Mach-O, FairPlay, and IPA handling are in [mobile-ios.md](mobile-ios.md). JNI `RegisterNatives` recovery and `@ReactMethod` native internals are in [managed-dotnet-jvm.md](managed-dotnet-jvm.md). Proxy capture is in [network-traffic-proxy.md](../02-dynamic-instrumentation/network-traffic-proxy.md).

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing React Native applications:

### Binary Signatures & Bundle Detection
- **Bundle File Locations**:
  - Android: `assets/index.android.bundle` inside APK.
  - iOS: `main.jsbundle` inside application bundle payload.
  - Native engine: `lib/<abi>/libhermes.so` or `libjsc.so` (JavaScriptCore).
- **Hermes Bytecode Magic Signature**:
  - Little-endian 8-byte magic: `\xC6\x1F\xBC\x03\xC1\x03\x19\x1F` (`0x1F1903C103BC1FC6`).
  - Short 4-byte check: `c6 1f bc 03`.
- **Hermes Version Byte**:
  - Located at byte offset `0x08` (32-bit unsigned integer immediately following the 8-byte magic).
- **Plain JavaScript Bundle Indicators**:
  - First bytes are ASCII text: `var __BUNDLE_START_TIME__ = ...` or `__d(function(g,r,i,a,m,e,d){ ... })`.

---

## 3. Tooling & CLI/MCP Actions
- **Bundle Triage & Format Identification**:
  ```bash
  # Extract bundle from APK
  unzip -j target.apk 'assets/index.android.bundle' -d ./out
  
  # Inspect first bytes to distinguish plain JS from Hermes bytecode
  head -c 16 ./out/index.android.bundle | xxd
  ```
- **Hermes disassemblers / decompilers**:
  - `hbctool`: disassembles HBC into an HASM text directory and reassembles it into valid HBC. Upstream `bongtrop/hbctool` supports **only HBC versions 59, 62, 74, and 76**. This is the only round-trip (patch-and-rebuild) path, and only for those versions. Install `pip install hbctool`. Argument order is `<HBC_FILE> <HASM_DIR>` for disasm, `<HASM_DIR> <HBC_FILE>` for asm:
    ```bash
    hbctool disasm index.android.bundle ./hbc_disasm
    # edit ./hbc_disasm/instruction.hasm and ./hbc_disasm/metadata.json
    hbctool asm ./hbc_disasm index.android.bundle.patched
    ```
  - `hermes-dec` (P1sec): read-only disassembler and a best-effort decompiler. It installs three entrypoints — `hbc-file-parser`, `hbc-disassembler`, `hbc-decompiler` — there is no `hermes-dec` binary that takes `-i/-o`. It parses a wide range of versions (tested through the 90s) but cannot reassemble. Install with `uv tool install hermes-dec` or `pipx install hermes-dec`:
    ```bash
    hbc-file-parser index.android.bundle        # header + counts
    hbc-disassembler index.android.bundle out.hasm
    hbc-decompiler index.android.bundle out.js   # pseudo-JS, best effort
    ```
  - `hermes_rs`: a Rust library (crate `hermes_rs`) for parsing/disassembling HBC across many versions; use it when you need to script analysis of a version the Python tools choke on. Not a drop-in CLI.
  - `hermesc`: the official Hermes compiler. It is the path *into* HBC (compiles JS to bytecode), not a general disassembler of arbitrary app bundles. `hermesc -dump-bytecode in.js` dumps bytecode for a source file you compile; it does not reliably decompile a shipped `index.android.bundle`. Build it from the `hermes` tag matching the target's React Native release (the bundled `hermesc` lives under `node_modules/react-native/sdks/hermesc/`). Its value here is producing a reference bundle at a known version to compare opcode encodings.
- **Plain Bundle Beautification**:
  ```bash
  # Format minified plain JS bundle
  npx -y js-beautify index.android.bundle -o bundle.clean.js
  ```

---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 Bundle Format Triage & HBC Version Table
When React Native builds an app, it either packages plain minified JavaScript (interpreted via JavaScriptCore or Hermes JIT) or pre-compiles the bundle into Hermes Bytecode (HBC).

#### Hermes Header Layout:
```c
struct HermesHeader {
    uint64_t magic;                    // 0x1F1903C103BC1FC6
    uint32_t version;                  // Bytecode version integer at offset 0x08
    uint8_t  sourceHash[20];           // SHA1 hash of original source
    uint32_t fileLength;               // Total file size
    uint32_t globalCodeIndex;          // Index of global entry function
    uint32_t functionCount;            // Total functions in bytecode
    uint32_t stringKindCount;
    uint32_t identifierCount;          // Total identifiers in string table
    uint32_t stringCount;              // Total string literals
    uint32_t overflowStringCount;
    uint32_t stringStorageSize;        // Size of UTF-8/UTF-16 string data block
    // ... Followed by function headers and bytecode arrays
};
```

#### Hermes Bytecode Version Mapping:
The HBC version is a monotonic integer defined by `#define HERMES_BYTECODE_VERSION` in `hermes/include/hermes/BCGen/HBC/BytecodeVersion.h` at the Hermes tag a given React Native release bundles. The mapping below is approximate — a dot-release can move the number, and only `hbctool`'s set (59/62/74/76) can be rebuilt. The decisive fact is the integer at offset `0x08`; the RN column is a hint. Grep `BytecodeVersion.h` at the matching tag to confirm.

| HBC Version | Approx. React Native | Round-trip (`hbctool`) | Read-only (`hermes-dec`) |
| :--- | :--- | :--- | :--- |
| **59** | RN 0.60–0.62 | yes | yes |
| **62** | RN 0.63 | yes | yes |
| **74** | RN 0.64–0.66 | yes | yes |
| **76** | RN 0.67 | yes | yes |
| **84** | RN 0.68–0.69 | no | yes |
| **89 / 90** | RN 0.70–0.71 | no | yes |
| **94 / 95** | RN 0.72–0.73 | no | yes |
| **96** | RN 0.74–0.76 | no | yes |

#### Version Extraction Workflow:
1. Read the 4-byte little-endian version at offset `0x08`:
   ```bash
   python3 -c "import struct;f=open('index.android.bundle','rb');f.seek(8);print('HBC version:',struct.unpack('<I',f.read(4))[0])"
   ```
   Cross-check with `file index.android.bundle` (identifies "Hermes JavaScript bytecode, version N") and `hbc-file-parser`.
2. If version is `59`, `62`, `74`, or `76`, `hbctool` can disassemble and reassemble (patch path).
3. For any version, `hbc-disassembler`/`hbc-decompiler` give a read-only view. Reassembly for `>76` is not supported by any public tool; patch at the native-module layer or with a Frida hook instead of rewriting HBC.

---

### 4.2 Disassembling Hermes Opcodes & Register Architecture
Hermes is a **register-based virtual machine**, fundamentally different from V8's stack machine.

#### Virtual Registers:
- Instructions operate on numbered registers: `r0, r1, r2, ...`.
- Parameters are passed in initial registers.
- Registers are local to each function frame.

#### Common Hermes Opcodes:
- `LoadConstString r0, string_idx`: Loads string literal from the string table into register `r0`.
- `LoadConstUInt8 r1, 1`: Loads immediate integer into `r1`.
- `GetById r2, r0, id_idx, "endpoint"`: Reads property `endpoint` from object in `r0` and stores in `r2`.
- `PutById r0, r1, id_idx, "token"`: Sets property `token` on object `r0` with value from `r1`.
- `Call r0, func_reg, arg_count`: Invokes function stored in `func_reg`.
- `JmpTrue offset, condition_reg`: Conditional branch.
- `Ret r0`: Returns value from register `r0`.

#### Reversing Workflow:
1. Run `hbc-decompiler` to produce pseudo-JavaScript.
2. If decompilation fails on a specific function, dump raw opcodes with `hbc-disassembler` (or script `hermes_rs` for an unsupported version).
3. Locate string indices in the disassembly table to resolve keys and URLs; the string table is the highest-value artifact in a stripped bundle.

#### JSC vs Hermes:
If `lib/<abi>/libhermes.so` is absent and `libjsc.so` is present (or neither Hermes magic nor engine lib appears), the app runs on JavaScriptCore and ships a **plain JavaScript** bundle — skip HBC tooling and go to the plain-bundle section. Hermes became the default engine in RN 0.70; older or opt-out apps are JSC.

#### CodePush / OTA bundles:
Apps using Microsoft CodePush (App Center) or Expo Updates download a replacement bundle at runtime and store it under the app's data dir (`.../files/CodePush/` or Expo's updates cache). The shipped bundle may be stale. For current logic, capture the OTA download (proxy) or pull the cached bundle from a lab device; it is the same HBC/plain format and uses the same tooling.

---

### 4.3 Recovering JavaScript Source from Plain Bundles
If the bundle is plain JavaScript (not Hermes bytecode):
1. **Module Boundary Identification**:
   React Native Metro bundler wraps all modules using `__d`:
   ```javascript
   __d(function(global, _$$_REQUIRE, _$$_IMPORT_DEFAULT, _$$_IMPORT_ALL, module, exports, _dependencyMap) {
       // Original module source code
       var ApiClient = {
           baseUrl: "https://api.production.domain/v2",
           apiKey: "AIzaSy..."
       };
       module.exports = ApiClient;
   }, 142, [10, 25]); // Module ID 142, dependencies [10, 25]
   ```
2. **Source Map Check**:
   Always verify whether Metro's source map was accidentally packaged:
   ```bash
   unzip -l target.apk | grep -E '\.map$'
   ```
   A packaged `.map` is a serious leak. Feed it plus the bundle to a source-map reconstructor such as `npx -y restore-source-tree index.android.bundle.map -o src/` (or load bundle+map in a browser devtools "Sources" panel) to recover original file paths, JSX, and comments. For a Metro bundle without a map, `npx -y react-native-decompiler -i index.android.bundle -o out` splits the `__d` modules back into per-module files. Verify any reconstructed tree against the `__d` module IDs; a reconstructor can misattribute paths.

---

### 4.4 Auditing Native Bridges: Java/ObjC ↔ JavaScript
React Native business logic relies on Native Modules to access camera, keychain, network sockets, and cryptography.

#### Architecture:
- JavaScript calls native code via `NativeModules.<ModuleName>.<MethodName>()`.
- In Android (Java/Kotlin):
  - Native module classes extend `ReactContextBaseJavaModule`.
  - Exported methods are annotated with `@ReactMethod`:
    ```java
    @ReactMethod
    public void secureStorageSet(String key, String value, Promise promise) { ... }
    ```
- In iOS (Objective-C/Swift):
  - Modules conform to `RCTBridgeModule`.
  - Methods are exported via `RCT_EXPORT_METHOD(...)`.
- **Reversing Action**: When analyzing authentication or cryptographic workflows, do not stop at the JavaScript bundle. Search for `@ReactMethod` in jadx (Android), or `RCT_EXPORT_METHOD` / the exported module name in the iOS binary via the official HexRaysSA `ida-mcp` (`open_database`, `execute_python`; see [ida-mcp-remote-debugging.md](../04-tool-usage/ida-mcp-remote-debugging.md)). TurboModules (New Architecture, default in RN 0.76) register through a codegen'd `__hostFunction`/JSI spec rather than the legacy bridge; look for the `NativeXxxSpec` C++ and the `TurboModuleProvider` lookup.
- **Dynamic note (Frida 17)**: the Frida CLI/REPL still bundle the Java and ObjC bridges, so `Java.use`/`ObjC.classes` work with `frida -U -l`. A `frida-compile`d agent must add `frida-java-bridge`/`frida-objc-bridge` explicitly. Hook the native module method, not the JS, to see decrypted arguments.

---

## 5. Concrete Code & Script Examples

### Python Hermes Bytecode Header Parser & String Dumper
```python
import struct
import sys

def parse_hermes_bundle(bundle_path):
    with open(bundle_path, "rb") as f:
        data = f.read()

    # Verify 8-byte Hermes magic
    if len(data) < 32:
        print("[-] File too small.")
        return

    magic = data[:8]
    # Check for little-endian magic: 0x1F1903C103BC1FC6
    if magic != b"\xC6\x1F\xBC\x03\xC1\x03\x19\x1F":
        if b"var __BUNDLE" in data[:100] or b"__d(" in data[:100]:
            print("[+] Target is Plain JavaScript Bundle (not Hermes bytecode).")
        else:
            print("[-] Not a valid Hermes Bytecode bundle.")
        return

    # Stable across versions: magic[8] + version[4] + sourceHash[20], then fileLength.
    version = struct.unpack_from("<I", data, 8)[0]
    source_hash = data[12:32].hex()
    file_len = struct.unpack_from("<I", data, 32)[0]

    print("[+] Valid Hermes Bytecode detected!")
    print(f"    Bytecode Version: {version}")
    print(f"    Source SHA1:      {source_hash}")
    print(f"    File Length:      {file_len} bytes")
    # Field offsets AFTER fileLength (functionCount, stringCount, stringStorageSize...)
    # move between HBC versions. Do not hardcode them here. Use `hbc-file-parser`
    # for exact, version-aware counts; this script only needs version + strings.

    # In modern HBC (e.g., HBC 74+), the string table header starts after the main header
    # Strings can be quickly scraped by hunting printable sequences in the storage block
    print("\n[+] Extracting sample string constants from bundle:")
    strings_found = []
    curr = []
    for b in data[64:]:
        if 0x20 <= b <= 0x7E:
            curr.append(chr(b))
        else:
            if len(curr) >= 8:
                s = "".join(curr)
                if any(k in s.lower() for k in ["http", "key", "token", "secret", "api"]):
                    strings_found.append(s)
            curr = []

    for s in strings_found[:20]:
        print(f"    [String] {s}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_hermes.py <index.android.bundle>")
        sys.exit(1)
    parse_hermes_bundle(sys.argv[1])
```

---

## 6. Boundaries & Anti-Patterns
- **Do not assume `hbctool` works on all Hermes bundles**: upstream `hbctool` supports HBC versions 59, 62, 74, and 76 only. On HBC 84+ it raises a parse exception. Check offset `0x08` first; for `>76` use `hbc-disassembler`/`hbc-decompiler` (read-only) and do not expect to reassemble.
- **Do not invoke `hermes-dec` as a single binary**: it has no `-i/-o` CLI. The entrypoints are `hbc-file-parser`, `hbc-disassembler`, and `hbc-decompiler`.
- **Do not ignore Native Modules**: Critical security checks, jailbreak detection, biometric authentication, and token storage are implemented in native code (`.so` or `.m`), not in the JavaScript bundle. Always bridge the gap between `NativeModules` and Java/Objective-C code.
- **Do not assume plain bundles are encrypted when they contain binary headers**: Always check magic bytes. If the first 4 bytes are `c6 1f bc 03`, it is standard Hermes bytecode, not custom encryption.
- **Do not reassemble HBC without verifying exact bytecode version**: Modifying disassembled Hermes JSON and reassembling it using an mismatched compiler version will produce corrupted bytecode that crashes the Hermes VM runtime.
