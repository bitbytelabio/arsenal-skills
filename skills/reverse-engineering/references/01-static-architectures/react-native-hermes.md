# React Native & Hermes Bytecode Reverse Engineering

## 1. Title & Overview
- **Domain**: React Native mobile applications targeting Android (APK/AAB) and iOS (IPA).
- **Scope**: Extracting packaged JavaScript bundles (`index.android.bundle`, `main.jsbundle`), identifying Hermes Bytecode (HBC) versions and header structures, disassembling and reassembling HBC with `hbctool` and `hasmer`, decompiling bytecode to JavaScript using `hermes-dec`, and auditing React Native native module bridges.

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
- **Hermes Decompilers & Disassemblers**:
  - `hbctool`: Disassembles HBC into JSON/instruction files and allows reassembly back into valid HBC (supports versions 59, 62, 74).
    ```bash
    hbctool disasm index.android.bundle ./hbc_disasm
    hbctool asm ./hbc_disasm index.android.bundle.patched
    ```
  - `hermes-dec`: Decompiler producing human-readable JavaScript pseudocode from newer HBC versions (versions 74 through 96+).
    ```bash
    hermes-dec -i index.android.bundle -o ./decompiled_js/
    ```
  - `hasmer`: Multi-version Hermes disassembler and CFG visualizer.
  - `hermesc`: Official Hermes compiler CLI built from the matching React Native tag:
    ```bash
    hermesc -dump-bytecode index.android.bundle -out bytecode.txt
    ```
- **Plain Bundle Beautification**:
  ```bash
  # Format minified plain JS bundle
  npx js-beautify index.android.bundle -o bundle.clean.js
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
| HBC Version | React Native Version | Compatible Tools |
| :--- | :--- | :--- |
| **59** | RN 0.62.x | `hbctool`, `hermes-dec`, `hasmer` |
| **62** | RN 0.63.x | `hbctool`, `hermes-dec`, `hasmer` |
| **74** | RN 0.64.x – 0.67.x | `hbctool`, `hermes-dec`, `hasmer` |
| **84** | RN 0.68.x – 0.69.x | `hermes-dec`, `hasmer`, official `hermesc` |
| **89 / 90** | RN 0.70.x – 0.71.x | `hermes-dec`, custom-built `hermesc` |
| **93 / 96+** | RN 0.72.x – 0.75+ | `hermes-dec` (latest branch), official `hermesc` |

#### Version Extraction Workflow:
1. Read 4 bytes at offset `0x08`:
   ```bash
   python3 -c "import struct; f=open('index.android.bundle','rb'); f.seek(8); print('HBC Version:', struct.unpack('<I', f.read(4))[0])"
   ```
2. If version is `59`, `62`, or `74`, use `hbctool` to enable bidirectional disassembly and repatching.
3. If version is greater than `74`, use `hermes-dec` for decompilation or build `hermesc` from the matching tag.

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
1. Run `hermes-dec` to produce pseudo-JavaScript.
2. If decompilation fails on a specific function, dump raw opcodes using `hasmer` or `hermesc -dump-bytecode`.
3. Locate string indices in the disassembly table to resolve encrypted keys and URLs.

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
   If `index.android.bundle.map` exists, run `restore-source-tree` to completely restore the developer's original React components, JSX files, and comments.

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
- **Reversing Action**: When analyzing authentication or cryptographic workflows, do not stop at the JavaScript bundle. Search for `@ReactMethod` in JADX or `RCT_EXPORT_METHOD` in IDA Pro to inspect the underlying native implementation.

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

    version = struct.unpack_from("<I", data, 8)[0]
    file_len = struct.unpack_from("<I", data, 28)[0]
    func_count = struct.unpack_from("<I", data, 36)[0]
    string_count = struct.unpack_from("<I", data, 48)[0]
    storage_size = struct.unpack_from("<I", data, 56)[0]

    print(f"[+] Valid Hermes Bytecode detected!")
    print(f"    Bytecode Version: {version}")
    print(f"    Function Count:   {func_count}")
    print(f"    String Count:     {string_count}")
    print(f"    String Storage:   {storage_size} bytes")

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
- **Do not assume `hbctool` works on all Hermes bundles**: Upstream `hbctool` strictly supports HBC versions 59, 62, and 74. Attempting to disassemble bundles from React Native 0.70+ (HBC 89+) will result in immediate parse exceptions. Check offset `0x08` first.
- **Do not ignore Native Modules**: Critical security checks, jailbreak detection, biometric authentication, and token storage are implemented in native code (`.so` or `.m`), not in the JavaScript bundle. Always bridge the gap between `NativeModules` and Java/Objective-C code.
- **Do not assume plain bundles are encrypted when they contain binary headers**: Always check magic bytes. If the first 4 bytes are `c6 1f bc 03`, it is standard Hermes bytecode, not custom encryption.
- **Do not reassemble HBC without verifying exact bytecode version**: Modifying disassembled Hermes JSON and reassembling it using an mismatched compiler version will produce corrupted bytecode that crashes the Hermes VM runtime.
