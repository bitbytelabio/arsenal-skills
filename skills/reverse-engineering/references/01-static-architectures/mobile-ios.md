# Apple iOS / macOS Native Application Reverse Engineering

## 1. Title & Overview
- **Domain**: Apple iOS and macOS native applications packaged as Mach-O binaries, App Store IPA archives (`Payload/*.app`), and macOS application bundles.
- **Scope**: Verifying and handling Mach-O FairPlay DRM encryption (`LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`), reconstructing Objective-C runtime metadata (`objc_msgSend`, class lists, method structures), analyzing Swift 5 ABI type descriptors and protocol witness tables (`__swift5_*`), extracting code signing entitlements, and assessing App Sandbox boundaries.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing compiled Apple ecosystem executables:

### Binary Signatures & Section Clues
- **Mach-O Container Structure**:
  - Magic bytes:
    - 64-bit Little-Endian: `0xFEEDFACF` (`\xCF\xFA\xED\xFE`)
    - 32-bit Little-Endian: `0xFEEDFACE` (`\xCE\xFA\xED\xFE`)
    - Universal / Fat Binary: `0xCAFEBABE` or `0xBEBAFECA`
- **Encryption Load Commands**:
  - `LC_ENCRYPTION_INFO` (`0x21`) or `LC_ENCRYPTION_INFO_64` (`0x2C`).
  - Contains `cryptid`: `cryptid = 1` indicates FairPlay DRM encryption; `cryptid = 0` indicates decrypted executable text.
- **Objective-C Runtime Sections**:
  - `__DATA,__objc_classlist`: Pointers to class definitions.
  - `__DATA,__objc_catlist`: Category definitions.
  - `__TEXT,__objc_methname`: Method selector strings.
  - `__TEXT,__objc_methtype`: Type encoding strings (e.g., `v16@0:8`).
- **Swift 5 ABI Sections**:
  - `__TEXT,__swift5_types`: Nominal type descriptors (structs, classes, enums).
  - `__TEXT,__swift5_proto`: Protocol definitions.
  - `__TEXT,__swift5_protos`: Protocol conformance descriptors.
  - `__TEXT,__swift5_reflstr`: Reflection string literals for field and type names.
  - Symbol prefix: Mangled symbols beginning with `$s` or `_$s`.

---

## 3. Tooling & CLI/MCP Actions
- **Mach-O Inspection & Triage**:
  ```bash
  # Check encryption status of Mach-O binary
  otool -l <binary> | grep -A 4 LC_ENCRYPTION_INFO

  # Extract Mach-O architectures from universal fat binary
  lipo -info <binary>
  lipo <binary> -thin arm64 -output <binary>_arm64

  # Inspect code signing entitlements
  codesign -d --entitlements :- <binary>
  # Alternatively using ldid
  ldid -e <binary>
  ```
- **Objective-C & Swift Metadata Dumpers**:
  - `ipsw class-dump`: the maintained dumper. Handles Objective-C and Swift, works on single Mach-O, fat binaries (`--arch arm64`), and dyld shared cache images. Prefer it over the legacy `class-dump` (unmaintained, Objective-C only, chokes on modern Swift and arm64e). `ipsw` is a single Go binary (`brew install blacktop/tap/ipsw`); see [ipsw.md](../04-tool-usage/ipsw.md).
    ```bash
    ipsw class-dump --headers --output ./headers <decrypted_binary>
    ipsw class-dump --swift <decrypted_binary>         # Swift types
    ipsw macho info <decrypted_binary>                 # header, load commands, segments
    ```
  - `dsdump`: alternative dumper for Objective-C and Swift 5 type structures (not preinstalled on this host; build from source). `dsdump --objc --color <binary>` and `dsdump --swift <binary>`.
  - `swift demangle` / `xcrun swift-demangle`: demangles Swift mangled symbols (prefix `$s` / `_$s`). There is no bare `swift-demangle` on PATH; invoke through the toolchain. Reads symbols as args or on stdin:
    ```bash
    xcrun swift-demangle '_$s4main3fooyyF'            # -> main.foo() -> ()
    nm <binary> | awk '{print $3}' | grep '^_\$s' | xcrun swift-demangle
    ```
- **FairPlay Decryption Utilities (On Research Device / Jailbreak)**:
  - `frida-ios-dump`: attaches to the running app over the Frida server, dumps decrypted pages, and repackages a decrypted IPA. The script is `dump.py` from the checkout; it needs the device reachable over USB/SSH and a running `frida-server`:
    ```bash
    BUNDLE_ID="com.target.app"
    python3 dump.py "$BUNDLE_ID"            # -> <AppName>.ipa with cryptid=0
    ```
  - `bagbak`: Node tool that decrypts the main binary plus embedded app extensions (`PlugIns/`) and frameworks in one pass (`npx bagbak "$BUNDLE_ID"`). Prefer it when extensions matter.
  - `flexdecrypt` / `ipadump`-style on-device decryptors: run on the jailbroken guest and overwrite the slice with `cryptid=0`. Use whichever the lab guest already provides; the goal is identical (a decrypted Mach-O), only the transport differs. Lab setup is in [host-and-lab-setup.md](../05-environment/host-and-lab-setup.md).

---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 FairPlay DRM Verification & Decryption Gating
Binaries acquired directly from the Apple App Store have their `__TEXT` segments encrypted with Apple FairPlay DRM:

```text
Mach-O Load Command: LC_ENCRYPTION_INFO_64
  cmd       0x2C (LC_ENCRYPTION_INFO_64)
  cmdsize   24
  cryptoff  16384     // File offset where encryption starts (__TEXT segment)
  cryptsize 12582912  // Number of encrypted bytes
  cryptid   1         // 1 = Encrypted, 0 = Decrypted
```

#### Workflow:
1. **Never attempt static analysis while `cryptid == 1`**: The decompiler will display garbage instructions and missing strings because the code segment is encrypted.
2. Deploy the IPA to an iOS research device or Corellium VM.
3. Launch the application so the iOS kernel decrypts the `__TEXT` segment into memory.
4. Execute `frida-ios-dump` or `bagbak` to dump the memory pages and overwrite the binary with `cryptid = 0`.
5. Verify that embedded dynamic libraries in `Frameworks/` and extensions in `PlugIns/` are also decrypted.

---

### 4.2 Objective-C Runtime Architecture & Message Dispatch
Objective-C uses dynamic message passing instead of direct function calls.

#### Core Runtime Structures:
Modern (non-fragile ABI, arm64) layout. `bits` is a `class_data_bits_t`: mask it with `FAST_DATA_MASK` (`0x00007ffffffffff8`) to reach a `class_rw_t`; the clean compile-time metadata (`class_ro_t`) hangs off that, or is `bits & mask` directly before the class is realized. There is no separate `vtable` word in the modern struct — `cache` is a two-word `cache_t` (bucket pointer + mask/occupied). Account for pointer authentication (arm64e) when dereferencing these on-device.
```c
struct objc_class {          // 5 words, arm64
    struct objc_class* isa;         // metaclass (arm64e: PAC-signed)
    struct objc_class* superclass;
    cache_t            cache;       // two words: _buckets + _mask/_flags
    class_data_bits_t  bits;        // (bits & FAST_DATA_MASK) -> class_rw_t -> class_ro_t
};

struct class_ro_t {
    uint32_t           flags;
    uint32_t           instanceStart;
    uint32_t           instanceSize;
    const uint8_t*     ivarLayout;
    const char*        name;        // Class name string ("LoginViewController")
    struct method_list_t* baseMethods; // List of instance methods
    struct protocol_list_t* baseProtocols;
    struct ivar_list_t*   ivars;
};

struct method_t {
    const char* name;               // Selector name ("loginWithUser:password:")
    const char* types;              // Type encoding string
    void*       imp;                // Function pointer to concrete machine code
};
```

#### Disassembly Call Pattern (`objc_msgSend`):
In ARM64 assembly, message sends appear as:
```nasm
; [receiver loginWithUser:username password:password]
mov     x0, x19              ; x0 = receiver object instance
adrp    x1, #sel_loginWithUser_password_@PAGE
ldr     x1, [x1, #sel_loginWithUser_password_@PAGEOFF] ; x1 = Selector (SEL)
mov     x2, x20              ; x2 = first argument (username)
mov     x3, x21              ; x3 = second argument (password)
bl      _objc_msgSend        ; Dynamic dispatch
```
**Reversing Action**:
1. Identify the selector string loaded into `x1`.
2. Inspect the receiver class loaded into `x0`.
3. Locate the `method_t` in the class's `baseMethods` list matching that selector to identify the concrete `imp` target function.

---

### 4.3 Swift 5 ABI & Type Descriptors
Swift 5 introduced a stable ABI. Unlike Objective-C, Swift favors direct calls and witness table dispatch, embedding metadata into dedicated sections:

#### Key Swift Sections:
- `__swift5_types`: Array of 32-bit signed relative offsets pointing to Nominal Type Descriptors (`ClassDescriptor`, `StructDescriptor`, `EnumDescriptor`).
- `__swift5_fieldmd`: Field descriptors storing member variable types and names.
- `__swift5_proto` and `__swift5_protos`: Protocol declarations and conformance records.

#### Nominal Type Descriptor Structure:
```c
struct TargetClassDescriptor {
    uint32_t flags;                // Type kind (16 = class, 17 = struct, 18 = enum)
    int32_t  parent;               // Relative offset to parent module/context
    int32_t  name;                 // Relative offset to type name string
    int32_t  accessFunctionPtr;    // Canonical metadata access function
    int32_t  fieldDescriptor;      // Relative offset to __swift5_fieldmd
    int32_t  superClassType;       // Relative offset to superclass descriptor
    uint32_t metadataNegativeSizeInWords;
    uint32_t metadataPositiveSizeInWords;
    uint32_t numImmediateMembers;
    uint32_t numFields;
    // Followed by vtable method pointer offsets
};
```

#### Protocol Witness Tables:
When invoking methods through a Swift protocol, dispatch occurs via a Protocol Witness Table (`PWT`):
- Argument 1 (`X0`): Value or existential container.
- Final argument (`X1` or `X2`): Pointer to the Protocol Witness Table containing function pointers to the conforming implementation.

---

### 4.4 Entitlements Extraction & Sandboxing Rules
Every iOS application runs inside an isolated App Sandbox enforced by the XNU kernel and Apple Mobile File Integrity (AMFI).

#### Entitlements Extraction:
Extract the XML property list containing embedded code signing entitlements:
```bash
codesign -d --entitlements :- Target.app/TargetApp > entitlements.plist
```

#### High-Value Entitlements to Audit:
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Keychain Sharing Access Groups -->
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.example.sharedkeychain</string>
    </array>

    <!-- App Groups (Shared sandbox directory) -->
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.example.appgroup</string>
    </array>

    <!-- Network Server Capability (macOS Sandbox) -->
    <key>com.apple.security.network.server</key>
    <true/>

    <!-- Custom URL Scheme Whitelist in Info.plist -->
</dict>
</plist>
```

#### Sandbox Storage Boundaries:
- Application Home Directory: `/var/mobile/Containers/Data/Application/<UUID>/`
  - `Documents/`: User data persisted to iCloud backup unless flagged `NSURLIsExcludedFromBackupKey`.
  - `Library/Caches/`: Ephemeral data, SQLite databases, network caches.
  - `Library/Preferences/<bundle_id>.plist`: `NSUserDefaults` key-value pairs (unencrypted plaintext).
- App Group Shared Directory: `/var/mobile/Containers/Shared/AppGroup/<UUID>/`
  - Accessible simultaneously by main app and app extensions (`PlugIns/`). High-value location for inter-process communication databases and shared tokens.

---

## 5. Concrete Code & Script Examples

### Python Script to Check Mach-O Load Commands & Encryption
```python
import struct
import sys

def check_macho_encryption(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)
        if magic in (b"\xCF\xFA\xED\xFE", b"\xCE\xFA\xED\xFE"): # Little-endian 64/32
            endian = "<"
        elif magic in (b"\xFE\xED\xFA\xCF", b"\xFE\xED\xFA\xCE"): # Big-endian 64/32
            endian = ">"
        else:
            print("[-] Not a valid thin Mach-O binary (check for fat universal binary).")
            return

        is_64 = magic in (b"\xCF\xFA\xED\xFE", b"\xFE\xED\xFA\xCF")
        
        # Read header: cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
        f.seek(16)
        ncmds, sizeofcmds = struct.unpack(f"{endian}II", f.read(8))
        f.seek(32 if is_64 else 28)

        print(f"[+] Mach-O parsed successfully: {ncmds} load commands.")

        for _ in range(ncmds):
            cmd_start = f.tell()
            cmd, cmdsize = struct.unpack(f"{endian}II", f.read(8))
            
            # LC_ENCRYPTION_INFO (0x21) or LC_ENCRYPTION_INFO_64 (0x2C)
            if cmd in (0x21, 0x2C):
                cryptoff, cryptsize, cryptid = struct.unpack(f"{endian}III", f.read(12))
                print(f"[!] Found LC_ENCRYPTION_INFO ({'64-bit' if cmd == 0x2C else '32-bit'}):")
                print(f"    Crypt Offset: 0x{cryptoff:X}")
                print(f"    Crypt Size:   0x{cryptsize:X} bytes")
                print(f"    Crypt ID:     {cryptid} ({'ENCRYPTED (FairPlay DRM)' if cryptid != 0 else 'DECRYPTED'})")
                return

            f.seek(cmd_start + cmdsize)

        print("[+] No LC_ENCRYPTION_INFO command found (binary is unencrypted).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_encryption.py <Mach-O binary>")
        sys.exit(1)
    check_macho_encryption(sys.argv[1])
```

---

### 4.5 macOS Desktop Surfaces
An iOS IPA and a macOS `.app` share Mach-O. The desktop checks below are not FairPlay steps.

Record, before decompiling:

- `codesign -dv --verbose=4` and `spctl -a -vv`. Note Developer ID versus ad-hoc, notarization, and Hardened Runtime.
- Entitlements that change injection: library validation, `com.apple.security.cs.disable-library-validation`, and `com.apple.security.get-task-allow`. A hardened runtime without the disable flag rejects `DYLD_INSERT_LIBRARIES`.
- TCC-sensitive APIs (`TCCAccessRequest`, FDA paths, screen capture, input monitoring) and their entitlement keys.
- XPC service names and Mach services in the bundle's `LaunchDaemons` or `XPCServices`.
- `LaunchAgents` and `LaunchDaemons` plists: program path, `RunAtLoad`, and `WatchPaths`.
- `otool -L` and `@rpath`. A dylib loaded from the app bundle is part of the target, not a system library.

iOS `cryptid` does not apply to a locally built macOS debug binary. A Mac App Store binary can still be encrypted. Check the load command instead of assuming.

A universal binary needs an explicit slice (`arm64`, `arm64e`, or `x86_64`) before import. If Mach-O reexport resolution blocks the import, import again without reexports and record that the static view omits them. A path under `/System/Library` is often a dyld-cache stub with no local Mach-O. Disassemble the extracted cache slice. Attach the debugger to the live process. A Frida hook on an unqualified native symbol that never fires is not evidence the function is absent. Retry `Module!symbol`. An XPC report with zero services is missing input until its warnings say the bundle was actually parsed.

### 4.6 Load Command Reference
The load commands you read most, and what each tells you:

| Load command | Value | What it tells you |
|---|---|---|
| `LC_SEGMENT_64` | `0x19` | Segment/section layout (`__TEXT`, `__DATA`, `__LINKEDIT`) |
| `LC_ENCRYPTION_INFO_64` | `0x2C` | FairPlay `cryptid`/`cryptoff`/`cryptsize` (decrypt gate) |
| `LC_ENCRYPTION_INFO` | `0x21` | 32-bit variant (rare on modern arm64) |
| `LC_LOAD_DYLIB` | `0x0C` | Linked dylib path (`@rpath`, framework deps) |
| `LC_RPATH` | `0x1C` | Runtime search path for `@rpath` resolution |
| `LC_CODE_SIGNATURE` | `0x1D` | Code signature blob; entitlements live here |
| `LC_UUID` | `0x1B` | Build UUID (symbolication, dyld-cache matching) |
| `LC_MAIN` | `0x80000028` | Entry point offset (`LC_MAIN` has the high bit set) |
| `LC_VERSION_MIN_*` / `LC_BUILD_VERSION` | `0x24..0x32` | Min OS / SDK version |

Dump them with `otool -l <binary>` or `ipsw macho info <binary>`. Confirm `cryptid` before any static read:
```bash
otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO
```

### 4.7 dyld Shared Cache Extraction
System frameworks (`UIKit`, `Foundation`, most of `/System/Library`) are not standalone Mach-O files on disk; they are merged into the dyld shared cache (`/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*` on-device, or `/System/Volumes/Preboot/.../dyld_shared_cache_*` and the Cryptexes on recent systems). A path under `/System/Library` usually yields a stub, not analyzable code. Extract the real image first:
```bash
# List images inside a cache, then extract one framework as a standalone Mach-O
ipsw dyld info dyld_shared_cache_arm64e
ipsw dyld extract dyld_shared_cache_arm64e /System/Library/Frameworks/UIKit.framework/UIKit
# Or split the whole cache into individual dylibs
ipsw dyld split dyld_shared_cache_arm64e --output ./cache_out
```
Then disassemble the extracted slice, not the on-disk stub. For a live process, attach the debugger or Frida to the mapped image (`Module!symbol`) rather than reading the stub.

## 6. Boundaries & Anti-Patterns
- **Do not decompile App Store binaries before memory decryption**: When `cryptid == 1`, the code section is ciphertext. Tools will misidentify function boundaries and produce useless output. Decrypt on device first.
- **Do not confuse universal/fat binaries with single architecture slices**: A fat Mach-O contains multiple architecture slices (e.g., `arm64`, `x86_64`). Use `lipo -thin arm64` to isolate the target slice before feeding it into decompilers or dumpers.
- **Do not ignore dynamic method dispatch when following call graphs**: Calls through `objc_msgSend` resolve at runtime based on the receiver's class. A static cross-reference to `objc_msgSend` does not directly reveal the target function without inspecting the selector in register `x1` / `rsi`.
- **Do not overlook App Extensions (`PlugIns/`)**: Critical functionality (authentication extensions, biometric widgets, network extensions) is often factored into separate binaries inside the `PlugIns/` folder. They have their own entitlements and must be analyzed individually.
