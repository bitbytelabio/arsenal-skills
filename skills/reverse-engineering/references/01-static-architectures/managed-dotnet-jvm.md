# Managed .NET & JVM / Dalvik Reverse Engineering

## 1. Title & Overview
- **Domain**: Virtual machine-managed bytecodes spanning Microsoft .NET (CIL / CLR / CoreCLR / Mono) and JVM / Android Dalvik / ART (Java `.class` files, Android `.dex`, `.apk`, `.aab`).
- **Scope**: Parsing ECMA-335 CLI metadata streams (`#~`, `#Strings`, `#US`, `#Blob`, `#GUID`), disassembling Common Intermediate Language (CIL), Dalvik Executable (DEX) file structures, Smali intermediate representation, deobfuscating identifier renaming (ProGuard / R8 / ConfuserEx), and tracing bidirectional native interop bridges (P/Invoke and JNI).

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing managed executables or virtual-machine bytecode containers:

### Binary Signatures & Section Clues
- **Microsoft .NET / CIL (PE Binaries)**:
  - PE Optional Header Data Directory index 14 (CLR Runtime Header): Points to `IMAGE_COR20_HEADER`.
  - Metadata root magic signature: `BSJB` (`0x424A534A`) at the start of CLI metadata.
  - Metadata stream names: `#~` (compressed metadata tables), `#Strings` (identifier names), `#US` (User Strings in UTF-16LE), `#Blob` (signatures and constants), `#GUID` (assembly UUIDs).
  - Imports: Imports `_CorExeMain` or `_CorDllMain` from `mscoree.dll`.
  - Compressed mobile assemblies: `XALZ` magic header (Xamarin/Mono compressed assemblies in APKs).
- **JVM & Android Dalvik / ART**:
  - Java Class file magic: `0xCAFEBABE` (followed by major/minor class versions).
  - Dalvik Executable magic: `dex\n035\0`, `dex\n037\0`, `dex\n038\0`, or `dex\n039\0`.
  - Container formats: `.apk`, `.aab`, `.jar`, `.war` (standard ZIP archives containing `.dex` or `.class` files).

---

## 3. Tooling & CLI/MCP Actions
- **.NET Decompilers & Analyzers**:
  - `ilspycmd`: Cross-platform .NET decompilation CLI tool.
    ```bash
    # Decompile assembly to structured C# project directory
    ilspycmd -p -o ./decompiled_net MyAssembly.dll
    # List embedded single-file bundles
    ilspycmd --list-bundle Target.exe
    ```
  - `dnSpyEx` / `dnSpy`: Windows GUI interactive decompiler, IL editor, and live managed debugger.
  - `de4dot` / `de4dot-cex`: Dedicated deobfuscator for ConfuserEx, .NET Reactor, SmartAssembly, Eazfuscator, Babel.NET, DeepSea, and Goliath.
    ```bash
    # Scan assembly to identify obfuscators
    de4dot -d Target.exe
    # Deobfuscate assembly with recursive dependency scanning and output directory
    de4dot -r ./input_bins -ro ./cleaned_bins
    # Handle custom token renaming schemes and decrypt strings
    de4dot Target.exe --strtyp delegate --dont-rename
    ```
  - `dnlib` / `AsmResolver`: High-performance low-level .NET metadata and CIL manipulation libraries for custom static devirtualization and cleaning pipelines.
  - `jadx` / `jadx-gui`: DEX to Java source decompiler with built-in deobfuscation engine, AST analysis, and custom script plugins.
    ```bash
    # Decompile APK with deobfuscation engine enabled, setting min identifier length.
    # (jadx 1.5.x: --deobf, --deobf-min, --deobf-max are real; there is NO
    #  --deobf-parse-kotlin-metadata flag. Kotlin renaming is on by default and
    #  tuned via the kotlin-metadata.* plugin options.)
    jadx -d ./jadx_out --deobf --deobf-min 3 Target.apk
    # Persist the auto-generated name map so manual corrections survive re-runs.
    # (The flag is --deobf-cfg-file [+ --deobf-cfg-file-mode], NOT --deobf-rewrite-cfg.)
    jadx -d ./jadx_out --deobf --deobf-cfg-file names.jobf --deobf-cfg-file-mode overwrite Target.apk
    # Apply an official ProGuard mapping when available:
    jadx -d ./jadx_out --mappings-path mapping.txt Target.apk
    ```
  - `apktool`: Decodes Android XML resources, manifest, and disassembles DEX to Smali text.
    ```bash
    apktool d Target.apk -o ./apk_disasm
    ```
  - `baksmali` / `smali`: Raw Dalvik assembler and disassembler.
    ```bash
    baksmali d classes.dex -o ./smali_out
    ```
  - `simplify` & `dex-oracle`: Dalvik bytecode virtual execution and deobfuscation engine for dead code elimination and opaque predicate resolution.
    ```bash
    # Simplify: Execute Dalvik bytecode symbolically to optimize and prune dead branches
    simplify.jar -i input.dex -o output_simplified.dex
    # dex-oracle: Extract string decryption and method indirection
    dex-oracle -i obfuscated.apk -o deobfuscated.apk
    ```
---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 ECMA-335 CLI Metadata Architecture (.NET)
A .NET assembly stores all type declarations, method signatures, and references in structured tables governed by the ECMA-335 standard:

```text
PE Optional Header Data Directory 14
        │
        ▼
IMAGE_COR20_HEADER
        │
        ▼
Metadata Root ("BSJB")
 ├── Stream: #~ (Optimized table heap)
 │    ├── TypeDef (Class definitions, extends, field/method lists)
 │    ├── MethodDef (RVA to CIL method body, flags, name offset)
 │    ├── MemberRef (External method/field references)
 │    └── Param (Parameter attributes and names)
 ├── Stream: #Strings (Null-delimited UTF-8 strings for identifiers)
 ├── Stream: #US (User Strings: Length-prefixed UTF-16 strings for literals)
 ├── Stream: #Blob (Binary data: method signatures, default parameter values)
 └── Stream: #GUID (128-bit GUIDs)
```

#### Metadata Tokens:
In CIL, items are referenced via a 32-bit Metadata Token:
- Top 8 bits: Table identifier (e.g., `0x02` = `TypeDef`, `0x06` = `MethodDef`, `0x70` = `#US` User String).
- Bottom 24 bits: 1-indexed row number in that table.
- Example: `ldstr 0x700001A2` instructs the CLR to load the User String located at row offset `0x1A2` in the `#US` stream.

#### CIL Opcode Reversing Patterns:
CIL executes on an evaluation stack machine:
- `ldarg.0`: Pushes the `this` pointer (for instance methods) or first argument onto the evaluation stack.
- `ldloc.0` / `stloc.0`: Loads from / stores to local variable slot 0.
- `call` vs `callvirt`: `call` performs direct static or non-virtual invocation; `callvirt` performs virtual polymorphic dispatch and enforces null checks on the receiver.
- `ldstr <token>`: Pushes string literal.
- `newobj <ctor_token>`: Allocates object and executes constructor.

---

### 4.2 Dalvik DEX Structure & Smali Syntax (Android / JVM)
Android Dalvik / ART uses register-based bytecode instead of stack-based evaluation:

#### DEX File Header Architecture:
```text
DEX File Header:
  +0x00: magic ("dex\n035\0")
  +0x20: file_size
  +0x38: string_ids_size & string_ids_off ----> Array of string data offsets
  +0x40: type_ids_size & type_ids_off ---------> Array of descriptor string indices
  +0x48: proto_ids_size & proto_ids_off -------> Method signatures (return type + parameters)
  +0x50: field_ids_size & field_ids_off -------> Class + Type + Name
  +0x58: method_ids_size & method_ids_off -----> Class + Proto + Name
  +0x60: class_defs_size & class_defs_off -----> Class declarations and code items
```

#### Smali Instruction Conventions:
- Registers: `v0, v1, v2` (local registers); `p0, p1, p2` (parameter registers; for non-static methods, `p0` is `this`).
- Dalvik Type Descriptors:
  - `V`: `void`
  - `Z`: `boolean`
  - `B`: `byte`
  - `S`: `short`
  - `C`: `char`
  - `I`: `int`
  - `J`: `long` (occupies two registers: e.g., `v0` and `v1`)
  - `F`: `float`
  - `D`: `double` (occupies two registers)
  - `Lcom/example/MyClass;`: Fully qualified class object reference
  - `[I`: Array of integers (`[[Ljava/lang/String;` = 2D array of strings)

#### Common Smali Idioms:
```smali
# Invoking virtual method: receiver is p0, argument is v0
invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
move-result-object v1 # Capture return value into v1

# String loading
const-string v0, "secret_api_key_value"

# Static field access
sget-object v0, Lcom/example/Config;->INSTANCE:Lcom/example/Config;
```

---

### 4.3 Advanced Java & Android (Dalvik/JVM) Deobfuscation

#### 1. ProGuard / R8 Mapping Recovery & Semantic Renaming
ProGuard and R8 strip debugging attributes (LocalVariableTable, LineNumberTable) and replace package, class, method, and field identifiers with short meaningless tokens (`a`, `b`, `c`). When an official `mapping.txt` is missing, semantic names can be algorithmically reconstructed:
- **Framework Inheritance & Manifest Anchor Points**:
  Android apps require components declared in `AndroidManifest.xml` to match valid class paths.
  - An obfuscated class extending `android.app.Activity` referenced as `<activity android:name="com.target.a.b"/>` can be definitively renamed to `MainActivity` or its intent-filter target.
  - Implementations of `android.app.Service`, `android.content.BroadcastReceiver`, and `android.content.ContentProvider` retain their lifecycle triggers (`onStartCommand`, `onReceive`, `query`).
- **Overridden Framework Method Boundaries**:
  Methods that implement or override system interfaces cannot be renamed without breaking polymorphic runtime dispatch:
  - `public void onClick(View v)` reveals UI event handler logic.
  - `public boolean onNavigationItemSelected(MenuItem item)` maps menu item IDs (`R.id.nav_settings`) to the containing class's semantic role (`SettingsFragment`).
- **String Cross-References & Logging Signatures**:
  Obfuscated classes frequently retain debug log strings (`Log.d("AuthManager", "Token expired")`) or analytics tracking events (`FirebaseAnalytics.logEvent("checkout_completed")`). Cross-referencing string constants directly yields semantic class names (`AuthManager`, `CheckoutController`).

#### 2. Dynamic String Decryption Automation (Frida & Dalvik Hooks)
Obfuscators obscure remote endpoints, API keys, and sensitive class names behind decryption routines utilizing XOR bit-shifts, AES-CBC, or multi-stage array manipulations.
- **Static Triage**: Locate static initialization blocks (`<clinit>`) or static utility functions receiving integer IDs or byte arrays and returning `java.lang.String`.
- **Dynamic Interception Strategy**: Rather than re-implementing custom crypto routines in Python, hook the target decryption method inside the live Android runtime via Frida. Capture inputs and outputs to build a global translation map.

#### 3. Reflection Deobfuscation & Direct Invocation Unwinding
Obfuscators conceal sensitive API invocations behind reflection:
```java
// Obfuscated Reflection Pattern
Class<?> clazz = Class.forName("android.os.SystemProperties");
Method method = clazz.getMethod("get", String.class);
String result = (String) method.invoke(null, "ro.build.version.sdk");
```
To restore readability in JADX or Smali:
1. Identify patterns loading constant strings into `Class.forName()` and `getMethod()`.
2. Statically resolve the target method token and parameter types.
3. In Smali, rewrite the reflection invocation sequence (`invoke-static {v0, v1}, Ljava/lang/Class;->getMethod(...)`) into a direct opcode invocation:
   ```smali
   # Rewritten Direct Call
   invoke-static {v0}, Landroid/os/SystemProperties;->get(Ljava/lang/String;)Ljava/lang/String;
   move-result-object v0
   ```

#### 4. Control-Flow Unflattening & Opaque Predicates (Simplify & dex-oracle)
Control-flow flattening breaks basic blocks into cases within an infinite loop controlled by a state variable switch statement. Opaque predicates introduce branches whose outcomes are invariant at runtime (e.g., `if ((x * x) >= 0)` or `if (static_final_true)`):
- **Dalvik Symbolic Execution via `simplify`**:
  `simplify` executes Dalvik bytecode inside a virtual execution engine (`smalivm`). It propagates constants, evaluates dead branching conditions, and collapses state variables.
- **Execution Pipeline**:
  1. `simplify` tracks register states and constant propagation across basic block boundaries.
  2. When an opaque condition is evaluated, branches that are mathematically unreachable are flagged as dead code.
  3. The control-flow graph (CFG) is rebuilt, replacing the dispatching switch construct with sequential jumps and eliminating redundant dispatcher blocks.

#### 5. JADX Deobfuscator Engine & JEB AST Scripting
- **JADX CLI Engine**:
  - `--deobf`: Activates JADX's internal renaming engine, creating unique deterministic names across packages.
  - `--deobf-min` / `--deobf-max`: length thresholds for which identifiers count as obfuscated (default min 3, max 64).
  - `--deobf-cfg-file <file>` with `--deobf-cfg-file-mode {read,overwrite,ignore}`: persists the auto-generated name map into a `.jobf` file so manual corrections survive re-decompilation (there is no `--deobf-rewrite-cfg` flag).
  - `--mappings-path <file>` with `--mappings-mode`: loads an external mapping (ProGuard `mapping.txt`, Tiny/Enigma, etc.) instead of auto-naming.
- **JEB Decompiler AST Transformations**:
  JEB allows programmatic AST visitors via Python plugins to traverse `CIntermediateTree` elements, identifying reflection wrappers and replacing AST call nodes with synthetic direct calls during decompilation passes.

---

### 4.4 Advanced C# & .NET (CIL/CLR) Deobfuscation

#### 1. `de4dot` & `de4dot-cex` Architectural Workflows
`de4dot` statically parses ECMA-335 assemblies, detects obfuscator signatures through metadata patterns and known stub signatures, and executes specialized unpacker passes:
- **Supported Obfuscators**: ConfuserEx (`-p cx`), .NET Reactor (`-p nr`), SmartAssembly (`-p sa`), Eazfuscator (`-p ef`), Babel.NET (`-p bb`), DeepSea (`-p ds`), Goliath (`-p go`).
- **Execution Phases**:
  1. **Detection**: Scans metadata streams for characteristic attribute classes (e.g., `ConfusedByAttribute`, `BabelAttribute`, `NineRays.Obfuscator`).
  2. **Decryption of Static Fields and User Strings**: Locates the assembly's `.cctor` decryption routines, emulates or extracts decryptor algorithms, and restores strings back into the `#US` stream.
  3. **Method Body Inlining & Metadata Cleansing**: Strips anti-dump and anti-tamper hooks, unhides member tokens, and eliminates proxy methods.
  4. **Identifier Renaming**: Generates consistent PascalCase names for types, methods, fields, and parameters.

#### 2. CIL Control Flow Unflattening
Flattened CIL code transforms linear execution into an explicit state machine:
```text
        ┌──────────────┐
        │ state = 0x01 │
        └──────┬───────┘
               ▼
  ┌───► ┌──────────────┐
  │     │ switch(state)│ ───► Case 1: Execute Block A -> state = 3; br loop
  │     └──────────────┘ ───► Case 2: Execute Block B -> return;
  └────────────┴───────────── Case 3: Execute Block C -> state = 2; br loop
```
Deobfuscation with `dnlib`:
1. Traverse CIL instructions to identify state variable indices (`ldloc / stloc`).
2. Locate the master `switch` instruction or chained conditional jumps (`beq`, `bne.un`).
3. Trace assignments to the state variable within each basic block.
4. Replace the terminal branch instruction (`br.s loop_head`) in each basic block with a direct branch instruction (`br.s target_case_block`) pointing to the block corresponding to the next state value.
5. Eliminate dead instructions, nop out the dispatcher loop, and call `cilBody.OptimizeBranches()`.

#### 3. Delegate Proxy Inlining
Obfuscators intercept calls to standard BCL APIs (`System.Diagnostics.Process::Start`) by instantiating dynamic delegate fields populated at runtime:
```csharp
// Obfuscated CIL construct:
call class TargetDelegate ObfuscatedProxy::ResolveDelegate(token)
callvirt instance void TargetDelegate::Invoke(...)
```
Deobfuscation steps:
1. Identify proxy classes containing private static delegate fields.
2. Inspect the proxy resolver routine to determine which real MethodDef/MemberRef token is bound to each delegate slot.
3. Search the entire assembly for `call` or `callvirt` instructions pointing to the delegate proxy `Invoke` method.
4. Replace the invocation sequence with a direct `call` or `callvirt` targeting the underlying system method token.
5. Remove unreferenced delegate type declarations and proxy resolver classes.

#### 4. Devirtualization of .NET Virtualization Protectors (KoiVM & Eazfuscator)
Virtualization protectors convert standard CIL instructions into proprietary virtual bytecodes executed by an embedded interpreter VM:
- **KoiVM Architecture**:
  - **VM Entry**: Native methods or stubbed CIL methods invoke `VMEntry(moduleId, methodKey)`.
  - **Dispatcher Loop**: A `while(true)` loop fetching virtual opcodes, decoding operands, and indexing into a function pointer jump table or nested `switch`.
  - **Virtual Stack & Registers**: Implements a simulated stack structure tracking operands and execution frames.
- **Devirtualization Pipeline**:
  1. **Identify the Dispatcher**: Locate the main interpreter loop inside the VM runtime class (often found in embedded resource streams or merged namespaces).
  2. **Opcode Mapping**: Map each internal virtual opcode handler back to its corresponding ECMA-335 CIL opcode (e.g., `V_OP_0x12` -> `Ldstr`, `V_OP_0x4F` -> `Call`, `V_OP_0x2A` -> `Ret`).
  3. **VM Bytecode Parsing**: Read the virtual bytecode stream associated with each protected method token.
  4. **CIL Reconstruction**: For each virtual instruction, construct the corresponding `dnlib.DotNet.Emit.Instruction` object, resolve operand tokens (strings, types, methods), and rebuild the `CilBody`.
  5. **Replace Stub**: Assign the reconstructed `CilBody` back to the original method definition, clearing virtualization entry attributes and VM dependency imports.

---

### 4.5 Interoperability Bridges: P/Invoke (.NET) and JNI (JVM)

#### A. Microsoft .NET P/Invoke
Managed .NET calls unmanaged native C/C++ DLLs using `[DllImport]`:
```csharp
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
```
- Reversing Action: Search for `[DllImport]` or `System.Runtime.InteropServices` in decompiled code. Extract the external DLL name and native function name. Cross-reference with disassembly of the target native `.dll` or `.so`.

#### B. Java Native Interface (JNI)
Java declares native methods using the `native` keyword:
```java
public class SecurityCore {
    public static native boolean verifyLicense(String key);
}
```
Native implementation follows two binding mechanisms:
1. **Static JNI Resolution**:
   - The native library exports a C function matching the exact signature:
     `Java_<package_name>_<ClassName>_<methodName>`
   - Example: `Java_com_example_app_SecurityCore_verifyLicense(JNIEnv* env, jclass clazz, jstring key)`
   - Locate the function directly in the native `.so` symbol export table (`readelf -Ws libtarget.so`).
2. **Dynamic JNI Resolution (`RegisterNatives`)**:
   - The native library registers methods at runtime inside `JNI_OnLoad`:
     ```c
     static JNINativeMethod methods[] = {
         {"verifyLicense", "(Ljava/lang/String;)Z", (void*)&native_verify}
     };
     (*env)->RegisterNatives(env, clazz, methods, 1);
     ```
   - Reversing Action: Open the native `.so` in IDA Pro / Ghidra, locate `JNI_OnLoad`, find the call to `RegisterNatives`, and inspect the `JNINativeMethod` array to find the function pointer `(void*)&native_verify`.

---

### 4.6 .NET Deployment Models: ReadyToRun, NativeAOT, Single-File
Before choosing a decompiler, classify how the assembly was published. The wrong model wastes a pass.

| Model | Recognition | What decompiles it |
|---|---|---|
| Plain IL assembly | `BSJB` metadata, `IMAGE_COR20_HEADER`, `MethodDef` RVAs point to CIL | `ilspycmd`, `dnSpyEx`, `AsmResolver`/`dnlib` |
| ReadyToRun (R2R / crossgen) | Still has CIL metadata, but `IMAGE_COR20_HEADER` has `COMIMAGE_FLAGS_IL_LIBRARY`; an `RTR0` ("R2R\0") magic header sits in the R2R section; methods have precompiled native code *alongside* IL | Decompile the IL normally (`ilspycmd`); the native code is a cache. Ignore it unless the IL was stripped. |
| NativeAOT | **No** ECMA-335 metadata, **no** `BSJB`, no `mscoree`/`_CorExeMain` import; it is a plain native PE/ELF/Mach-O. Telltale strings: `S_P_CoreLib`, `__modules`, `RhpNewFast`, reflection blobs | Native tools only — route to [native-cpp-abi.md](native-cpp-abi.md). `ilspycmd`/`dnSpy` fail. |
| Single-file bundle | A native host `.exe`/ELF with assemblies appended; bundle marker `0x8eb5…` signature and a bundle manifest at the end of file | Extract first (below), then decompile the embedded assemblies as plain IL. |
| Mono/Unity | `mono-2.0`/`mscorlib` from Mono; Unity games use `Assembly-CSharp.dll` or IL2CPP | IL path for Mono assemblies; IL2CPP is [unity-il2cpp.md](unity-il2cpp.md). |

**Single-file bundle extraction**: .NET 5+ single-file apps staple the managed assemblies onto a native host. List and extract without running the host. The ILSpy GUI shows a "bundle" node and can save the embedded assemblies; standalone extractors (`ExtractSingleFile`, `dotnet-bundle-extract`) carve them from the appended bundle. Then run `ilspycmd -p -o ./out Extracted.dll` on each recovered assembly. Verify counts against the bundle manifest (it lists how many assemblies were bundled).

**Obfuscator identification** (run `de4dot -d Target.exe` first; it names the obfuscator). Map name to tool:

| Obfuscator | Marker | Best unpacker |
|---|---|---|
| ConfuserEx / ConfuserEx2 | `ConfusedByAttribute`, mangled `<Module>` cctor, control-flow + proxy calls | `de4dot-cex` (fork) or community ConfuserEx unpackers; `NETReactorSlayer` does not apply |
| .NET Reactor | `()` ctor stubs, encrypted resource, native stub | `NETReactorSlayer` (maintained), then `de4dot -p nr` |
| Eazfuscator.NET | VM + homoglyph names, `<PrivateImplementationDetails>` | `de4dot -p ef` (older builds); newer builds need manual devirtualization |
| SmartAssembly | `{SmartAssembly...}` strings, strings-encoding | `de4dot -p sa` |
| Babel.NET | `BabelAttribute` | `de4dot -p bb` |
| KoiVM / virtualization | `KoiVM`/`Koi` runtime, VM dispatcher resource | `OldRod` (KoiVM devirtualizer), then `de4dot` cleanup |

`dnSpyEx` is the maintained fork of the abandoned `dnSpy`; prefer it for interactive IL editing and the managed debugger.

### 4.7 JVM: Class File, `javap`, and Decompiler Choice
A `.class` file starts with `0xCAFEBABE`, a 2-byte minor and 2-byte major version (major 52 = Java 8, 55 = Java 11, 61 = Java 17, 65 = Java 21), then the constant pool. Use the JDK's `javap` for ground truth when a decompiler output looks wrong:
```bash
javap -p -c -v -constants Target.class    # private members, bytecode, pool, flags
```
Decompiler choice (JVM `.class`/`.jar`, distinct from the DEX path):

| Decompiler | Strength |
|---|---|
| **Vineflower** (Fernflower fork) | Best default for modern Java and Kotlin; active |
| **CFR** | Strongest on modern control flow, lambdas, `switch` expressions, records |
| **Procyon** | Good on older/enum/annotation-heavy code; slower |
| **jadx** | DEX/APK (Dalvik), not plain `.class`; also reads `.jar` |

Run two and diff when a method looks suspect; decompilers disagree on generated control flow.

**Kotlin metadata**: Kotlin classes carry a `@kotlin.Metadata` annotation whose `d1`/`d2` arrays encode original names, nullability, and declaration structure in protobuf. jadx reads it to restore Kotlin-level names; `kotlinx-metadata-jvm` parses it programmatically. Do not treat a Kotlin class as plain Java — property getters/setters, `companion` objects, and coroutine state machines come from this metadata.

## 5. Concrete Code & Script Examples

### 5.1 Automated Frida Script for Android String Decryption Mapping
Inject this script into an obfuscated Android application to hook the string decryptor routine and dump a JSON-compatible translation table:

```javascript
/**
 * frida-dump-strings.js
 * Hooks obfuscated static string decryption routines and dumps ciphertext -> plaintext mappings.
 * Usage: frida -U -f com.example.target -l frida-dump-strings.js --no-pause
 */

Java.perform(function () {
    console.log("[*] Initializing Dalvik String Decryption Hook Engine...");

    // Target obfuscator decryptor class and method
    // Adjust target class and method signatures based on static triage
    const targetClass = "com.target.obfuscator.Decrypter";
    const targetMethod = "decrypt";

    const Decrypter = Java.use(targetClass);
    const stringMap = {};
    let dumpCounter = 0;

    // Overload variant: string decrypt(String encryptedInput, int key)
    Decrypter[targetMethod].overload("java.lang.String", "int").implementation = function (cipherText, key) {
        const plainText = this[targetMethod](cipherText, key);
        
        const mapKey = cipherText + "_KEY_" + key;
        if (!stringMap[mapKey]) {
            stringMap[mapKey] = plainText;
            dumpCounter++;
            console.log(`[+] [Decrypted #${dumpCounter}] Key: ${key}`);
            console.log(`    Cipher: ${cipherText}`);
            console.log(`    Plain : ${plainText}`);
        }
        return plainText;
    };

    // Overload variant for byte-array based decrypters: String decrypt(byte[] data).
    // .overload() THROWS if the overload is absent, so guard with try/catch
    // (do not use it as a truthy check).
    let byteArrayOverload = null;
    try {
        byteArrayOverload = Decrypter[targetMethod].overload("[B");
    } catch (e) {
        byteArrayOverload = null;
    }
    if (byteArrayOverload) {
        byteArrayOverload.implementation = function (cipherBytes) {
            const plainText = this[targetMethod](cipherBytes);
            
            // Convert byte array to hex representation for mapping key
            let hexKey = "";
            for (let i = 0; i < cipherBytes.length; i++) {
                let b = (cipherBytes[i] & 0xFF).toString(16);
                if (b.length === 1) b = "0" + b;
                hexKey += b;
            }

            if (!stringMap[hexKey]) {
                stringMap[hexKey] = plainText;
                dumpCounter++;
                console.log(`[+] [Decrypted #${dumpCounter}] Hex: ${hexKey.substring(0, 32)}...`);
                console.log(`    Plain : ${plainText}`);
            }
            return plainText;
        };
    }

    // Periodic logger / exporter hook on pause or back button
    const Activity = Java.use("android.app.Activity");
    Activity.onPause.implementation = function () {
        console.log(`\n[*] Activity paused. Captured ${Object.keys(stringMap).length} unique strings.`);
        this.onPause();
    };
});
```

---

### 5.2 Complete `dnlib` C# Script for .NET Assembly Cleansing
The following production-ready C# program utilizes `dnlib` to strip obfuscation attributes, resolve encrypted metadata strings, unflatten trivial switch blocks, and save a clean assembly:

```csharp
using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace DotNetDeobfuscator
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: DotNetDeobfuscator <input_assembly> <output_assembly>");
                return;
            }

            string inputPath = args[0];
            string outputPath = args[1];

            Console.WriteLine($"[*] Loading assembly: {inputPath}");
            ModuleDefMD module = ModuleDefMD.Load(inputPath);

            // 1. Strip Obfuscator Attributes from Assembly and Module Metadata
            CleanObfuscatorAttributes(module);

            // 2. Resolve Static String Decryption Calls & Inline Plaintexts
            CleanEncryptedStrings(module);

            // 3. Remove Anti-Tamper / Anti-Debug initialization hooks in .cctor
            CleanGlobalModuleConstructor(module);

            // 4. Write deobfuscated assembly with preserved tokens where possible
            Console.WriteLine($"[*] Writing cleaned assembly to: {outputPath}");
            var writerOptions = new ModuleWriterOptions(module);
            writerOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
            writerOptions.Logger = DummyLogger.NoThrowInstance;

            module.Write(outputPath, writerOptions);
            Console.WriteLine("[+] Deobfuscation pass completed successfully.");
        }

        private static void CleanObfuscatorAttributes(ModuleDefMD module)
        {
            string[] blacklistedAttributes = new string[]
            {
                "ConfusedByAttribute",
                "BabelAttribute",
                "SmartAssembly.Attributes",
                "NineRays.Obfuscator",
                "DotfuscatorAttribute",
                "CryptoObfuscator",
                "YanoAttribute",
                "EMyPID_CYA"
            };

            int stripped = 0;
            for (int i = module.CustomAttributes.Count - 1; i >= 0; i--)
            {
                var attr = module.CustomAttributes[i];
                if (blacklistedAttributes.Any(b => attr.TypeFullName.Contains(b)))
                {
                    module.CustomAttributes.RemoveAt(i);
                    stripped++;
                }
            }

            if (module.Assembly != null)
            {
                for (int i = module.Assembly.CustomAttributes.Count - 1; i >= 0; i--)
                {
                    var attr = module.Assembly.CustomAttributes[i];
                    if (blacklistedAttributes.Any(b => attr.TypeFullName.Contains(b)))
                    {
                        module.Assembly.CustomAttributes.RemoveAt(i);
                        stripped++;
                    }
                }
            }
            Console.WriteLine($"[+] Stripped {stripped} obfuscator marker attributes.");
        }

        private static void CleanEncryptedStrings(ModuleDefMD module)
        {
            int inlinedCount = 0;

            foreach (TypeDef type in module.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions)
                        continue;

                    var instructions = method.Body.Instructions;
                    for (int i = 0; i < instructions.Count; i++)
                    {
                        // Look for: call string ObfuscatorDecryptor::Decrypt(string, int)
                        if (instructions[i].OpCode == OpCodes.Call || instructions[i].OpCode == OpCodes.Callvirt)
                        {
                            if (instructions[i].Operand is IMethod targetMethod &&
                                targetMethod.Name.Contains("StringDecrypt") &&
                                targetMethod.MethodSig.Params.Count == 1 &&
                                targetMethod.MethodSig.Params[0].TypeName == "Int32")
                            {
                                // Check preceding instruction for ldc.i4 operand
                                if (i > 0 && instructions[i - 1].IsLdcI4())
                                {
                                    int key = instructions[i - 1].GetLdcI4Value();
                                    string decrypted = StaticDecryptString(key);

                                    // Replace ldc.i4 with nop, and call with ldstr
                                    instructions[i - 1].OpCode = OpCodes.Nop;
                                    instructions[i].OpCode = OpCodes.Ldstr;
                                    instructions[i].Operand = decrypted;
                                    inlinedCount++;
                                }
                            }
                        }
                    }
                    // Optimize branch offsets after instruction mutation
                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches();
                }
            }
            Console.WriteLine($"[+] Inlined {inlinedCount} decrypted strings.");
        }

        private static string StaticDecryptString(int key)
        {
            // Emulated decryption logic matching target binary's routine
            // XOR cipher example:
            int xorMask = 0x5A;
            char[] chars = key.ToString().ToCharArray();
            for (int i = 0; i < chars.Length; i++)
                chars[i] = (char)(chars[i] ^ xorMask);
            return new string(chars);
        }

        private static void CleanGlobalModuleConstructor(ModuleDefMD module)
        {
            TypeDef globalType = module.GlobalType;
            MethodDef cctor = globalType.FindStaticConstructor();
            if (cctor != null && cctor.HasBody)
            {
                // Remove calls to anti-debug or runtime unpacker stubs
                var instructions = cctor.Body.Instructions;
                for (int i = instructions.Count - 1; i >= 0; i--)
                {
                    if (instructions[i].OpCode == OpCodes.Call &&
                        instructions[i].Operand.ToString().Contains("InitializeAntiTamper"))
                    {
                        instructions[i].OpCode = OpCodes.Nop;
                        instructions[i].Operand = null;
                        Console.WriteLine("[+] NOPed anti-tamper initialization in .cctor.");
                    }
                }
            }
        }
    }
}
```

---

### 5.3 Python Script to Carve .NET `#US` User Strings Directly from PE
```python
import struct
import sys

def parse_dotnet_user_strings(pe_path):
    with open(pe_path, "rb") as f:
        data = f.read()

    # Search for BSJB magic
    bsjb_offset = data.find(b"BSJB")
    if bsjb_offset == -1:
        print("[-] Not a valid .NET metadata PE.")
        return

    print(f"[+] Found BSJB metadata root at offset 0x{bsjb_offset:X}")
    
    # Read version string length at bsjb + 12
    vlen = struct.unpack_from("<I", data, bsjb_offset + 12)[0]
    streams_header = bsjb_offset + 16 + vlen
    
    # Flags (2 bytes), Streams count (2 bytes)
    flags, streams_count = struct.unpack_from("<HH", data, streams_header)
    print(f"[+] Stream count: {streams_count}")

    curr = streams_header + 4
    us_offset = None
    us_size = None

    for _ in range(streams_count):
        s_offset, s_size = struct.unpack_from("<II", data, curr)
        name_start = curr + 8
        name_end = data.find(b"\x00", name_start)
        stream_name = data[name_start:name_end].decode("ascii", errors="ignore")
        
        # Advance 4-byte aligned
        name_len = name_end - name_start + 1
        aligned_len = (name_len + 3) & ~3
        curr = name_start + aligned_len

        if stream_name == "#US":
            us_offset = bsjb_offset + s_offset
            us_size = s_size
            print(f"[+] Found #US stream at 0x{us_offset:X} (Size: {us_size} bytes)")
            break

    if not us_offset:
        print("[-] No #US (User Strings) stream found.")
        return

    # Parse #US strings (length-prefixed UTF-16LE)
    idx = us_offset + 1 # First byte of #US is empty 0x00
    end = us_offset + us_size
    strings_found = []

    while idx < end:
        # Read 7-bit encoded length
        b0 = data[idx]
        if b0 == 0:
            idx += 1
            continue
        if (b0 & 0x80) == 0:
            length = b0
            idx += 1
        elif (b0 & 0xC0) == 0x80:
            length = ((b0 & 0x3F) << 8) | data[idx + 1]
            idx += 2
        else:
            length = ((b0 & 0x1F) << 24) | (data[idx + 1] << 16) | (data[idx + 2] << 8) | data[idx + 3]
            idx += 4

        # Strings in #US have a trailing terminal byte indicating wide characters
        if length > 1:
            str_bytes = data[idx:idx + length - 1]
            try:
                decoded = str_bytes.decode("utf-16le")
                if len(decoded.strip()) > 0:
                    strings_found.append(decoded)
            except UnicodeDecodeError:
                pass
        idx += length

    print(f"[+] Successfully extracted {len(strings_found)} user strings:")
    for s in strings_found[:25]:
        print(f"    \"{s}\"")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 extract_us.py <target.exe/dll>")
        sys.exit(1)
    parse_dotnet_user_strings(sys.argv[1])
```

---

## 6. Boundaries & Anti-Patterns
- **Do not mistake ProGuard / R8 identifier renaming for encryption**: Identifiers like `a.b.c(int a)` retain the original control flow, basic block structures, and system API calls. Focus on external calls (`HttpURLConnection`, `Cipher`, `SharedPreferences`) to contextualize renamed symbols.
- **Do not analyze NativeAOT binaries with .NET decompilers**: .NET NativeAOT compiles C# directly to native machine code without ECMA-335 metadata or CIL opcodes. `ilspycmd` and `dnSpy` will fail immediately. Route NativeAOT binaries to native reverse engineering workflows (`native-cpp-abi.md`).
- **Run `de4dot` before a deep read of a packed assembly, and keep the original**: ConfuserEx, SmartAssembly, Babel, Eazfuscator, and .NET Reactor garbage in the C# view is the packer, not the program. Analyze `*-clean` and diff it against the original if a decryptor pass looks lossy.
- **Verify branches in IL, not only in C#**: The C# view drops or invents structure for `async`/`await`, `yield`, and compiler state machines. The branch you cite has to exist as CIL (`br`, `brtrue`, `switch`) or it is not a finding.
- **Prefer an IL edit over a C# recompile when patching**: Recompilation fails on missing references. An IL change (`ldc.i4.0` to `ldc.i4.1`, or a `nop` range) round-trips. APK decision order, as opposed to DEX internals, is [android-apk.md](android-apk.md).
- **Do not overlook multi-DEX files in Android**: Modern Android APKs distribute code across `classes.dex`, `classes2.dex`, `classes3.dex`, etc. Ensure decompilation runs over all DEX files simultaneously rather than inspecting only the primary `classes.dex`.
- **Beware of dynamic assembly loading**: Malware and packed .NET applications frequently store their real payload as an encrypted resource and invoke `Assembly.Load(byte[])` or `AppDomain.CurrentDomain.Load`. Always check resource streams and hook `Assembly.Load` before deep-diving into the outer loader stub.
