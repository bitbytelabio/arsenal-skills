# Dynamic Binary Instrumentation & Frida Hooking

## Title & Overview
- **Domain**: Dynamic Binary Instrumentation (DBI) using Frida across native libraries (ELF/PE/Mach-O), Android ART/Dalvik, and iOS/macOS Objective-C/Swift runtimes.
- **Scope**: DBI fundamentals, spawning vs attaching, synchronous vs asynchronous hooks, intercepting libc/Win32 APIs, reading and writing memory buffers, dumping live objects, and SSL/TLS pinning bypass.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Target requires fine-grained runtime inspection without halting entire processes in an interactive debugger.
- Analyzing Android applications with Java/Kotlin methods or JNI native boundaries (`.so` libraries).
- Analyzing iOS applications with Objective-C messaging (`objc_msgSend`) or Swift runtime calls.
- Need to observe decrypted strings, API arguments, cryptographic session keys, or protocol frames before transport encryption.
- Target employs anti-debugging or ptrace restrictions that complicate traditional debugger attachment.

---

## Tooling & CLI/MCP Actions

### Primary Tooling Matrix
- **Frida CLI Tools**:
  - `frida-ps`: Enumerate processes on local host, USB device, or remote daemon.
  - `frida`: Interactive REPL and script injection environment.
  - `frida-trace`: Rapid API tracer generating hook templates automatically.
- **Daemons & Agents**:
  - Android: `frida-server` (deployed to `/data/local/tmp/`, run as `root`).
  - iOS: `frida-server` (installed via Sileo/Zebra on jailbroken iOS or research VM).
  - Environment helper: `scripts/setup_android_emulator.py`.

### Process Connection & Execution Modes
```bash
# 1. Enumerate processes on connected USB device
frida-ps -U -a

# 2. Enumerate processes on remote network daemon
frida-ps -H 192.168.64.5:27042

# 3. Spawn Mode: Spawns process frozen at startup, injects script, and resumes execution
frida -U -f com.example.targetapp -l hooks.js

# 4. Attach Mode: Injects script into an existing running process by PID or name
frida -U -n "target_process" -l hooks.js
frida -p 1337 -l hooks.js
```

---

## Core Methodologies & Step-by-Step Technical Workflow

### 1. DBI Fundamentals: Architecture & Lifecycle
Frida operates by injecting Google's V8 (or QuickJS on constrained devices) JavaScript runtime into the target address space:
1. **Injector Stage**: Frida client uses OS-specific debugging APIs (`ptrace` on Linux/Android, `task_for_pid` / `mach_vm_*` on macOS/iOS, `CreateRemoteThread` on Windows) to allocate memory and load `frida-agent.so` / `frida-agent.dylib` / `frida-agent.dll`.
2. **Runtime Engine**: The agent bootstraps the JavaScript engine inside a dedicated agent thread.
3. **Interception**: Frida modifies the function prologue at runtime by replacing the first several bytes with an unconditional jump (`trampoline`) to dynamic trampoline stubs that invoke `onEnter` and `onLeave` callbacks before returning execution to the original instruction stream.

### 2. Synchronous vs Asynchronous Hooking Architecture

| Hooking Paradigm | Mechanism | Latency / Impact | Use Case |
|---|---|---|---|
| **Synchronous Hooks** (`send()`, `recv().wait()`) | JavaScript thread pauses until Frida host client acknowledges via IPC message | High latency; blocks application thread; causes ANR or watchdog timeouts | Interactive parameter alteration, stepping, or awaiting external decisions |
| **Asynchronous Hooks** (`console.log()`, non-blocking `send()`) | Enqueues messages to background buffer without stalling application execution | Ultra-low overhead; non-blocking; minimal target disruption | Bulk tracing, crypto key harvesting, passive protocol observation |

### 3. Intercepting Native C/C++ APIs (Libc, Win32, Custom SOs)

#### Resolving Exported and Unexported Symbols
- **Exported Symbols**: Resolved directly using `Module.findExportByName(moduleName, symbolName)`.
- **Unexported / Stripped Symbols**: Resolved by finding the module base address via `Process.findModuleByName(moduleName).base` and adding the static VMA offset.

#### Reading and Writing Memory Buffers
```javascript
// intercept_native.js
var libc = Process.platform === 'windows' ? 'msvcrt.dll' : 'libc.so';
var openPtr = Module.findExportByName(null, 'open');

if (openPtr) {
    Interceptor.attach(openPtr, {
        onEnter: function (args) {
            // Read null-terminated UTF-8 / ASCII string from pointer
            var path = Memory.readUtf8String(args[0]);
            var flags = args[1].toInt32();
            console.log("[*] open() invoked: path=" + path + " flags=0x" + flags.toString(16));

            // Passive inspection of buffer if reading specific file
            if (path.indexOf("target_config.dat") !== -1) {
                this.isTarget = true;
            }
        },
        onLeave: function (retval) {
            var fd = retval.toInt32();
            if (this.isTarget) {
                console.log("[+] target_config.dat opened with file descriptor: " + fd);
            }
        }
    });
}
```

### 4. Advanced Memory Dumping & Object Inspection
```javascript
// Memory dumping helper function
function dumpMemoryRegion(ptr, length) {
    if (ptr.isNull()) {
        console.log("[-] Buffer pointer is NULL");
        return;
    }
    console.log(hexdump(ptr, {
        offset: 0,
        length: length,
        header: true,
        ansi: false
    }));
}

// Hooking custom decryption routine: void decrypt(char *in, char *out, int len, char *key)
var targetMod = Process.findModuleByName("libcrypto_core.so");
if (targetMod) {
    var decryptOffset = 0x0001a450; // Offset identified from static analysis
    var decryptAddr = targetMod.base.add(decryptOffset);

    Interceptor.attach(decryptAddr, {
        onEnter: function (args) {
            this.outBuf = args[1];
            this.len = args[2].toInt32();
            var keyBuf = args[3];

            console.log("[*] Decrypt called. Length: " + this.len);
            console.log("[*] Encryption Key:");
            dumpMemoryRegion(keyBuf, 16);
        },
        onLeave: function (retval) {
            console.log("[+] Decrypted Output Buffer:");
            dumpMemoryRegion(this.outBuf, Math.min(this.len, 128));
        }
    });
}
```

### 5. Android Java / ART Hooking Workflows
```javascript
// android_art_hooks.js
Java.perform(function () {
    console.log("[*] Attached to Android Java VM");

    // 1. Locate Target Class
    var TargetClass = Java.use("com.example.service.CryptoHelper");

    // 2. Handle Method Overloads Specifically
    // public byte[] processData(String action, byte[] payload)
    TargetClass.processData.overload('java.lang.String', '[B').implementation = function (action, payload) {
        console.log("[+] CryptoHelper.processData called with action: " + action);

        // Convert byte array to hex string
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        var hexData = ByteString.of(payload).hex();
        console.log("    Payload (hex): " + hexData);

        // Call original method implementation
        var result = this.processData(action, payload);

        var hexResult = ByteString.of(result).hex();
        console.log("    Result (hex): " + hexResult);

        return result;
    };

    // 3. Instance Enumeration and Dumping
    Java.choose("com.example.model.SessionState", {
        onMatch: function (instance) {
            console.log("[*] Found SessionState active instance: " + instance);
            console.log("    User ID: " + instance.userId.value);
            console.log("    Session Token: " + instance.sessionToken.value);
        },
        onComplete: function () {
            console.log("[*] SessionState enumeration finished");
        }
    });
});
```

### 6. iOS / macOS Objective-C and Swift Hooking Workflows
```javascript
// ios_objc_swift_hooks.js
if (ObjC.available) {
    console.log("[*] Objective-C Runtime Available");

    // Intercept Objective-C Selector: -[AuthenticationController handleLogin:password:]
    var hook = ObjC.classes.AuthenticationController["- handleLogin:password:"];
    if (hook) {
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                // args[0] = self (instance pointer)
                // args[1] = _cmd (selector pointer)
                // args[2] = first argument
                // args[3] = second argument
                var username = ObjC.Object(args[2]).toString();
                var password = ObjC.Object(args[3]).toString();
                console.log("[+] Login Attempt: User=" + username + " Pass=" + password);
            }
        });
    }

    // Intercept Swift Method via Mangled Export Name
    var swiftSymbol = "_$s10TargetApp12DataSecurityC14verifyChecksum6bufferSb10Foundation0D0V_tF";
    var swiftPtr = Module.findExportByName(null, swiftSymbol);
    if (swiftPtr) {
        Interceptor.attach(swiftPtr, {
            onEnter: function (args) {
                console.log("[*] Swift DataSecurity.verifyChecksum() intercepted");
            },
            onLeave: function (retval) {
                console.log("[+] Checksum validation returned: " + retval);
            }
        });
    }
}
```

### 7. SSL/TLS Pinning Bypass Mechanics
Integrates with `scripts/setup_proxy_ca.py`:
- **OkHttp3 CertificatePinner**: Hooks `okhttp3.CertificatePinner.check(String, List)` and `check$okhttp(String, Function0)` to act as no-ops.
- **Conscrypt / Android TrustManager**: Replaces `TrustManagerImpl.checkTrustedRecursive` to return an empty trusted certificate chain list.
- **iOS `NSURLSession`**: Hooks `-[NSURLSession sessionWithConfiguration:delegate:delegateQueue:]` delegate challenge callbacks to accept the proxy certificate.

---

## Boundaries & Anti-Patterns
- **Do not introduce heavy synchronous locks in high-frequency hooks**: Hooking tight loops (e.g. per-byte decryptors or `memcpy`) with `send()` or `console.log()` will cause catastrophic target deadlocks or severe throttling; use debugger tracepoints or batch logging instead.
- **Do not modify control flow to exploit or alter software behavior**: Observe return values, memory, and crypto structures passively; do not inject exploit payloads or bypass licensing gates destructively.
- **Do not run Frida against production endpoints or unisolated hosts**: Perform DBI strictly in contained lab environments and isolated virtual machines.
