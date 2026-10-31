# Frida Tool Usage, Mobile Setup, and TLS Unpinning

## Purpose

Use this reference to drive Frida itself: versions, the CLI tools, the Python API, compiled agents, Gadget, the mobile pre-flight gate, and TLS unpinning on Android and iOS. Hooking methodology (what to hook, Interceptor vs Stalker, CModule, memory scans, detection vectors) is in [`frida-hooking.md`](../02-dynamic-instrumentation/frida-hooking.md). Installing a proxy CA and bypassing pinning are separate operations: the CA makes the proxy certificate a trust anchor, while the hooks neutralize application-enforced pins.

Read [`network-traffic-proxy.md`](../02-dynamic-instrumentation/network-traffic-proxy.md) for proxy routing and capture, and [`flutter-dart.md`](../01-static-architectures/flutter-dart.md) for Flutter's statically linked BoringSSL path. Untrusted samples are instrumented only inside the lab from [`malware-sandbox-isolation.md`](../02-dynamic-instrumentation/malware-sandbox-isolation.md).

## Versions and the Frida 17 Break

The client (`frida-tools` + the `frida` Python package) and the injected side (`frida-server` or Gadget) must share a major version. Check both before debugging a hook:

```bash
frida --version
uv run --with "frida==17.*" python -c "import frida; print(frida.__version__)"
frida-ps -U >/dev/null && echo "server reachable"
```

Frida 17 removed the static `Module.*ExportByName` forms, `Module.findBaseAddress`, and the `Memory.readXxx`/`Memory.writeXxx` statics. It also stopped putting `Java`, `ObjC`, and `Swift` into every script. The migration table and verified replacements are in [`frida-hooking.md`](../02-dynamic-instrumentation/frida-hooking.md#frida-17-api-baseline). Where each bridge is available:

| How the script is loaded | `Java` / `ObjC` / `Swift` globals |
|---|---|
| `frida ... -l script.js` (REPL, including `-q`) | Present. The REPL bundles the bridges. |
| `frida-trace` handlers | Present. |
| Python/Node `session.create_script(source)` | Absent. Verified: `typeof ObjC === 'undefined'`. |
| Agent built with `frida-compile` | Present only if imported: `import ObjC from "frida-objc-bridge"`. |

## CLI Reference

| Task | Command |
|---|---|
| List devices | `frida-ls-devices` |
| Processes / apps on USB device | `frida-ps -U`, `frida-ps -Uai` (apps, installed, with identifiers), `-j` for JSON |
| Processes on a remote server | `frida-ps -H 192.168.64.5:27042` |
| Spawn, load, resume | `frida -U -f "$PACKAGE_ID" -l agent.js` (spawned programs resume after load; add `--pause` to keep the main thread paused, then `%resume`) |
| Spawn a local program | `frida -f "$PWD/sample" -l agent.js -- arg1` (an absolute path avoids "unable to find application") |
| Attach by name / PID / identifier | `-n NAME`, `-p PID`, `-N com.example.app`, `-F` (frontmost app) |
| Wait for a process to appear | `frida -U -W com.example.app -l agent.js` |
| Non-interactive run with a bound | `frida -U -n NAME -l agent.js -q -t 30` (quiet, exit after 30 s; `-t inf` runs until killed) |
| Write output to a file | `-o session.log` |
| Fail fast in automation | `--exit-on-error`, `--kill-on-exit` |
| Pass parameters to a script | `-P '{"rva": "0x1a450"}'`, read as the global `parameters` |
| Load a C module | `-C hooks.c` |
| Choose the JS runtime | `--runtime=v8` (better JIT for heavy scripts) or `--runtime=qjs` (default) |
| Emulated realm (Android x86 emulators with ARM libraries) | `--realm=emulated` |
| Kill / file transfer | `frida-kill -U PID`, `frida-pull`, `frida-push`, `frida-ls`, `frida-rm` |

Every automated `frida` invocation needs `-q -t SECONDS` or an outer `timeout`. Without them a non-interactive run waits forever at the REPL.

### frida-trace

```bash
frida-trace -U -f "$PACKAGE_ID" -i 'libssl.so!SSL_write' -i 'libssl.so!SSL_read' -o trace.log
frida-trace -p "$PID" -i 'open*' -x 'openat64' -I libtarget.so -a 'libtarget.so!0x1a450'
frida-trace -U -N com.example.app -m '-[NSURLSession dataTask*]' -j '*!*certificate*/isu'
```

| Flag | Meaning |
|---|---|
| `-i MOD!FUNC` / `-x MOD!FUNC` | Include / exclude functions by glob (`MOD!` optional) |
| `-I MOD` / `-X MOD` | Include / exclude all exports of a module |
| `-a MOD!OFFSET` | Hook an unexported function by RVA; the handler is named `sub_<offset>` |
| `-T` / `-t MOD` | Include the program's imports / one module's imports |
| `-m` / `-M` | Include / exclude ObjC methods (`-[Class sel*]`) |
| `-y` / `-Y` | Include / exclude Swift functions |
| `-j` / `-J` | Include / exclude Java methods (`Class!method`, suffix `/i` case-insensitive, `/s` include signatures, `/u` user classes only) |
| `-s SYMBOL` | Include a debug symbol |
| `-S init.js` | Run a JS file first, for shared helpers |
| `-P JSON` | Parameters exposed as `parameters` |
| `-d` | Prefix log lines with the module name |
| `-o FILE` | Write messages to a file |

Handlers are generated under `./__handlers__/<module>/<function>.js` and reused on the next run. Frida 17 handlers use `defineHandler({ onEnter(log, args, state) {...}, onLeave(log, retval, state) {...} })`. Edit the handler to decode arguments. Delete it to regenerate. Verified on 17.17: `-i`, `-a`, and import tracing generated handlers and logged calls with timestamps and thread IDs.

`frida-itrace` records instruction-level traces of a range. `frida-strace` traces syscalls on Linux and Android. Both are slower than `frida-trace`; scope them narrowly.

## Python API

Use the Python API when the session needs logic: collecting binary messages, RPC calls, spawn gating, or several processes. Verified against Frida 17.25 Python bindings and a 17.17 Gadget:

```python
# drive.py — uv run --with "frida==17.*" python drive.py "$PACKAGE_ID" agent.js spawn
#            uv run --with "frida==17.*" python drive.py "$PROCESS_NAME" agent.js attach
import sys, time, frida

target, agent_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]
device = frida.get_usb_device(timeout=5)          # or frida.get_device_manager().add_remote_device("HOST:PORT")
pid = device.spawn([target]) if mode == "spawn" else None
session = device.attach(pid if pid is not None else target)
session.on("detached", lambda reason, crash: print(f"[detached] {reason} {crash}"))

script = session.create_script(open(agent_path).read())
records = []
def on_message(message, data):
    if message["type"] == "send":
        records.append((message["payload"], data))
    else:
        print(message.get("stack", message))
script.on("message", on_message)
script.load()
if pid is not None:
    device.resume(pid)

time.sleep(10)                                    # bounded observation window
print(f"[drive] {len(records)} messages")
print(script.exports_sync.counter() if "counter" in script.list_exports_sync() else "")
script.unload()
session.detach()
```

- `device.spawn(program, argv=None, envp=None, env=None, cwd=None, stdio=None)` returns a PID in the suspended state. Always `device.resume(pid)`.
- `script.exports_sync.name(...)` calls `rpc.exports.name`. `script.list_exports_sync()` lists them.
- `message["type"] == "error"` carries `description`, `stack`, `fileName`, `lineNumber`.
- Spawn gating (`device.enable_spawn_gating()`, `spawn-added`) and child gating (`session.enable_child_gating()`, `child-added`) are in [`frida-hooking.md`](../02-dynamic-instrumentation/frida-hooking.md#early-instrumentation).
- `session.compile_script(source)` returns bytecode for faster repeated loads (`create_script_from_bytes`).

## Compiled Agents and Bridges

Agents with npm dependencies (bridges, `frida-il2cpp-bridge`, TypeScript) are compiled into one bundle. Verified: an agent importing `frida-objc-bridge` and `frida-java-bridge` compiled with `frida-compile` and reported `ObjC.available === true` on macOS.

```bash
AGENT_DIR="$PWD/agent"            # your own scratch directory, never the sample's
mkdir -p "$AGENT_DIR" && cd "$AGENT_DIR"
npm init -y >/dev/null
npm install frida-java-bridge frida-objc-bridge @types/frida-gum
cat > agent.ts <<'EOF'
import Java from "frida-java-bridge";
import ObjC from "frida-objc-bridge";
console.log(`Java=${Java.available} ObjC=${ObjC.available}`);
EOF
frida-compile agent.ts -o _agent.js -S      # frida-tools ships frida-compile; -S omits source maps
frida -U -f "$PACKAGE_ID" -l _agent.js -q -t 20
```

`frida-create -t agent` scaffolds the same layout. Unity IL2CPP targets use `frida-il2cpp-bridge`; see [`unity-il2cpp.md`](../01-static-architectures/unity-il2cpp.md).

## Frida Gadget

Gadget is the Frida runtime as a shared library loaded by the target itself. Use it when no `frida-server` can run (non-rooted Android, non-jailbroken iOS, sandboxed processes) or when the injector is detected.

Gadget reads a JSON config named after its own file: `libfrida-gadget.so` → `libfrida-gadget.config.so` on Android (the `.so` suffix makes the package installer extract it), `frida-gadget.dylib` → `frida-gadget.config` elsewhere.

| `interaction.type` | Behavior | Use |
|---|---|---|
| `listen` (default, `127.0.0.1:27042`) | Waits for a client; `on_load: "wait"` blocks the app until attach, `"resume"` does not | Interactive work: `frida -H 127.0.0.1:27042 -n Gadget -l agent.js` |
| `connect` | Connects out to a `frida-portal` | Many devices, one controller |
| `script` | Runs a local JS file, no client needed | Unattended capture, CI, devices without a network path |
| `script-directory` | Runs scripts matching a filter per process | System-wide on rooted images |

```json
{ "interaction": { "type": "script", "path": "/data/local/tmp/agent.js", "on_change": "ignore" } }
```

Packaging:
- Android: `frida-apk -g libfrida-gadget.so -c on_load=wait app.apk -o app.gadget.apk` marks the app debuggable and adds the gadget with a `wrap.sh` (`LD_PRELOAD`). The output is unsigned: `zipalign -p 4` then `apksigner sign --ks lab.keystore`. Alternatives: add a `System.loadLibrary("frida-gadget")` to smali, or add a `DT_NEEDED` entry to an existing native library with LIEF.
- iOS: insert a load command for `@executable_path/Frameworks/FridaGadget.dylib` (`insert_dylib`, LIEF, or Sideloadly/objection patching), then re-sign the whole bundle with your identity. Signature changes break apps that verify their own team ID or entitlements.
- macOS / Linux test harness: `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` on a binary you own. Hardened-runtime and SIP-protected binaries ignore `DYLD_INSERT_LIBRARIES`.

Gadget is how this reference's snippets were tested on a macOS host with Developer Mode disabled. `frida -f` and `frida -p` need `task_for_pid`; Gadget in `script` or `listen` mode does not. The test binary was the agent's own C program, never a sample:

```bash
GADGET="$PWD/frida-gadget.dylib"        # from the frida release matching `frida --version`
printf '{"interaction":{"type":"script","path":"%s","on_change":"ignore"}}' "$PWD/agent.js" > "$PWD/frida-gadget.config"
timeout 20 env DYLD_INSERT_LIBRARIES="$GADGET" ./own_test_program
```

Put `timeout` outside `env`. Otherwise the gadget also loads into `timeout` itself.

## Mandatory Mobile Pre-Flight Environment Gate

**MUST complete this gate before launching a mobile process, loading a hook, or attempting TLS interception.** A missing or unrooted target is an environment-provisioning problem, not a hook failure. Do not attach blindly and do not continue with partial output.

The remediation authority is [host and lab setup](../05-environment/host-and-lab-setup.md).

### Android gate

Run all three checks:

```bash
adb devices
adb shell "su -c id"
adb shell "test -e /system/bin/ksu || which su"
```

The gate passes only when:

- exactly one intended emulator or device is in the `device` state;
- `su -c id` contains `uid=0(root)`; and
- KernelSU, Magisk, or another working `su` installation is present.

If no target is connected, the state is `offline`/`unauthorized`, or root is not confirmed, stop dynamic analysis and invoke the tool-setup bridge:

```bash
uv run scripts/setup_android_emulator.py setup-all
adb wait-for-device
adb shell "su -c id"
```

`setup-all` selects an installed official Google Play ARM64 system image, obtains the matching KernelSU GKI `Image` and `KernelSU_Next_*.apk`, backs up and replaces `kernel-ranchu`, cold-boots without a Quick Boot snapshot, installs the manager, and requires `uid=0(root)`. If no Google Play image is installed, install the image first and rerun:

```bash
sdkmanager "system-images;android-36;google_apis_playstore;arm64-v8a"
uv run scripts/setup_android_emulator.py setup-all
```

Install the mitmproxy CA into the rooted system trust path through the real tool-setup subcommand:

```bash
uv run scripts/setup_proxy_ca.py install-android
uv run scripts/setup_proxy_ca.py set-android-proxy
```

On recent read-only Android images, `install-android` uses a KernelSU/Magisk module or a mount overlay instead of assuming `adb remount` can modify EROFS.

### iOS gate

Inventory every available transport, then prove that the selected research guest is usable:

```bash
frida-ls-devices
ssh -o BatchMode=yes -o ConnectTimeout=5 -p 2222 root@localhost id
xcrun simctl list
```

For device-class analysis, the gate passes only when the SSH command reaches the intended guest and prints `uid=0`, and Frida can enumerate it. A booted iOS Simulator is sufficient only for a simulator build; it is not a rooted arm64e iPhone environment.

If no rooted guest is active, use [host and lab setup](../05-environment/host-and-lab-setup.md), its [`macos-vm-ansible-setup.md`](../05-environment/macos-vm-ansible-setup.md) host guidance, and [`ipsw.md`](./ipsw.md). On Apple Silicon, the rooted path is the `vphone-cli` research VM:

```bash
# Run in macOS Recovery when the host has not enabled research guests.
csrutil allow-research-guests enable

# Run from the vphone-cli checkout on the normal macOS host.
make
sudo VPhoneEscalator allow "$PWD/build/vphone-vm"
make fw_patch_jb
vphone-cli host preflight
vphone-cli vm start iOS-Research-VM

# The jailbreak firmware profile applies the 112-patch set and provides
# root SSH on port 2222, Sileo, TrollStore, and guest Frida support.
ssh -p 2222 root@localhost "/usr/bin/frida-server -D"
frida-ps -H 127.0.0.1:27042 -ai
```

For a booted iOS Simulator, install the proxy CA with:

```bash
uv run scripts/setup_proxy_ca.py install-ios-sim
```

For a `vphone-cli` guest, transfer the same CA profile to the guest, install it, and enable full trust in **Settings > General > About > Certificate Trust Settings**. The simulator keychain command does not modify the guest keychain.

## Frida Transport and Version Matching

The server binary must match the client's major version and the device ABI (`arm64-v8a` → `android-arm64`, `x86_64` → `android-x86_64`).

```bash
FRIDA_VERSION="$(frida --version)"
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in
  arm64-v8a) FRIDA_ARCH=arm64 ;; armeabi-v7a) FRIDA_ARCH=arm ;;
  x86_64) FRIDA_ARCH=x86_64 ;; x86) FRIDA_ARCH=x86 ;; *) echo "unknown ABI $ABI"; exit 1 ;;
esac
curl -fL -o frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}.xz"
xz -d -f frida-server.xz
adb push frida-server /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server -D'"          # -D daemonizes; no trailing &
frida-ps -Uai
```

To move off the default port (a common detection vector), start the server with `-l 127.0.0.1:41337`, run `adb forward tcp:41337 tcp:41337`, and use `-H 127.0.0.1:41337` instead of `-U`.

Use USB/device mode for Android and physical iOS devices, and host mode for the default `vphone-cli` forwarding. Derive the package identifier from the artifact under analysis, never from "the first third-party package" on the device:

```bash
PACKAGE_ID="$(apkanalyzer manifest application-id target.apk)"   # or: aapt2 dump packagename target.apk
test -n "$PACKAGE_ID"
adb shell pm path "$PACKAGE_ID"                                   # confirm it is installed
frida -U -f "$PACKAGE_ID" -l ssl_unpin_android.js
BUNDLE_ID=com.apple.mobilesafari                                  # replace with the target's CFBundleIdentifier
frida -H 127.0.0.1:27042 -f "$BUNDLE_ID" -l ssl_unpin_ios.js
```

## TLS Trust Boundaries

Hook the narrowest boundary that actually rejects the proxy certificate:

| Platform layer | Typical rejection point | Required action |
|---|---|---|
| Android platform trust | Conscrypt `TrustManagerImpl`, Network Security Config | Accept the chain or skip pin comparison |
| OkHttp 3/4 | `CertificatePinner.check` / `check$okhttp` | Return without throwing |
| Android WebView | `WebViewClient.onReceivedSslError` | Call `SslErrorHandler.proceed()` |
| Cronet / Chromium | `CronetEngine.Builder` pins and `AndroidNetworkLibrary` callback | Suppress configured pins and return verification success |
| iOS Security.framework | `SecTrustEvaluateWithError`, legacy trust APIs | Return success and clear the error/result |
| Foundation | `NSURLSessionDelegate` challenge callback | Supply `NSURLCredential` built from `serverTrust` |
| AFNetworking | `AFSecurityPolicy` | Return `YES` |
| Alamofire 5 | `ServerTrustEvaluating.evaluate(_:forHost:)` | Prevent the Swift throwing evaluator from propagating failure |
| TrustKit | `TSKPinningValidator evaluateTrust:forHostname:` | Return `TSKTrustDecisionShouldAllowConnection` |
| Flutter | `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so` | Force the native return register to `1` |

## Android SSL/TLS Unpinning Script

The following script handles OkHttp 3/4, Conscrypt, Network Security Config, WebView, and Cronet. It logs every installed hook and every bypassed host. A missing class is reported and is not treated as success.

```javascript
// ssl_unpin_android.js
'use strict';

setImmediate(function () {
    if (!Java.available) {
        console.error('[-] Android Java runtime is unavailable');
        return;
    }

    Java.perform(function () {
        const installed = [];

        function useClass(name) {
            try {
                return Java.use(name);
            } catch (error) {
                return null;
            }
        }

        function signature(overload) {
            return overload.argumentTypes.map(function (type) {
                return type.className;
            }).join(',');
        }

        function record(label) {
            installed.push(label);
            console.log('[+] Hooked ' + label);
        }

        // OkHttp 3 and OkHttp 4 retain the okhttp3.CertificatePinner class.
        const CertificatePinner = useClass('okhttp3.CertificatePinner');
        if (CertificatePinner !== null) {
            if (CertificatePinner.check) {
                CertificatePinner.check.overloads.forEach(function (overload) {
                    const sig = signature(overload);
                    if (sig === 'java.lang.String,java.util.List' ||
                        sig === 'java.lang.String,[Ljava.security.cert.Certificate;') {
                        overload.implementation = function (hostname) {
                            console.log('[OkHttp] accepted pinned host ' + hostname);
                            return;
                        };
                        record('okhttp3.CertificatePinner.check(' + sig + ')');
                    }
                });
            }

            // OkHttp 4 performs lazy peer-certificate evaluation through Function0.
            if (CertificatePinner['check$okhttp']) {
                CertificatePinner['check$okhttp'].overloads.forEach(function (overload) {
                    const sig = signature(overload);
                    if (sig.indexOf('java.lang.String,') === 0) {
                        overload.implementation = function (hostname) {
                            console.log('[OkHttp4] accepted pinned host ' + hostname);
                            return;
                        };
                        record('okhttp3.CertificatePinner.check$okhttp(' + sig + ')');
                    }
                });
            }
        }

        // Android platform Conscrypt appears under different package names by release.
        [
            'com.android.org.conscrypt.TrustManagerImpl',
            'org.conscrypt.TrustManagerImpl',
            'com.google.android.gms.org.conscrypt.TrustManagerImpl'
        ].forEach(function (className) {
            const TrustManagerImpl = useClass(className);
            if (TrustManagerImpl === null) {
                return;
            }

            if (TrustManagerImpl.checkServerTrusted) {
                TrustManagerImpl.checkServerTrusted.overloads.forEach(function (overload) {
                    const sig = signature(overload);
                    if (sig === '[Ljava.security.cert.X509Certificate;,java.lang.String') {
                        overload.implementation = function () {
                            console.log('[Conscrypt] checkServerTrusted accepted');
                            return;
                        };
                        record(className + '.checkServerTrusted(' + sig + ')');
                    }
                });
            }

            // Newer Android releases route the public method through this list-returning helper.
            if (TrustManagerImpl.checkTrustedRecursive) {
                const ArrayList = Java.use('java.util.ArrayList');
                TrustManagerImpl.checkTrustedRecursive.overloads.forEach(function (overload) {
                    const sig = signature(overload);
                    overload.implementation = function () {
                        console.log('[Conscrypt] checkTrustedRecursive accepted');
                        return ArrayList.$new();
                    };
                    record(className + '.checkTrustedRecursive(' + sig + ')');
                });
            }
        });

        // Network Security Config performs pin-set comparison after chain validation.
        const NetworkSecurityTrustManager =
            useClass('android.security.net.config.NetworkSecurityTrustManager');
        if (NetworkSecurityTrustManager !== null && NetworkSecurityTrustManager.checkPins) {
            NetworkSecurityTrustManager.checkPins.overloads.forEach(function (overload) {
                const sig = signature(overload);
                overload.implementation = function () {
                    console.log('[NetworkSecurityConfig] pin set accepted');
                    return;
                };
                record('NetworkSecurityTrustManager.checkPins(' + sig + ')');
            });
        }

        // Base WebView callback plus explicit cancel handling cover the common override paths.
        const WebViewClient = useClass('android.webkit.WebViewClient');
        if (WebViewClient !== null && WebViewClient.onReceivedSslError) {
            const webViewSsl = WebViewClient.onReceivedSslError.overload(
                'android.webkit.WebView',
                'android.webkit.SslErrorHandler',
                'android.net.http.SslError'
            );
            webViewSsl.implementation = function (view, handler, error) {
                console.log('[WebView] proceeding after SSL error: ' + error);
                handler.proceed();
            };
            record('WebViewClient.onReceivedSslError');
        }

        const SslErrorHandler = useClass('android.webkit.SslErrorHandler');
        if (SslErrorHandler !== null && SslErrorHandler.cancel) {
            const cancel = SslErrorHandler.cancel.overload();
            cancel.implementation = function () {
                console.log('[WebView] converted SslErrorHandler.cancel() to proceed()');
                this.proceed();
            };
            record('SslErrorHandler.cancel');
        }

        // Disable Cronet PKP registration before the engine is built.
        [
            'org.chromium.net.CronetEngine$Builder',
            'org.chromium.net.impl.CronetEngineBuilderImpl'
        ].forEach(function (className) {
            const Builder = useClass(className);
            if (Builder === null) {
                return;
            }

            if (Builder.addPublicKeyPins) {
                Builder.addPublicKeyPins.overloads.forEach(function (overload) {
                    const sig = signature(overload);
                    overload.implementation = function (hostname) {
                        console.log('[Cronet] ignored public-key pins for ' + hostname);
                        return this;
                    };
                    record(className + '.addPublicKeyPins(' + sig + ')');
                });
            }

            if (Builder.enablePublicKeyPinningBypassForLocalTrustAnchors) {
                const bypass =
                    Builder.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean');
                bypass.implementation = function () {
                    console.log('[Cronet] enabled local-trust-anchor pin bypass');
                    return bypass.call(this, true);
                };
                record(className + '.enablePublicKeyPinningBypassForLocalTrustAnchors');
            }
        });

        // Chromium's native stack calls this Java callback for platform certificate verification.
        const AndroidNetworkLibrary =
            useClass('org.chromium.net.AndroidNetworkLibrary') ||
            useClass('org.chromium.net.impl.AndroidNetworkLibrary');
        const AndroidCertVerifyResult =
            useClass('org.chromium.net.AndroidCertVerifyResult') ||
            useClass('org.chromium.net.impl.AndroidCertVerifyResult');

        function cronetSuccessResult() {
            try {
                return AndroidCertVerifyResult.$new.overload('int')
                    .call(AndroidCertVerifyResult, 0);
            } catch (oneArgumentError) {
                const ArrayList = Java.use('java.util.ArrayList');
                return AndroidCertVerifyResult.$new.overload(
                    'int', 'boolean', 'java.util.List'
                ).call(AndroidCertVerifyResult, 0, true, ArrayList.$new());
            }
        }

        if (AndroidNetworkLibrary !== null &&
            AndroidCertVerifyResult !== null &&
            AndroidNetworkLibrary.verifyServerCertificates) {
            AndroidNetworkLibrary.verifyServerCertificates.overloads.forEach(function (overload) {
                const sig = signature(overload);
                overload.implementation = function (chain, authType, hostname) {
                    console.log('[Cronet] certificate callback accepted ' + hostname);
                    return cronetSuccessResult();
                };
                record('AndroidNetworkLibrary.verifyServerCertificates(' + sig + ')');
            });
        }

        console.log('[+] Android TLS hooks installed: ' + installed.length);
    });
});
```

Launch early enough to intercept builder configuration:

```bash
PACKAGE_ID="$(apkanalyzer manifest application-id target.apk)"
test -n "$PACKAGE_ID"
frida -U -f "$PACKAGE_ID" -l ssl_unpin_android.js -o unpin.log
```

The script uses the `Java` global, so load it through the `frida` CLI or `frida-trace -S`. From Python or a compiled agent, add `import Java from "frida-java-bridge";` at the top and build it with `frida-compile`.

If the application uses a non-default class loader, enumerate loaders with `Java.enumerateClassLoadersSync()`, pick the one where `loader.findClass('okhttp3.CertificatePinner')` does not throw, and assign it to `Java.classFactory.loader` before installing the OkHttp hooks.

## iOS SSL/TLS Unpinning Script

This script covers Security.framework, both `NSURLSession` challenge selectors, AFNetworking, TrustKit, and symbol-bearing Alamofire 5 builds.

```javascript
// ssl_unpin_ios.js
'use strict';

function globalExport(name) {
    try {
        return Module.getGlobalExportByName(name);
    } catch (error) {
        console.log('[-] Export not found: ' + name);
        return null;
    }
}

function hookSecurityFramework() {
    const modern = globalExport('SecTrustEvaluateWithError');
    if (modern !== null) {
        Interceptor.attach(modern, {
            onEnter: function (args) {
                this.errorOut = args[1];
            },
            onLeave: function (retval) {
                if (!this.errorOut.isNull()) {
                    this.errorOut.writePointer(NULL);
                }
                retval.replace(1);
                console.log('[Security] SecTrustEvaluateWithError -> true');
            }
        });
    }

    ['SecTrustEvaluate', 'SecTrustGetTrustResult'].forEach(function (name) {
        const address = globalExport(name);
        if (address === null) {
            return;
        }
        Interceptor.attach(address, {
            onEnter: function (args) {
                this.resultOut = args[1];
            },
            onLeave: function (retval) {
                if (!this.resultOut.isNull()) {
                    this.resultOut.writeU32(1); // kSecTrustResultProceed
                }
                retval.replace(0); // errSecSuccess
                console.log('[Security] ' + name + ' -> proceed');
            }
        });
    });
}

function hookChallengeSelector(selector, challengeIndex, completionIndex) {
    const hookedImplementations = new Set();

    Object.keys(ObjC.classes).forEach(function (className) {
        const klass = ObjC.classes[className];
        if (klass.$ownMethods.indexOf(selector) === -1) {
            return;
        }
        const method = klass[selector];
        if (method === undefined) {
            return;
        }

        const oldAddress = method.implementation;
        const key = oldAddress.toString();
        if (hookedImplementations.has(key)) {
            return;
        }
        hookedImplementations.add(key);

        const argumentCount = completionIndex + 1;
        const nativeTypes = Array(argumentCount).fill('pointer');
        const original = new NativeFunction(oldAddress, 'void', nativeTypes);

        method.implementation = ObjC.implement(method, function () {
            const args = Array.prototype.slice.call(arguments);
            const challenge = new ObjC.Object(args[challengeIndex]);
            const protectionSpace = challenge.protectionSpace();
            const authMethod = protectionSpace.authenticationMethod().toString();

            if (authMethod !== 'NSURLAuthenticationMethodServerTrust') {
                original.apply(null, args);
                return;
            }

            const trust = protectionSpace.serverTrust();
            const credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
            const completion = new ObjC.Block(args[completionIndex]);
            completion.implementation(0, credential.handle); // UseCredential
            console.log('[NSURLSession] accepted server trust in ' + className);
        });

        console.log('[+] Hooked ' + className + ' ' + selector);
    });
}

function hookObjectiveCPinners() {
    const AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    if (AFSecurityPolicy !== undefined) {
        const method = AFSecurityPolicy['- evaluateServerTrust:forDomain:'];
        if (method !== undefined) {
            Interceptor.attach(method.implementation, {
                onLeave: function (retval) {
                    retval.replace(1);
                    console.log('[AFNetworking] AFSecurityPolicy -> YES');
                }
            });
        }
    }

    const TSKPinningValidator = ObjC.classes.TSKPinningValidator;
    if (TSKPinningValidator !== undefined) {
        const method = TSKPinningValidator['- evaluateTrust:forHostname:'];
        if (method !== undefined) {
            Interceptor.attach(method.implementation, {
                onLeave: function (retval) {
                    // TSKTrustDecisionShouldAllowConnection is enum value 0.
                    retval.replace(0);
                    console.log('[TrustKit] evaluateTrust -> allow');
                }
            });
        }
    }
}

function hookAlamofireSwiftEvaluators() {
    if (Process.arch !== 'arm64') {
        console.log('[-] Alamofire Swift error-register hook requires arm64');
        return;
    }

    const seen = new Set();
    let count = 0;

    Process.enumerateModules().forEach(function (module) {
        if (module.path.indexOf('/System/Library/') !== -1) {
            return;
        }

        let symbols;
        try {
            symbols = module.enumerateSymbols();
        } catch (error) {
            return;
        }

        symbols.forEach(function (symbol) {
            const name = symbol.name || '';
            const isAlamofire = name.indexOf('Alamofire') !== -1;
            const isTrustEvaluator =
                name.indexOf('evaluateServerTrust') !== -1 ||
                (name.indexOf('evaluate') !== -1 && name.indexOf('forHost') !== -1);
            const key = symbol.address.toString();

            if (!isAlamofire || !isTrustEvaluator || seen.has(key)) {
                return;
            }
            seen.add(key);

            Interceptor.attach(symbol.address, {
                onLeave: function () {
                    // Swift arm64 uses x21 as the swifterror register.
                    this.context.x21 = ptr(0);
                    console.log('[Alamofire] suppressed ServerTrustEvaluating error');
                }
            });
            count += 1;
            console.log('[+] Hooked Alamofire trust symbol ' + name);
        });
    });

    console.log('[+] Alamofire trust symbols hooked: ' + count);
}

if (!ObjC.available) {
    console.error('[-] Objective-C runtime is unavailable');
} else {
    hookSecurityFramework();
    hookChallengeSelector(
        '- URLSession:didReceiveChallenge:completionHandler:', 3, 4
    );
    hookChallengeSelector(
        '- URLSession:task:didReceiveChallenge:completionHandler:', 4, 5
    );
    hookObjectiveCPinners();
    hookAlamofireSwiftEvaluators();
}
```

Alamofire 5's actual API is `ServerTrustEvaluating.evaluate(_:forHost:)`; `evaluateServerTrust` is commonly an application wrapper, not a stable Alamofire API. Release builds may strip Swift symbols. When the script reports zero Alamofire symbols and traffic still fails after the Security.framework hook, recover the evaluator RVA from the app's Mach-O and hook that exact address. Do not scan arbitrary executable pages and treat the first match as a trust evaluator.

Run against the research guest:

```bash
BUNDLE_ID=com.apple.mobilesafari      # replace with the target's CFBundleIdentifier
frida-ps -H 127.0.0.1:27042 -ai
frida -H 127.0.0.1:27042 -f "$BUNDLE_ID" -l ssl_unpin_ios.js -o unpin.log
```

The script uses the `ObjC` global (CLI only, or import `frida-objc-bridge` in a compiled agent). Loaded on macOS through Gadget, it installed the Security.framework hooks and both `NSURLSession` challenge selectors without errors; the TLS bypass effect itself still needs the device and proxy evidence below.

## Flutter BoringSSL

Flutter does not route Dart `HttpClient` validation through Android's Java `TrustManager`, Network Security Config, or OkHttp. The engine statically links BoringSSL into `libflutter.so` on Android and `Flutter.framework/Flutter` on iOS. Installing the system CA is still useful for platform traffic, but it does not neutralize Flutter's native verifier.

Use the version-aware executable-range scan and `Interceptor.attach` workflow in [`flutter-dart.md`](../01-static-architectures/flutter-dart.md). Its target is `ssl_crypto_x509_session_verify_cert_chain`; a successful hook replaces the ARM64 return register `X0` with `1`. For an offline alternative, `re-flutter` patches a matching engine binary before the package is resigned.

## Evidence and Failure Isolation

Do not call the bypass successful merely because Frida attached.

1. Confirm the proxy sees a CONNECT request and a decrypted request/response.
2. Confirm the relevant hook logs the hostname or trust callback.
3. Confirm the target no longer emits its original TLS error.
4. Capture the process name, package identifier, ABI, Frida versions, installed hook names, and proxy flow timestamp.
5. Disable hook families one at a time to identify the minimum effective bypass.

Common failure interpretations:

| Observation | Interpretation | Next action |
|---|---|---|
| No Frida device | Environment gate failed | Provision or restart the rooted target |
| Frida attaches, no hook classes | Wrong process, class loader, or native stack | Inspect loaded classes/modules |
| OkHttp hook logs, TLS still fails | Additional native/Cronet/TrustKit pinning | Trace the next trust boundary |
| Proxy sees CONNECT but no HTTP | TLS negotiation still fails | Inspect target logs and verifier hooks |
| Flutter pattern has no match | Engine-version signature mismatch | Derive signature/RVA from the extracted engine |
| iOS callback runs twice or crashes | Two hooks consumed one completion block | Keep only the narrowest delegate hook |

## Boundaries

- Use these bypasses only on software and endpoints explicitly authorized for analysis.
- Keep the target inside an isolated emulator, simulator, research VM, or test device.
- Do not weaken trust on a personal device or leave a proxy CA installed after the analysis.
- Do not suppress every exception in a process. Restrict hooks to the verified TLS boundary and retain logs that show what was changed.
- Restore Android proxy state with `setup_proxy_ca.py clear-android-proxy`, stop Frida servers, and remove temporary CA profiles when the session ends.
