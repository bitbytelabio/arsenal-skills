# Flutter and Dart AOT Reverse Engineering

## Purpose

Use this reference for Flutter Android, iOS, and desktop artifacts. It covers engine identification, Dart AOT snapshot recovery, native TLS trust boundaries, a runtime BoringSSL verifier hook, and offline `re-flutter` patching. Read [`frida.md`](../04-tool-usage/frida.md) for general Frida transport and [`network-traffic-proxy.md`](../02-dynamic-instrumentation/network-traffic-proxy.md) for proxy capture.

## Detection and Architecture

### Android indicators

- `lib/arm64-v8a/libflutter.so`: Flutter engine, Dart VM, and statically linked native dependencies including BoringSSL.
- `lib/arm64-v8a/libapp.so`: AOT-compiled application isolate instructions and snapshot data.
- `assets/flutter_assets/`: fonts, assets, manifests, and application resources.
- `assets/flutter_assets/kernel_blob.bin`: debug/profile Kernel IR; normally absent from release AOT builds.

### iOS indicators

- `Frameworks/Flutter.framework/Flutter`: Flutter engine Mach-O.
- `Frameworks/App.framework/App`: AOT-compiled application code and snapshot.
- Flutter and Dart VM version strings in the engine binary.

### Execution model

```text
Dart application code
    -> AOT compiler
    -> libapp.so or App.framework
       - VM snapshot data
       - VM snapshot instructions
       - isolate snapshot data and object pool
       - isolate snapshot instructions
    -> Flutter engine
       - Dart VM runtime
       - Skia or Impeller
       - statically linked BoringSSL
```

The engine and application snapshot are a versioned pair. Snapshot layout and object encodings change across Dart revisions, so a parser built for a different snapshot hash can produce plausible but incorrect names and offsets.

## Static Triage

Preserve the package and extract it without modifying the original:

```bash
mkdir -p flutter-analysis/unpacked
cp target.apk flutter-analysis/target.original.apk
shasum -a 256 flutter-analysis/target.original.apk
unzip -q flutter-analysis/target.original.apk -d flutter-analysis/unpacked

file flutter-analysis/unpacked/lib/arm64-v8a/libflutter.so
file flutter-analysis/unpacked/lib/arm64-v8a/libapp.so
readelf -hW flutter-analysis/unpacked/lib/arm64-v8a/libflutter.so
readelf -lW flutter-analysis/unpacked/lib/arm64-v8a/libapp.so
```

Determine build mode and collect version evidence:

```bash
find flutter-analysis/unpacked -type f \
  \( -name 'libflutter.so' -o -name 'libapp.so' -o -name 'kernel_blob.bin' \) \
  -print

strings -a flutter-analysis/unpacked/lib/arm64-v8a/libflutter.so \
  | grep -E 'Flutter engine version|Dart VM version|SnapshotFormat|^[0-9a-f]{32}$'
```

Recover AOT structure with `blutter` only after matching its Dart parser to the target snapshot:

```bash
python3 blutter.py \
  flutter-analysis/unpacked/lib/arm64-v8a \
  flutter-analysis/blutter-output
```

Prioritize:

- `pp.txt` for object-pool strings, URIs, keys, and constants;
- `objs.txt` for libraries, classes, fields, and method code offsets;
- generated assembly for object-pool-relative loads through Dart's pool pointer;
- IDA/Ghidra scripts for applying recovered names to `libapp.so`.

On AArch64 Dart AOT, `X27` commonly holds the pool pointer. A load such as `ldr x0, [x27, #0x280]` is an object-pool access, not a normal native global. Resolve the pool entry before assigning semantic meaning.

## Mandatory Mobile Pre-Flight Environment Gate

Static extraction does not require a device. **Before any dynamic Flutter analysis, proxy interception, or TLS bypass, the agent MUST verify the target environment.** If the gate fails, do not launch the app or scan arbitrary processes. Invoke [host and lab setup](../05-environment/host-and-lab-setup.md), remediate, and rerun the checks.

### Android

```bash
adb devices
adb shell "su -c id"
adb shell "test -e /system/bin/ksu || which su"
```

Pass criteria are an intended target in the `device` state, `uid=0(root)`, and KernelSU/Magisk or a working `su`.

If the device is missing or unrooted:

```bash
uv run scripts/setup_android_emulator.py setup-all
adb wait-for-device
adb shell "su -c id"
uv run scripts/setup_proxy_ca.py install-android
uv run scripts/setup_proxy_ca.py set-android-proxy
```

The tool-setup workflow selects an installed official Google Play ARM64 image, downloads the matching KernelSU GKI and `KernelSU_Next_*.apk`, backs up and replaces `kernel-ranchu`, cold-boots, installs the manager, and verifies `uid=0(root)`. If the image is not installed:

```bash
sdkmanager "system-images;android-36;google_apis_playstore;arm64-v8a"
uv run scripts/setup_android_emulator.py setup-all
```

### iOS

```bash
frida-ls-devices
ssh -o BatchMode=yes -o ConnectTimeout=5 -p 2222 root@localhost id
xcrun simctl list
```

A Simulator is valid only for a simulator build. A device-class Flutter IPA requires a rooted guest with `uid=0` and a reachable Frida server. If none is active, follow [`macos-vm-ansible-setup.md`](../05-environment/macos-vm-ansible-setup.md) and [`ipsw.md`](../04-tool-usage/ipsw.md):

```bash
# Enable once from macOS Recovery.
csrutil allow-research-guests enable

# Continue from the vphone-cli checkout.
make
sudo VPhoneEscalator allow "$PWD/build/vphone-vm"
make fw_patch_jb
vphone-cli host preflight
vphone-cli vm start iOS-Research-VM
ssh -p 2222 root@localhost "/usr/bin/frida-server -D"
frida-ps -H 127.0.0.1:27042 -ai
```

This path uses the 112 jailbreak patches and provides root SSH on port 2222, Sileo, TrollStore, and guest `frida-server`. For a booted iOS Simulator:

```bash
uv run scripts/setup_proxy_ca.py install-ios-sim
```

The research VM has a separate keychain. Transfer the CA profile to the guest, install it, and enable full trust in **Settings > General > About > Certificate Trust Settings**.

## Why Java Trust Hooks Do Not Unpin Flutter

Android applications written around OkHttp or `HttpsURLConnection` normally reach Java `X509TrustManager`, Conscrypt, and Network Security Config. Flutter's Dart `HttpClient` takes a different route:

```text
Dart HttpClient
    -> dart:io native socket bindings
    -> Flutter engine
    -> statically linked BoringSSL in libflutter.so
    -> ssl_crypto_x509_session_verify_cert_chain
```

Therefore:

- an Android system CA does not change a private Flutter verifier or application callback;
- `TrustManagerImpl.checkServerTrusted`, OkHttp `CertificatePinner`, and WebView hooks do not observe the Dart handshake;
- a Java-only "universal SSL bypass" can report success while Flutter traffic still fails; and
- the decisive runtime return is native BoringSSL state in `libflutter.so`.

The exact implementation changes across Flutter engine commits and architectures. Prefer a recovered export or an RVA from the exact extracted engine. When symbols are stripped, use a sufficiently long architecture-specific signature over an executable range, require one unique match, and refuse ambiguity.

## Runtime BoringSSL Verifier Hook

The following Android ARM64 Frida script waits for `libflutter.so`, tries the verifier export, and then scans executable mappings for the `ssl_crypto_x509_session_verify_cert_chain` prologue and nearby constant loads. The wildcards cover relocation- and build-dependent instruction fields. It attaches only when one unique address is found.

```javascript
// flutter_boringssl_unpin.js
'use strict';

const MODULE_NAME = 'libflutter.so';
const VERIFY_SYMBOL = 'ssl_crypto_x509_session_verify_cert_chain';
const ARM64_VERIFY_PATTERNS = [
    // Function prologue plus verifier-state constant loads.
    'FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 ' +
    '48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9'
];

let hookInstalled = false;
let attempts = 0;

function attachVerifier(address, source) {
    if (hookInstalled) {
        return;
    }
    hookInstalled = true;

    console.log('[+] Hooking Flutter verifier at ' + address + ' via ' + source);
    Interceptor.attach(address, {
        onLeave: function (retval) {
            const original = retval.toInt32();
            // On AArch64 the integer return register is X0. retval.replace(1)
            // writes X0 before control returns to the caller.
            retval.replace(1);
            console.log('[Flutter TLS] verifier ' + original + ' -> 1');
        }
    });
}

function finishScan(matches) {
    const unique = [];
    const seen = new Set();

    matches.forEach(function (address) {
        const key = address.toString();
        if (!seen.has(key)) {
            seen.add(key);
            unique.push(address);
        }
    });

    if (unique.length === 1) {
        attachVerifier(unique[0], 'ARM64 executable-range signature');
        return;
    }

    if (unique.length === 0) {
        console.error(
            '[-] No Flutter verifier signature matched this engine build; ' +
            'recover the RVA or a signature from the extracted libflutter.so'
        );
        return;
    }

    console.error(
        '[-] Refusing to hook ' + unique.length +
        ' ambiguous Flutter verifier candidates'
    );
}

function scanExecutableRanges(module) {
    if (Process.arch !== 'arm64') {
        console.error('[-] This signature set is for Android arm64, not ' + Process.arch);
        return;
    }

    const ranges = module.enumerateRanges('r-x');
    const matches = [];
    let pending = ranges.length * ARM64_VERIFY_PATTERNS.length;

    ranges.forEach(function (range) {
        ARM64_VERIFY_PATTERNS.forEach(function (pattern) {
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function (address) {
                    matches.push(address);
                    console.log('[+] Flutter verifier candidate ' + address);
                },
                onError: function (reason) {
                    console.error('[-] Memory scan error: ' + reason);
                },
                onComplete: function () {
                    pending -= 1;
                    if (pending === 0) {
                        finishScan(matches);
                    }
                }
            });
        });
    });
}

function locateVerifier() {
    if (hookInstalled) {
        return;
    }

    const module = Process.findModuleByName(MODULE_NAME);
    if (module === null) {
        attempts += 1;
        if (attempts % 10 === 0) {
            console.log('[-] Waiting for ' + MODULE_NAME);
        }
        setTimeout(locateVerifier, 250);
        return;
    }

    try {
        attachVerifier(module.getExportByName(VERIFY_SYMBOL), 'export');
        return;
    } catch (error) {
        console.log('[*] Flutter verifier export is stripped; scanning executable ranges');
    }

    scanExecutableRanges(module);
}

setImmediate(locateVerifier);
```

Launch the application from a stopped state so the hook is active before the first client is constructed:

```bash
PACKAGE_ID="$(apkanalyzer manifest application-id flutter-analysis/target.original.apk)"
test -n "$PACKAGE_ID"
frida -U -f "$PACKAGE_ID" -l flutter_boringssl_unpin.js
```

Success requires all of the following:

1. the script reports exactly one export or signature match;
2. the verifier log appears during a TLS connection;
3. its original return is replaced with `1`;
4. the proxy receives a decrypted request and response; and
5. the application no longer emits its original handshake error.

An attach message or a pattern match alone is not evidence of successful interception.

### Deriving a version-specific address

If the signature does not match:

```bash
rabin2 -I flutter-analysis/unpacked/lib/arm64-v8a/libflutter.so
rabin2 -zz flutter-analysis/unpacked/lib/arm64-v8a/libflutter.so \
  | grep -E 'ssl_(client|server)|certificate|x509'
r2 -AA flutter-analysis/unpacked/lib/arm64-v8a/libflutter.so
```

In the disassembler, identify the verifier from the exact engine build, record its ELF RVA, and hook `module.base.add(rva)`. Confirm that the address falls inside an `r-x` range and that the function returns a Boolean before changing it. Do not reuse an RVA from another Flutter version.

For iOS, the same logical verifier resides in `Flutter.framework/Flutter`, but the Mach-O, arm64e/PAC environment, and engine build require an iOS-specific export, RVA, or signature. Do not apply the Android byte signature to the iOS image.

## Offline `re-flutter` Engine Patching

`re-flutter` is the offline alternative when live injection is unstable or the verifier address is known for a supported engine. The project is commonly exposed as the `reflutter` CLI. It selects a snapshot-compatible patched engine and repackages the application:

```bash
cp target.apk flutter-analysis/target.pre-reflutter.apk
shasum -a 256 flutter-analysis/target.pre-reflutter.apk
reflutter flutter-analysis/target.pre-reflutter.apk
```

After patching:

1. compare the original and replacement engine architecture and Flutter/Dart revision;
2. preserve hashes for both packages and both engine binaries;
3. align and sign the generated APK with the authorized research key;
4. install only on the disposable rooted emulator; and
5. verify proxy traffic independently of the tool's success message.

An engine with the wrong snapshot ABI can crash before Dart isolate startup. Never fix that crash by mixing another `libapp.so`; select a matching engine build.

## Failure Isolation

| Observation | Likely cause | Action |
|---|---|---|
| `libflutter.so` never loads | Wrong process or non-Flutter target | Inspect process modules and package contents |
| Pattern has no match | Unsupported engine revision or ABI | Recover the exact RVA/signature from the extracted engine |
| Multiple matches | Signature is too short | Add surrounding stable instructions and rescan |
| Verifier logs, no proxy connection | Routing is not configured | Verify Android global proxy or guest Wi-Fi proxy |
| Proxy CONNECT followed by TLS alert | Another native/app-level verifier remains | Trace BoringSSL error and app callbacks |
| App crashes at isolate startup after patch | Engine/snapshot mismatch or bad package signing | Restore original engine and use the matching revision |

## Boundaries

- Analyze only applications and endpoints covered by explicit authorization.
- Do not treat Flutter release builds as Java/Kotlin applications; application logic is in Dart AOT native code.
- Do not run `blutter` against an unmatched snapshot and trust partially recovered output.
- Do not hook every signature candidate or every Boolean-returning native function.
- Keep original package, engine, and snapshot hashes so runtime and offline modifications remain reproducible.
- Remove the proxy CA, proxy setting, patched package, and Frida server from disposable targets when the analysis ends.
