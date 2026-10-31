# Frida Mobile Dynamic Instrumentation and TLS Unpinning

## Purpose

Use this reference for authorized runtime analysis of Android and iOS applications with Frida. It covers device readiness, transport setup, framework-specific certificate pinning, and evidence that a bypass reached the intended trust boundary. Installing a proxy CA and bypassing pinning are separate operations: the CA makes the proxy certificate a trust anchor, while the hooks neutralize application-enforced pins.

Read [`network-traffic-proxy.md`](../02-dynamic-instrumentation/network-traffic-proxy.md) for proxy routing and capture, and [`flutter-dart.md`](../01-static-architectures/flutter-dart.md) for Flutter's statically linked BoringSSL path.

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
python3 scripts/setup_android_emulator.py setup-all
adb wait-for-device
adb shell "su -c id"
```

`setup-all` selects an installed official Google Play ARM64 system image, obtains the matching KernelSU GKI `Image` and `KernelSU_Next_*.apk`, backs up and replaces `kernel-ranchu`, cold-boots without a Quick Boot snapshot, installs the manager, and requires `uid=0(root)`. If no Google Play image is installed, install the image first and rerun:

```bash
sdkmanager "system-images;android-36;google_apis_playstore;arm64-v8a"
python3 scripts/setup_android_emulator.py setup-all
```

Install the mitmproxy CA into the rooted system trust path through the real tool-setup subcommand:

```bash
python3 scripts/setup_proxy_ca.py install-android
python3 scripts/setup_proxy_ca.py set-android-proxy
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
python3 scripts/setup_proxy_ca.py install-ios-sim
```

For a `vphone-cli` guest, transfer the same CA profile to the guest, install it, and enable full trust in **Settings > General > About > Certificate Trust Settings**. The simulator keychain command does not modify the guest keychain.

## Frida Transport and Version Matching

The host tools and injected server must use the same Frida major version and a server binary matching the target ABI.

```bash
frida --version
adb shell getprop ro.product.cpu.abi
adb push frida-server /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server -D &'"
frida-ps -Uai
```

Use USB/device mode for Android and physical iOS devices, and host mode for the default `vphone-cli` forwarding:

```bash
frida -U -f "$(adb shell pm list packages -3 | sed -n '1s/^package://p' | tr -d '\r')" -l ssl_unpin_android.js
frida -H 127.0.0.1:27042 -f com.apple.mobilesafari -l ssl_unpin_ios.js
```

For a specific application, derive and inspect its package identifier before spawning it rather than copying an identifier from another target.

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
frida -U -f "$PACKAGE_ID" -l ssl_unpin_android.js
```

If the application uses a non-default class loader, enumerate class loaders and set `Java.classFactory.loader` to the loader that resolves `okhttp3.CertificatePinner` before installing the OkHttp hooks.

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
frida-ps -H 127.0.0.1:27042 -ai
frida -H 127.0.0.1:27042 -f com.apple.mobilesafari -l ssl_unpin_ios.js
```

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
