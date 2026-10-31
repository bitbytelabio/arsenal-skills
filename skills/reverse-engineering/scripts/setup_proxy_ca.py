#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""Automate mitmproxy CA setup and SSL pinning bypass for Android and iOS emulators/simulators."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, NotRequired, TypedDict

DEFAULT_MITMPROXY_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
DEFAULT_ANDROID_HOST = "10.0.2.2"
DEFAULT_ANDROID_PORT = 8080
DEFAULT_IOS_DEVICE = "booted"

ANDROID_FRIDA_SCRIPT = r"""/**
 * Universal Android SSL Pinning Bypass (Frida Script)
 *
 * Covers:
 *  - javax.net.ssl.TrustManager / X509TrustManager (universal all-trusting TrustManager)
 *  - javax.net.ssl.SSLContext.init
 *  - OkHttp3 CertificatePinner (standard and Kotlin mangled check$okhttp)
 *  - Conscrypt / Android OpenSSL TrustManagerImpl (checkTrustedRecursive, verifyChain)
 *  - android.webkit.WebViewClient (onReceivedSslError handler.proceed)
 *  - android.security.net.config.NetworkSecurityConfig
 */

Java.perform(function () {
    console.log("[*] Initializing Universal Android SSL Pinning Bypass...");

    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // 1. Create all-trusting TrustManager implementation
    var TrustManager = Java.registerClass({
        name: 'com.mitmproxy.bypass.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () {
                return [];
            }
        }
    });

    var TrustManagers = [TrustManager.$new()];

    // 2. Hook SSLContext.init
    try {
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (keyManager, trustManager, secureRandom) {
            console.log("[+] SSLContext.init() intercepted, replacing with TrustAllManager");
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch (e) {
        console.log("[-] SSLContext.init hook skipped: " + e.message);
    }

    // 3. Hook OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        try {
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
                console.log("[+] OkHttp3 CertificatePinner.check(String, List) bypassed for: " + hostname);
            };
        } catch (e) {}

        try {
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, peerCertificates) {
                console.log("[+] OkHttp3 CertificatePinner.check(String, Cert[]) bypassed for: " + hostname);
            };
        } catch (e) {}

        try {
            CertificatePinner['check$okhttp'].implementation = function (hostname, cleanedPeerCertificatesFn) {
                console.log("[+] OkHttp3 CertificatePinner.check$okhttp bypassed for: " + hostname);
            };
        } catch (e) {}
    } catch (e) {
        console.log("[-] OkHttp3 CertificatePinner not found or hook skipped");
    }

    // 4. Hook Conscrypt TrustManagerImpl
    var conscryptClasses = [
        'com.android.org.conscrypt.TrustManagerImpl',
        'org.conscrypt.TrustManagerImpl'
    ];
    conscryptClasses.forEach(function (className) {
        try {
            var TrustManagerImpl = Java.use(className);
            TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                var ArrayList = Java.use('java.util.ArrayList');
                return ArrayList.$new();
            };
            console.log("[+] Conscrypt TrustManagerImpl.checkTrustedRecursive bypassed (" + className + ")");
        } catch (e) {}

        try {
            var TrustManagerImpl2 = Java.use(className);
            TrustManagerImpl2.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log("[+] Conscrypt TrustManagerImpl.verifyChain bypassed for host: " + host);
                return untrustedChain;
            };
        } catch (e) {}
    });

    // 5. Hook WebViewClient onReceivedSslError
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
            console.log("[+] WebViewClient.onReceivedSslError intercepted, proceeding anyway");
            sslErrorHandler.proceed();
        };
    } catch (e) {
        console.log("[-] WebViewClient onReceivedSslError hook skipped");
    }

    // 6. Hook NetworkSecurityConfig
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.isCleartextTrafficPermitted.overload().implementation = function () {
            return true;
        };
    } catch (e) {}

    console.log("[+] Universal Android SSL Pinning Bypass active.");
});
"""

IOS_FRIDA_SCRIPT = r"""/**
 * Universal iOS SSL Pinning Bypass (Frida Script)
 *
 * Covers:
 *  - Security.framework SecTrustEvaluateWithError
 *  - Security.framework SecTrustEvaluate
 *  - NSURLSession delegate challenge handling
 *  - AFNetworking / AFSecurityPolicy (evaluateServerTrust:forDomain:)
 */

(function () {
    console.log("[*] Initializing Universal iOS SSL Pinning Bypass...");

    // 1. Hook SecTrustEvaluateWithError (iOS 12+)
    var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, errorPtr) {
            console.log("[+] SecTrustEvaluateWithError bypassed");
            if (!errorPtr.isNull()) {
                errorPtr.writePointer(NULL);
            }
            return 1; // true
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] Hooked SecTrustEvaluateWithError");
    }

    // 2. Hook SecTrustEvaluate (legacy iOS / fallback)
    var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, resultPtr) {
            console.log("[+] SecTrustEvaluate bypassed");
            if (!resultPtr.isNull()) {
                resultPtr.writeU32(1); // kSecTrustResultProceed = 1, kSecTrustResultUnspecified = 4
            }
            return 0; // errSecSuccess = 0
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] Hooked SecTrustEvaluate");
    }

    // 3. Hook Objective-C frameworks if runtime is available
    if (ObjC.available) {
        // AFNetworking / AFSecurityPolicy
        try {
            if (ObjC.classes.AFSecurityPolicy) {
                var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
                var evalSel = '- evaluateServerTrust:forDomain:';
                if (AFSecurityPolicy[evalSel]) {
                    AFSecurityPolicy[evalSel].implementation = ObjC.implement(
                        AFSecurityPolicy[evalSel],
                        function (self, sel, trust, domain) {
                            var domainStr = domain ? domain.toString() : "unspecified";
                            console.log("[+] AFSecurityPolicy evaluateServerTrust:forDomain: bypassed for: " + domainStr);
                            return 1; // YES
                        }
                    );
                    console.log("[+] Hooked AFSecurityPolicy evaluateServerTrust:forDomain:");
                }
            }
        } catch (e) {
            console.log("[-] AFSecurityPolicy hook error: " + e.message);
        }

        // NSURLSession didReceiveChallenge
        try {
            var NSURLCredential = ObjC.classes.NSURLCredential;
            var classes = ObjC.enumerateLoadedClassesSync();
            var targetMethod = '- URLSession:didReceiveChallenge:completionHandler:';
            for (var i = 0; i < classes.length; i++) {
                var className = classes[i];
                var cls = ObjC.classes[className];
                if (cls && cls[targetMethod]) {
                    (function (cName, methodObj) {
                        try {
                            Interceptor.attach(methodObj.implementation, {
                                onEnter: function (args) {
                                    var challenge = new ObjC.Object(args[3]);
                                    var completionHandler = new ObjC.Block(args[4]);
                                    var protectionSpace = challenge.protectionSpace();
                                    var authMethod = protectionSpace.authenticationMethod().toString();
                                    if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                                        console.log("[+] NSURLSession didReceiveChallenge bypassed for class: " + cName);
                                        var trust = protectionSpace.serverTrust();
                                        var cred = NSURLCredential.credentialForTrust_(trust);
                                        // disposition: NSURLSessionAuthChallengeUseCredential = 0
                                        completionHandler.implementation(0, cred);
                                    }
                                }
                            });
                        } catch (err) {}
                    })(className, cls[targetMethod]);
                }
            }
        } catch (e) {
            console.log("[-] NSURLSession challenge hook error: " + e.message);
        }
    }

    console.log("[+] Universal iOS SSL Pinning Bypass active.");
})();
"""


class StatusResult(TypedDict):
    cert_present: bool
    cert_path: str | None
    subject_hash: str | None
    hash_filename: str | None
    subject_details: NotRequired[str]
    error: NotRequired[str]


class ExportResult(TypedDict):
    success: bool
    source_cert: str
    target_path: str
    subject_hash: str
    hash_filename: str
    size_bytes: int
    error: NotRequired[str]


class CommandResult(TypedDict):
    success: bool
    action: str
    message: str
    details: NotRequired[dict[str, Any]]
    error: NotRequired[str | None]

def run_process(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def find_openssl() -> str:
    which = shutil.which("openssl")
    if which:
        return which
    if Path("/usr/bin/openssl").exists():
        return "/usr/bin/openssl"
    return "openssl"


def get_subject_hash(cert_path: Path) -> tuple[str | None, str | None]:
    """Return (subject_hash_old, subject_details) using openssl."""
    if not cert_path.exists():
        return None, None
    openssl = find_openssl()
    proc = run_process([openssl, "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path), "-noout"])
    if proc.returncode != 0:
        # Fall back without -noout
        proc = run_process([openssl, "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path)])
        if proc.returncode != 0:
            return None, None
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        return None, None
    subject_hash = lines[0]

    # Get subject details
    detail_proc = run_process([openssl, "x509", "-in", str(cert_path), "-text", "-fingerprint"])
    details = detail_proc.stdout if detail_proc.returncode == 0 else ""
    return subject_hash, details


def get_ca_status(cert_path: Path | None = None) -> StatusResult:
    target = cert_path or DEFAULT_MITMPROXY_CA
    if not target.exists():
        return {
            "cert_present": False,
            "cert_path": None,
            "subject_hash": None,
            "hash_filename": None,
            "error": f"Certificate not found at {target}. Run mitmproxy/mitmdump once to generate it.",
        }
    subject_hash, details = get_subject_hash(target)
    if not subject_hash:
        return {
            "cert_present": True,
            "cert_path": str(target),
            "subject_hash": None,
            "hash_filename": None,
            "error": "Failed to compute subject_hash_old with openssl.",
        }
    res: StatusResult = {
        "cert_present": True,
        "cert_path": str(target),
        "subject_hash": subject_hash,
        "hash_filename": f"{subject_hash}.0",
    }
    if details:
        res["subject_details"] = details
    return res


def export_ca_cert(out_dir: Path, cert_path: Path | None = None) -> ExportResult:
    target = cert_path or DEFAULT_MITMPROXY_CA
    status = get_ca_status(target)
    if not status["cert_present"] or not status["subject_hash"] or not status["hash_filename"]:
        return {
            "success": False,
            "source_cert": str(target),
            "target_path": "",
            "subject_hash": "",
            "hash_filename": "",
            "size_bytes": 0,
            "error": status.get("error", "Certificate unavailable"),
        }
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / status["hash_filename"]

    cert_text = target.read_text(encoding="utf-8")
    subject_details = status.get("subject_details", "")
    formatted_content = f"{cert_text}\n{subject_details}".strip() + "\n"

    out_file.write_text(formatted_content, encoding="utf-8")
    return {
        "success": True,
        "source_cert": str(target),
        "target_path": str(out_file.resolve()),
        "subject_hash": status["subject_hash"],
        "hash_filename": status["hash_filename"],
        "size_bytes": out_file.stat().st_size,
    }


def set_android_proxy(host: str, port: int, serial: str | None = None) -> CommandResult:
    adb = shutil.which("adb") or "adb"
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    proxy_val = f"{host}:{port}"
    cmd.extend(["shell", "settings", "put", "global", "http_proxy", proxy_val])
    proc = run_process(cmd)
    if proc.returncode != 0:
        return {
            "success": False,
            "action": "set-android-proxy",
            "message": f"Failed to set global http_proxy: {proc.stderr.strip()}",
            "error": proc.stderr.strip(),
        }
    return {
        "success": True,
        "action": "set-android-proxy",
        "message": f"Global http_proxy set to {proxy_val}",
        "details": {"host": host, "port": port, "proxy": proxy_val, "serial": serial},
    }


def clear_android_proxy(serial: str | None = None) -> CommandResult:
    adb = shutil.which("adb") or "adb"
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(["shell", "settings", "put", "global", "http_proxy", ":0"])
    proc = run_process(cmd)
    if proc.returncode != 0:
        return {
            "success": False,
            "action": "clear-android-proxy",
            "message": f"Failed to clear global http_proxy: {proc.stderr.strip()}",
            "error": proc.stderr.strip(),
        }
    return {
        "success": True,
        "action": "clear-android-proxy",
        "message": "Global http_proxy cleared",
        "details": {"serial": serial},
    }


def install_android_ca(serial: str | None = None, cert_path: Path | None = None) -> CommandResult:
    adb = shutil.which("adb")
    if not adb:
        return {
            "success": False,
            "action": "install-android",
            "message": "adb binary not found in PATH",
            "error": "adb not found",
        }

    status = get_ca_status(cert_path)
    if not status["cert_present"] or not status["hash_filename"]:
        return {
            "success": False,
            "action": "install-android",
            "message": f"CA cert not ready: {status.get('error')}",
            "error": status.get("error", "CA cert not ready"),
        }

    hash_file = status["hash_filename"]
    tmp_out = Path("/tmp") / hash_file
    exp = export_ca_cert(Path("/tmp"), cert_path)
    if not exp["success"]:
        return {
            "success": False,
            "action": "install-android",
            "message": f"Failed to export formatted CA: {exp.get('error')}",
            "error": exp.get("error"),
        }

    base_cmd = [adb]
    if serial:
        base_cmd.extend(["-s", serial])

    # 1. Push cert to /data/local/tmp
    push_cmd = base_cmd + ["push", str(tmp_out), f"/data/local/tmp/{hash_file}"]
    p_proc = run_process(push_cmd)
    if p_proc.returncode != 0:
        return {
            "success": False,
            "action": "install-android",
            "message": f"Failed to push CA to device: {p_proc.stderr.strip()}",
            "error": p_proc.stderr.strip(),
        }

    # 2. Check if /data/adb/modules exists (KernelSU / Magisk module)
    chk_ksu = base_cmd + ["shell", "su", "-c", "[ -d /data/adb/modules ] && echo ksu || echo noksu"]
    k_proc = run_process(chk_ksu)
    ksu_detected = "ksu" in k_proc.stdout

    installed_methods: list[str] = []

    if ksu_detected:
        mod_dir = "/data/adb/modules/mitmproxy-ca/system/etc/security/cacerts"
        setup_mod_script = (
            f"mkdir -p {mod_dir} && "
            f"cat << 'EOF' > /data/adb/modules/mitmproxy-ca/module.prop\n"
            f"id=mitmproxy-ca\n"
            f"name=Mitmproxy System CA\n"
            f"version=1.0\n"
            f"versionCode=1\n"
            f"author=reverse-engineering\n"
            f"description=Mitmproxy system CA certificate module\n"
            f"EOF\n"
            f"cp /data/local/tmp/{hash_file} {mod_dir}/{hash_file} && "
            f"chmod 644 {mod_dir}/{hash_file}"
        )
        mod_run = run_process(base_cmd + ["shell", "su", "-c", setup_mod_script])
        if mod_run.returncode == 0:
            installed_methods.append("KernelSU/Magisk module (/data/adb/modules/mitmproxy-ca)")

    # 3. Attempt direct write to /system/etc/security/cacerts/<hash>.0
    direct_script = (
        f"mount -o rw,remount / 2>/dev/null || mount -o rw,remount /system 2>/dev/null || true; "
        f"cp /data/local/tmp/{hash_file} /system/etc/security/cacerts/{hash_file} && "
        f"chmod 644 /system/etc/security/cacerts/{hash_file}"
    )
    d_run = run_process(base_cmd + ["shell", "su", "-c", direct_script])
    if d_run.returncode == 0:
        # Verify it exists
        verify = run_process(base_cmd + ["shell", "ls", f"/system/etc/security/cacerts/{hash_file}"])
        if verify.returncode == 0:
            installed_methods.append(f"Direct /system/etc/security/cacerts/{hash_file}")

    if not installed_methods:
        # Try tmpfs overlay as fallback
        overlay_script = (
            f"mkdir -p -m 700 /data/local/tmp/cacerts && "
            f"cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/ && "
            f"cp /data/local/tmp/{hash_file} /data/local/tmp/cacerts/{hash_file} && "
            f"chmod 644 /data/local/tmp/cacerts/{hash_file} && "
            f"mount -t tmpfs tmpfs /system/etc/security/cacerts && "
            f"cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/ && "
            f"chown root:root /system/etc/security/cacerts/* && "
            f"chmod 644 /system/etc/security/cacerts/*"
        )
        o_run = run_process(base_cmd + ["shell", "su", "-c", overlay_script])
        if o_run.returncode == 0:
            installed_methods.append("tmpfs mount overlay on /system/etc/security/cacerts")

    if installed_methods:
        return {
            "success": True,
            "action": "install-android",
            "message": f"Installed {hash_file} via: {', '.join(installed_methods)}",
            "details": {
                "hash_filename": hash_file,
                "methods": installed_methods,
                "serial": serial,
            },
        }

    return {
        "success": False,
        "action": "install-android",
        "message": f"Could not write {hash_file} to system cert store (su or remount failed).",
        "error": "Root/remount failed",
    }


def install_ios_sim_ca(device: str = DEFAULT_IOS_DEVICE, cert_path: Path | None = None) -> CommandResult:
    xcrun = shutil.which("xcrun")
    if not xcrun:
        return {
            "success": False,
            "action": "install-ios-sim",
            "message": "xcrun binary not found. iOS Simulator tooling requires macOS and Xcode CLI tools.",
            "error": "xcrun not found",
        }

    target = cert_path or DEFAULT_MITMPROXY_CA
    if not target.exists():
        return {
            "success": False,
            "action": "install-ios-sim",
            "message": f"Mitmproxy CA cert not found at {target}",
            "error": "cert not found",
        }

    cmd = [xcrun, "simctl", "keychain", device, "add-root-cert", str(target.resolve())]
    proc = run_process(cmd)
    if proc.returncode != 0:
        return {
            "success": False,
            "action": "install-ios-sim",
            "message": f"Failed to install CA into iOS Simulator keychain: {proc.stderr.strip()}",
            "error": proc.stderr.strip(),
        }

    return {
        "success": True,
        "action": "install-ios-sim",
        "message": f"Installed {target.name} into iOS Simulator ({device}) keychain successfully.",
        "details": {"device": device, "cert_path": str(target.resolve())},
    }


def export_frida_scripts(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    android_path = out_dir / "ssl_unpin_android.js"
    ios_path = out_dir / "ssl_unpin_ios.js"

    android_path.write_text(ANDROID_FRIDA_SCRIPT.strip() + "\n", encoding="utf-8")
    ios_path.write_text(IOS_FRIDA_SCRIPT.strip() + "\n", encoding="utf-8")

    return {
        "success": True,
        "out_dir": str(out_dir.resolve()),
        "scripts": {
            "android": str(android_path.resolve()),
            "ios": str(ios_path.resolve()),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    common_parser.add_argument(
        "--cert-path",
        type=Path,
        default=None,
        help="Path to mitmproxy-ca-cert.pem (default: ~/.mitmproxy/mitmproxy-ca-cert.pem)",
    )

    parser = argparse.ArgumentParser(
        description="Mitmproxy CA certificate setup & SSL pinning bypass helper.",
        parents=[common_parser],
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    subparsers.add_parser("status", parents=[common_parser], help="Check mitmproxy CA cert presence and subject hash")

    # export-ca
    p_export = subparsers.add_parser("export-ca", parents=[common_parser], help="Export formatted <hash>.0 Android CA file")
    p_export.add_argument("--out-dir", type=Path, default=Path.cwd(), help="Output directory")

    # set-android-proxy
    p_set = subparsers.add_parser("set-android-proxy", parents=[common_parser], help="Set global HTTP proxy on Android emulator")
    p_set.add_argument("--host", default=DEFAULT_ANDROID_HOST, help=f"Proxy host IP (default: {DEFAULT_ANDROID_HOST})")
    p_set.add_argument("--port", type=int, default=DEFAULT_ANDROID_PORT, help=f"Proxy port (default: {DEFAULT_ANDROID_PORT})")
    p_set.add_argument("--serial", default=None, help="Device serial (adb -s)")

    # clear-android-proxy
    p_clear = subparsers.add_parser("clear-android-proxy", parents=[common_parser], help="Clear global HTTP proxy on Android emulator")
    p_clear.add_argument("--serial", default=None, help="Device serial (adb -s)")

    # install-android
    p_inst_and = subparsers.add_parser("install-android", parents=[common_parser], help="Install CA cert to connected Android device/emulator")
    p_inst_and.add_argument("--serial", default=None, help="Device serial (adb -s)")

    # install-ios-sim
    p_inst_ios = subparsers.add_parser("install-ios-sim", parents=[common_parser], help="Install CA cert into iOS Simulator keychain")
    p_inst_ios.add_argument("--device", default=DEFAULT_IOS_DEVICE, help=f"Simulator device UDID or 'booted' (default: {DEFAULT_IOS_DEVICE})")

    # export-frida-scripts
    p_frida = subparsers.add_parser("export-frida-scripts", parents=[common_parser], help="Export universal SSL unpinning Frida scripts")
    p_frida.add_argument("--out-dir", type=Path, default=Path.cwd(), help="Output directory")

    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cert_path: Path | None = args.cert_path

    if args.command == "status":
        res = get_ca_status(cert_path)
        if args.json:
            sys.stdout.write(json.dumps(res, indent=2) + "\n")
        else:
            if res["cert_present"]:
                sys.stdout.write(f"Mitmproxy CA cert: {res['cert_path']}\n")
                sys.stdout.write(f"Subject hash (old): {res['subject_hash']}\n")
                sys.stdout.write(f"Target filename: {res['hash_filename']}\n")
                sys.stdout.write("Status: present\n")
            else:
                sys.stderr.write(f"Error: {res.get('error')}\n")
                return 1
        return 0 if res["cert_present"] else 1

    elif args.command == "export-ca":
        res_exp = export_ca_cert(args.out_dir, cert_path)
        if args.json:
            sys.stdout.write(json.dumps(res_exp, indent=2) + "\n")
        else:
            if res_exp["success"]:
                sys.stdout.write(f"Exported CA to: {res_exp['target_path']} ({res_exp['size_bytes']} bytes)\n")
            else:
                sys.stderr.write(f"Error exporting CA: {res_exp.get('error')}\n")
                return 1
        return 0 if res_exp["success"] else 1

    elif args.command == "set-android-proxy":
        res_set = set_android_proxy(args.host, args.port, args.serial)
        if args.json:
            sys.stdout.write(json.dumps(res_set, indent=2) + "\n")
        else:
            sys.stdout.write(f"{res_set['message']}\n")
        return 0 if res_set["success"] else 1

    elif args.command == "clear-android-proxy":
        res_clear = clear_android_proxy(args.serial)
        if args.json:
            sys.stdout.write(json.dumps(res_clear, indent=2) + "\n")
        else:
            sys.stdout.write(f"{res_clear['message']}\n")
        return 0 if res_clear["success"] else 1

    elif args.command == "install-android":
        res_inst = install_android_ca(args.serial, cert_path)
        if args.json:
            sys.stdout.write(json.dumps(res_inst, indent=2) + "\n")
        else:
            sys.stdout.write(f"{res_inst['message']}\n")
        return 0 if res_inst["success"] else 1

    elif args.command == "install-ios-sim":
        res_ios = install_ios_sim_ca(args.device, cert_path)
        if args.json:
            sys.stdout.write(json.dumps(res_ios, indent=2) + "\n")
        else:
            sys.stdout.write(f"{res_ios['message']}\n")
        return 0 if res_ios["success"] else 1

    elif args.command == "export-frida-scripts":
        res_frida = export_frida_scripts(args.out_dir)
        if args.json:
            sys.stdout.write(json.dumps(res_frida, indent=2) + "\n")
        else:
            sys.stdout.write(f"Exported Frida scripts to {res_frida['out_dir']}:\n")
            for platform_name, script_path in res_frida["scripts"].items():
                sys.stdout.write(f"  - {platform_name}: {script_path}\n")
        return 0 if res_frida["success"] else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
