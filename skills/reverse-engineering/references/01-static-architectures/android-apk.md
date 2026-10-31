# Android APK Reverse Engineering

## When To Open
Open this file for an `.apk`, `.aab`, `.xapk`, or `.apkm`: manifest attack surface, Java or Kotlin logic, smali patch-and-rebuild, packer identification, signature schemes, split-APK assembly, and the handoff into a native `.so`. DEX internals, Smali syntax, ProGuard/R8, ConfuserEx, and `RegisterNatives` recovery live in [managed-dotnet-jvm.md](managed-dotnet-jvm.md). Flutter stays in [flutter-dart.md](flutter-dart.md). React Native and Hermes stay in [react-native-hermes.md](react-native-hermes.md). Unity stays in [unity-il2cpp.md](unity-il2cpp.md).

This file is the decision order for Android packages. It tells you which view to open, when to leave Java for native, and how to rebuild a patched package. Static first. Dynamic only in a lab or rooted emulator; see [host-and-lab-setup.md](../05-environment/host-and-lab-setup.md) and `uv run scripts/setup_android_emulator.py`.

## Order Of Work
Do not patch smali, and do not write a hook, until the manifest and the entry classes have been read.

1. **Identify the container first.** A plain `.apk` is a ZIP. An `.aab` is an App Bundle (not installable directly). An `.xapk`/`.apkm` is a ZIP of a base APK plus split APKs. Handle splits before decompiling (see "Split APKs, XAPK, AAB").
2. **Decode both views.** `jadx` for reading Java/Kotlin, `apktool` for the manifest, resources, and smali. A partial jadx run is still evidence. Incomplete Java is not "the logic cannot be analyzed."
   ```bash
   jadx -d jadx_out --deobf app.apk            # readable Java/Kotlin
   apktool d app.apk -o apk_out                # manifest, resources, smali
   ```
3. **Read the manifest first.** Package name, `application` class, the launcher activity, and every exported component. See "Manifest Attack Surface."
4. **Read Java at the entry.** `Application.onCreate`, the launcher activity, then classes matching `login`, `sign`, `cipher`, `token`, `okhttp`, `retrofit`, `webview`, `certificate`, `root`, `integrity`.
5. **Leave Java when the method is a wrapper.** `System.loadLibrary`, a `native` method with no `Java_` export, or a signing check that disappears after the load. Continue in the ABI under `lib/`. See "Native Handoff."
6. **Smali is the patch surface, not the first reading surface.** Use it when jadx failed on a method or a rebuild must change a branch. See "Smali Patch, Rebuild, Sign."
7. **Rebuild only after the edit is named.** `apktool b`, then `zipalign`, then `apksigner`. Keep the original APK and its hash.

## Tooling On This Host
| Task | Tool | Verified invocation |
|---|---|---|
| Java/Kotlin decompile | jadx 1.5.6 | `jadx -d jadx_out --deobf app.apk` |
| Manifest/resources/smali | apktool 3.0.3 | `apktool d app.apk -o apk_out` |
| Rebuild | apktool 3.0.3 | `apktool b apk_out -o patched.apk` |
| Align | zipalign (build-tools) | `zipalign -p -f 4 in.apk out.apk` |
| Sign + verify | apksigner (build-tools) | `apksigner sign ...` / `apksigner verify -v ...` |
| App id / min-sdk | apkanalyzer | `apkanalyzer manifest application-id app.apk` |
| Split assembly / AAB build | bundletool (jar) | `java -jar bundletool.jar build-apks ...` |
| Native symbols | readelf / r2 | `readelf -Ws lib/arm64-v8a/libfoo.so` |

`apksigner`, `zipalign`, and `apkanalyzer` ship in the Android SDK (`$ANDROID_HOME/build-tools/<ver>/` and `cmdline-tools/latest/bin/`). `bundletool` is a standalone jar from the AndroidX bundletool releases; it is not on PATH by default.

jadx deobfuscation flags that exist in 1.5.6: `--deobf`, `--deobf-min <n>` (default 3), `--deobf-max <n>`, `--deobf-whitelist`, `--deobf-cfg-file <file>`, `--deobf-cfg-file-mode`, `--rename-flags`, `--mappings-path`, `--mappings-mode`. There is no `--deobf-parse-kotlin-metadata` and no `--deobf-rewrite-cfg`; Kotlin renaming is controlled by the `kotlin-metadata.*` plugin options. To persist an auto-generated name map so manual corrections survive a re-run, use `--deobf-cfg-file names.jobf --deobf-cfg-file-mode overwrite` (then `read` on later runs). To load a ProGuard `mapping.txt`, use `--mappings-path mapping.txt`.

## Manifest Attack Surface
Read `apk_out/AndroidManifest.xml` (apktool decodes the binary XML to text; jadx also shows it). Treat the following as the reachable surface, not as capabilities by themselves.

- **`android:exported="true"`** components, plus any component with an `intent-filter` (implicitly exported pre-S, must be explicit on API 31+). These are the external entry points: `Activity`, `Service`, `BroadcastReceiver`, `ContentProvider`.
- **`ContentProvider`** `android:authorities`, `android:grantUriPermissions`, and `android:readPermission`/`writePermission`. Exported providers without permission gating are a direct data surface.
- **`android:permission`** on a component versus a custom permission with `android:protectionLevel="normal"` (any app can hold it) versus `signature` (same signer only).
- **`android:debuggable="true"`**, **`android:allowBackup="true"`**, **`android:networkSecurityConfig`** (points to an XML in `res/xml/` that may pin certs or allow cleartext/user CAs).
- **`<uses-permission>`** list, especially `REQUEST_INSTALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`, `QUERY_ALL_PACKAGES`.
- **Launcher activity**: the `<activity>` with `<action android:name="android.intent.action.MAIN"/>` and `<category android:name="android.intent.category.LAUNCHER"/>`.
- **`android:name` on `<application>`**: the custom `Application` subclass. Its `attachBaseContext`/`onCreate` runs before any activity and is where packers and SDK init live.
- **Hidden launcher**: `Theme.NoDisplay`, empty label, or no launcher category is an observation about the package, not a reason to execute it.

Get the application id programmatically for later commands:
```bash
PACKAGE_ID="$(apkanalyzer manifest application-id app.apk)"
test -n "$PACKAGE_ID" && echo "$PACKAGE_ID"
```

## Multi-DEX
Modern APKs split code across `classes.dex`, `classes2.dex`, `classes3.dex`, and so on. jadx and apktool read all of them automatically when given the APK. If you hand a tool a single extracted `classes.dex`, you see only part of the program. List them before concluding anything about coverage:
```bash
unzip -l app.apk | grep -E 'classes[0-9]*\.dex'
```
A `classes.dex` that is tiny or holds only a loader class, while the real classes live in an asset or a second DEX decrypted at runtime, means the first DEX is a stub. See "Packers."

## Packers
A stub `classes.dex` plus a known packer native library means the Java you see is the loader, not the app. Identify the packer by the library name under `lib/<abi>/` or by asset names, then dump the runtime DEX inside the lab and run jadx on the dump.

| Packer | Library / asset signature |
|---|---|
| Bangcle / SecShell | `libsecexe.so`, `libSecShell.so`, `libDexHelper.so`, assets `classes0.jar` |
| Qihoo 360 Jiagu | `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so` |
| Tencent Legu | `libshella-*.so`, `libshellx-*.so`, `libtup.so`, `libtxdexff.so`, assets `tencent_stub` |
| Ali / Alibaba | `libmobisec.so`, `libsgmain.so`, `libsgsecuritybody.so` |
| Baidu | `libbaiduprotect.so`, asset `baiduprotect.jar` |
| Jiagu (DexProtector) | `libdexprotector.*.so`, encrypted assets under `assets/dp/` |
| ApkProtect / APKProtect | `libAPKProtect.so`, `libapkprotect2.so` |

Dumping approach (lab only, rooted emulator): let the app start so the real DEX is loaded into memory, then dump loaded DEX images. `frida-dexdump` (Frida script that scans the process for `dex\n0` magic and carves each in-memory DEX) is the common path; run it from the lab host against the emulator. See [frida.md](../04-tool-usage/frida.md) and `uv run scripts/dump_memory.py`. Do not conclude the app's behavior from the stub, and do not execute a packed sample outside the lab.

## Signature Schemes v1-v4
Android has four APK signing schemes. A rebuild must re-sign, and the scheme matters for what the device accepts.

- **v1 (JAR signing)**: `META-INF/*.SF`, `*.RSA`/`*.DSA`, and `MANIFEST.MF`. Per-file digests. Does not protect the ZIP structure outside the manifest. Required for pre-API-24 installs.
- **v2 (APK Signature Scheme v2, API 24+)**: a signing block inserted before the ZIP central directory; hashes the whole APK. Breaks if the ZIP is modified after signing. This is why you sign last.
- **v3 (API 28+)**: v2 plus key-rotation (`SigningCertificateLineage`).
- **v4 (API 30+)**: a separate `<apk>.idsig` file carrying a Merkle-tree hash for incremental install; used with `adb install --incremental`. Not a standalone scheme — it accompanies v2/v3.

Inspect what an APK carries:
```bash
apksigner verify -v --print-certs app.apk
```
It prints which schemes verified (v1/v2/v3/v4), the signer certificate, and the digest. A self-rebuilt APK will carry your research key, not the original signer — expected, and relevant to any same-signer permission or `signatureOrSystem` check.

## Split APKs, XAPK, AAB
- **Split APKs** (`split_config.arm64_v8a.apk`, `split_config.xxhdpi.apk`, `base.apk`): the base plus per-ABI, per-density, and per-language splits. Decompile `base.apk` for code; the splits usually hold resources and native libs. Install all together with `adb install-multiple base.apk split_*.apk`.
- **XAPK / APKM**: a ZIP wrapper. Unzip to recover the base and splits, then treat as split APKs.
  ```bash
  mkdir -p xapk_out && unzip -q app.xapk -d xapk_out && ls xapk_out/*.apk
  ```
- **AAB (`.aab`)**: an App Bundle, a build artifact, not installable. To get installable APKs, build a universal or device-specific set with bundletool:
  ```bash
  java -jar bundletool.jar build-apks --bundle=app.aab --output=app.apks \
    --mode=universal
  # app.apks is a ZIP; the universal APK is inside.
  unzip -o app.apks -d apks_out && ls apks_out
  ```
  For analysis a universal APK is simplest: one APK with all ABIs and resources. jadx reads the bundle's `base/dex/` too, but a built universal APK matches what a device runs.

## Native Handoff
Leave Java when a method is a thin wrapper over native code.

- `System.loadLibrary("foo")` loads `lib/<abi>/libfoo.so`. `arm64-v8a` is the device ABI. `x86_64` is easier to decompile when the APK ships it; pick it for static work if present, but verify behavior matches arm64.
- A `native`-declared Java method is implemented either by an exported `Java_<pkg>_<Class>_<method>` symbol (static binding) or by a pointer registered via `RegisterNatives` in `JNI_OnLoad` (dynamic binding, no matching export). Recovery of both, and reading the `JNINativeMethod` table, is in [managed-dotnet-jvm.md](managed-dotnet-jvm.md).
- Confirm the export before assuming static binding:
  ```bash
  readelf -Ws lib/arm64-v8a/libfoo.so | grep -i 'Java_\|JNI_OnLoad\|RegisterNatives'
  ```
- A signing or root check that reads bytes in Java but decides in native belongs to the `.so`. Continue in a native decompiler ([native-cpp-abi.md](native-cpp-abi.md)) or IDA via the official HexRaysSA `ida-mcp` (`open_database`, `execute_python`); see [ida-mcp-remote-debugging.md](../04-tool-usage/ida-mcp-remote-debugging.md). Do not reference any other IDA bridge.

## Smali Patch, Rebuild, Sign
Prefer the smallest edit that changes the decision: an exported-component guard, a single boolean return, or one branch. Do not rewrite a method you have not first located in jadx.

1. Decode to smali with apktool (`apktool d app.apk -o apk_out`).
2. Find the method in `apk_out/smali*/...`. Edit the branch or return. A common root/integrity bypass forces a method that returns `Z` (boolean) to return false (or true), e.g. replace the body's result with:
   ```smali
   const/4 v0, 0x0
   return v0
   ```
   Change a conditional (`if-eqz`, `if-nez`) only after confirming the register and the branch target in jadx.
3. Rebuild, align, sign, verify. Use a debug or research keystore, never a cracked production key.
   ```bash
   # Rebuild
   apktool b apk_out -o patched.unsigned.apk

   # Create a research keystore once
   keytool -genkeypair -v -keystore research.keystore \
     -alias research -keyalg RSA -keysize 2048 -validity 10000 \
     -storepass android -keypass android \
     -dname "CN=research, OU=re, O=lab, C=US"

   # Align BEFORE signing (v2/v3 hash the aligned file)
   BUILD_TOOLS="$ANDROID_HOME/build-tools/36.0.0"
   "$BUILD_TOOLS/zipalign" -p -f 4 patched.unsigned.apk patched.aligned.apk

   # Sign with v1+v2+v3
   "$BUILD_TOOLS/apksigner" sign \
     --ks research.keystore --ks-key-alias research \
     --ks-pass pass:android --key-pass pass:android \
     --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
     --out patched.apk patched.aligned.apk

   # Verify
   "$BUILD_TOOLS/apksigner" verify -v --print-certs patched.apk
   ```
4. Install only on the disposable lab device:
   ```bash
   adb install -r patched.apk          # or install-multiple for splits
   ```
   `adb install` of an unsigned APK is rejected. An `adb install` is not, by itself, a signed package — the signing step above is what makes it installable.

Keep the original APK and record its `shasum -a 256`. Record whether a hook only printed (observation) or forced a return (experiment).

## Play Integrity Awareness
Many apps call the Play Integrity API (successor to SafetyNet Attestation) through Google Play services and ship server-verified integrity verdicts. Consequences for analysis:

- The verdict is produced by Play services and signed by Google; it is not a local boolean you flip in smali. A client-side patch that fakes a local check does not forge the server-validated token.
- Rooted emulators, unlocked bootloaders, and modified packages typically fail `MEETS_DEVICE_INTEGRITY` / `MEETS_STRONG_INTEGRITY`. Expect integrity-gated features to refuse to run even after a clean smali patch.
- Static-first: read how the app consumes the verdict (which endpoints gate on it, which features degrade) rather than trying to defeat attestation. Record integrity gating as an observation.
- Root/emulator hardening (Magisk DenyList, hiding `su`) is a lab-environment concern, not an APK edit. Setup is in [host-and-lab-setup.md](../05-environment/host-and-lab-setup.md) and `uv run scripts/setup_android_emulator.py`.

## Dynamic
Hook Java before native. Print arguments and the return value before changing either. `javax.crypto.Cipher.getInstance` and `Cipher.init` name the algorithm and key bytes. `frida-trace` on a certificate or cipher glob is the scout; a full bypass script is a later step, and only on a device you are allowed to instrument.

The Frida CLI and REPL (Frida 17.x on this host) still bundle the Java and ObjC bridges, so `Java.perform` / `Java.use` work directly with `frida -U -l script.js`. Agents built with `frida-compile` must now add the `frida-java-bridge` npm package explicitly — the bundled bridge was removed from the default runtime in Frida 17. Prefer `Interceptor.attach` and `Module.*` instance methods; the removed statics (`Module.findExportByName(null, ...)` → `Module.findGlobalExportByName`, `Memory.readU32` → `ptr.readU32()`) matter once you touch native code. Transport and script loading are in [frida.md](../04-tool-usage/frida.md). Proxy capture is in [network-traffic-proxy.md](../02-dynamic-instrumentation/network-traffic-proxy.md); CA install is `uv run scripts/setup_proxy_ca.py install-android`.

## Boundaries
- JEB is a licensed decompiler. Do not download or crack it. If it is not available, stay on jadx, apktool, baksmali, and a native decompiler.
- A hook that only prints is an observation. A hook that forces a return is an experiment. Record which one you ran.
- Xamarin and MAUI ship C# plus `XALZ`-compressed assemblies. Once the assemblies are extracted, the managed layer is [managed-dotnet-jvm.md](managed-dotnet-jvm.md), not this APK path.
- Do not execute a packed or hidden-launcher sample outside the lab. Dumping the runtime DEX is a lab action.
- Analyze only packages and endpoints covered by explicit authorization. Remove the proxy CA, proxy setting, patched package, and Frida server from disposable targets when the analysis ends.
