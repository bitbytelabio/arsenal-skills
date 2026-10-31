# Android APK Reverse Engineering

## When To Open
Open this file for an `.apk` or `.aab`: manifest, Java or Kotlin business logic, smali patches, packers, or the handoff into a native `.so`. DEX layout, Smali syntax, ProGuard, and `RegisterNatives` stay in [managed-dotnet-jvm.md](managed-dotnet-jvm.md). Flutter and React Native stay in their own architecture files.

## Order Of Work
Do not patch smali, and do not write a hook, until the manifest and the entry classes have been read.

1. **Decode both views.** `jadx -d jadx_out --deobf app.apk` for reading. `apktool d app.apk -o apk_out` for the manifest, resources, and smali. A partial jadx run is still evidence. Incomplete Java is not "the logic cannot be analyzed."
2. **Read the manifest first.** Package name, `application`, activities, services, receivers, providers, exported components, and the launcher activity. Permissions and `android:debuggable` / `android:allowBackup` are observations, not capabilities by themselves.
3. **Read Java at the entry.** `Application`, the launcher activity, then classes matching `login`, `sign`, `cipher`, `token`, `okhttp`, `retrofit`, `webview`, `certificate`, `root`.
4. **Leave Java when the method is a wrapper.** `System.loadLibrary`, a `native` method with no `Java_` export, or a certificate or signing check that disappears after the load. Continue in the ABI under `lib/` that you can decompile. `arm64-v8a` is the device ABI. `x86_64` is easier to decompile when the APK ships it. JNI binding is in [managed-dotnet-jvm.md](managed-dotnet-jvm.md).
5. **Smali is the patch surface, not the first reading surface.** Use it when jadx failed on a method or a rebuild has to change a branch. Prefer exported-component flags, a single boolean return, or a certificate branch. Do not rewrite a method you have not located in Java.
6. **Rebuild only after the edit is named.** `apktool b`, then `zipalign`, then `apksigner`. `adb install` is not a signed package. Keep the original APK.

## Packers And Multi-DEX
A classes.dex that is a stub, plus `libjiagu`, `libsecexe`, `libDexHelper`, or a packer asset, means the Java you see is the loader. Dump the runtime DEX inside the lab, then run jadx on the dump. Do not conclude the app's behavior from the stub. Open every `classes*.dex`, not only `classes.dex`.

Record, and do not execute, a manifest that hides its icon (`Theme.NoDisplay`, empty label, no launcher category) or an asset that is a remote shell script. Those are observations about the package.

## Dynamic
Hook Java before native. Print arguments and the return value before changing either. `javax.crypto.Cipher.getInstance` and `Cipher.init` name the algorithm and the key bytes. `frida-trace` on a certificate or cipher glob is the scout. A full bypass script is a later step, and only on a device you are allowed to instrument. Root and proxy setup stay in `SKILL.md` and [frida.md](../04-tool-usage/frida.md).

## Boundaries
- JEB is a licensed second decompiler. Do not download or crack it. If it is not already available, stay on jadx, apktool, and a native decompiler.
- A hook that only prints is an observation. A hook that forces a return is an experiment. Record which one you ran.
- Xamarin and MAUI ship C# plus `XALZ` blobs. The managed layer is [managed-dotnet-jvm.md](managed-dotnet-jvm.md), not this APK path, once the assemblies are extracted.
