# Rule 2: Progressive Reference Disclosure

## Mandate
After obtaining the triage manifest, load **ONLY** the single matching domain reference recommended by the scanner or determined by primary runtime classification.

## Reference Hierarchy
The reference repository follows a strict stage-gate hierarchy:
1. `references/01-static-architectures/`: Load the single document corresponding to the target's language runtime or binary ecosystem:
   - Go: `references/01-static-architectures/native-golang.md`
   - Rust: `references/01-static-architectures/native-rust.md`
   - C/C++ (MSVC/GCC/Clang): `references/01-static-architectures/native-cpp-abi.md`
   - .NET / JVM: `references/01-static-architectures/managed-dotnet-jvm.md`
   - Android APK: `references/01-static-architectures/android-apk.md` (DEX and JNI internals stay in `managed-dotnet-jvm.md`)
   - iOS / Mach-O: `references/01-static-architectures/mobile-ios.md`
   - Unity IL2CPP: `references/01-static-architectures/unity-il2cpp.md`
   - Flutter / Dart: `references/01-static-architectures/flutter-dart.md`
   - React Native: `references/01-static-architectures/react-native-hermes.md`
   - Firmware / Embedded: `references/01-static-architectures/firmware-iot.md`
   - Scripts / Non-PE: `references/01-static-architectures/script-nonpe-analysis.md`
   - Runtime exe, game pack, or installer: `references/01-static-architectures/runtimes-and-packagers.md`
   - Browser JS / WASM: `references/01-static-architectures/browser-js-wasm.md`
   - Browser Extensions: `references/01-static-architectures/browser-extensions.md`
   - Anti-Analysis / Armor: `references/01-static-architectures/deobfuscation-anti-analysis.md`
2. `references/02-dynamic-instrumentation/`: Load strictly upon reaching a dynamic instrumentation phase and obtaining required safety authorizations:
   - Frida instrumentation: `references/02-dynamic-instrumentation/frida-hooking.md`
   - Debugger workflows: `references/02-dynamic-instrumentation/debugger-workflows.md`
   - Unpacking & memory dumping: `references/02-dynamic-instrumentation/unpacking-memory-dump.md`
   - Fuzzing as a reversing oracle: `references/02-dynamic-instrumentation/fuzzing-for-reversing.md`
   - Network interception: `references/02-dynamic-instrumentation/network-traffic-proxy.md`
   - Sandbox containment: `references/02-dynamic-instrumentation/malware-sandbox-isolation.md`
3. `references/03-objectives/`: Load strictly when producing final analytical deliverables or target-specific verification contracts:
   - Algorithmic reconstruction: `references/03-objectives/algorithm-recovery.md`
   - Network protocols / IPC: `references/03-objectives/protocol-recovery.md`
   - Vulnerability research & patching: `references/03-objectives/vuln-research-patch.md`
   - Artifact schema verification: `references/03-objectives/static-artifact-contract.md`
   - Desktop thick client: `references/03-objectives/thick-client.md`
   - Recognized field shape: `references/03-objectives/case-patterns.md`
4. `references/05-environment/`: Load when the task is host detection, tool install, a rooted emulator, a proxy CA, or VM provisioning. This does not replace the architecture reference.

## Prohibition
A path saved in a ledger, including `recommended_reference`, is not identification. Confirm the format from the file bytes before opening that reference.

Never preload multiple domain references simultaneously under speculative "just-in-case" assumptions. Simultaneous preloading is permitted only when concrete triage evidence demonstrates a hybrid multi-runtime target (e.g. Unity IL2CPP using both `unity-il2cpp.md` and `native-cpp-abi.md`, or an Electron desktop application combining Node.js native addons with Chromium V8).
