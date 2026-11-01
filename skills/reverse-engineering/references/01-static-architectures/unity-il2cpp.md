# Unity IL2CPP Reverse Engineering

## 1. Overview
- **Domain**: Unity games and apps built with the IL2CPP backend. C# is compiled to C++ and then to native code. Names, types, and method addresses live in `global-metadata.dat`. The code lives in `libil2cpp.so`, `GameAssembly.dll`, or `UnityFramework`.
- **Goal of this reference**: get a correct `dump.cs` (types, fields, method RVAs) and symbolized IDA/Ghidra database on the first attempt. Pick the route from what the package actually contains, not from habit.
- **Helper**: `scripts/il2cpp_tools.py` wraps every tool below with no interactive prompts. Start with `doctor` and `extract`.

Most failed runs come from one of four mistakes:
1. Running a static dumper on a protected build, where the metadata is encrypted or the runtime image only exists in memory.
2. Treating the wrong library as `libil2cpp.so` after the game renamed it, or rejecting the real image because it exports no `il2cpp_*` symbol.
3. A tool waiting on a prompt (`press any key`, `ask_file`, dump base) and the agent waiting on the tool.
4. Patching only the metadata magic, or scanning process memory only for `AF 1B B1 FA`, when the section words are permuted and a decoded copy still wears the variant magic.

## 2. Detection
- **Metadata**: `assets/bin/Data/Managed/Metadata/global-metadata.dat` (Android), `<Game>_Data/il2cpp_data/Metadata/global-metadata.dat` (Windows), `Data/Managed/Metadata/global-metadata.dat` inside the `.app` (iOS). The canonical first four bytes are `AF 1B B1 FA`. A protected file often keeps a one-byte variant, commonly `AF 1B B1 EA` (`0xEAB11BAF`). The next four bytes are the little-endian version. A plausible version (16–39 or 104–110) plus plaintext names such as `Assembly-CSharp` in the body means this is still metadata. Section offsets that run past EOF mean the header words are transformed, not that the file is truncated.
- **Runtime image**: `lib/<abi>/libil2cpp.so`, `GameAssembly.dll`, `Frameworks/UnityFramework.framework/UnityFramework`. A stock image exports hundreds of `il2cpp_*` functions. A protected image can export none, and so can `libmain.so` and a hook library. Do not reject a candidate for a missing export. Prefer the image mapped beside `global-metadata.dat`, or the largest executable image under the game's `files/` or `lib/<abi>/`. After a dump, `CodeRegistration` inside that image is the confirmation. A string search for `il2cpp_init` cannot tell a runtime image from a library that only mentions the API.
- **Mono, not IL2CPP**: `assets/bin/Data/Managed/*.dll` with real IL code and no `libil2cpp.so`. Use [managed-dotnet-jvm.md](managed-dotnet-jvm.md) instead.

## 3. Pick the route

Run these first:

```bash
uv run scripts/il2cpp_tools.py doctor
uv run scripts/il2cpp_tools.py extract game.apk -o work/        # APK, XAPK, APKS, IPA, or a game folder
```

`extract` looks inside split APKs. If the standard names are missing, it ranks libraries by exported `il2cpp_*` symbols (using LIEF) and scans assets for the metadata magic. It prints `metadata_info` (magic, version, sha256) and a hint.

| What `extract` reports | Route | Tool |
|---|---|---|
| Binary and metadata found, `magic_ok: true` | Static | `dump --engine dumper`. If it fails or looks wrong, `--engine inspector` or `--engine both`. |
| Package input, binary or metadata not split out cleanly | Static | `dump game.apk --engine inspector`. Inspector loads APK, XAPK, AAB, and decrypted IPA directly. |
| `magic_ok: false`, version not in 16–39 or 104–110 | Static first, then runtime | il2cpp-dumper-rs auto-detects simple XOR (1/4/8-byte, rolling, header-only). Inspector handles the Arknights, Free Fire, and Wild Rift styles, and loads plugins for miHoYo. If both fail, go to runtime. |
| `magic_ok: false`, version plausible, body already has assembly names, raw section ranges past EOF | Static header repair, then the normal dump | [§4.5](#45-header-only-permutation). XOR detectors do not cover a word permutation. Flipping the magic byte and dumping again is the same failure. Runtime only after §4.5 rejects the candidate. |
| No metadata file, or every native image is an importer | Runtime | `bridge-dump` (Frida). If the game kills Frida, use the Zygisk module. A runtime image with zero `il2cpp_*` exports stays on the static route when `global-metadata.dat` is present (§2). |
| You already have a memory dump of the runtime image | Static on the dump | `dump <dump.so> <metadata> --dump-base 0x<base>`. Inspector also reads GameGuardian `maps` + `.bin` dumps. |

Static is preferred whenever it works. It never runs the game, and the method RVAs match the shipped binary.

## 4. Static route

### 4.1 Install

```bash
uv run scripts/il2cpp_tools.py install-dumper      # cargo install from git; crates.io is several majors behind
uv run scripts/il2cpp_tools.py install-inspector   # Il2CppInspectorRedux CLI release; needs the .NET 10 runtime (brew install dotnet)
```

### 4.2 Run

```bash
uv run scripts/il2cpp_tools.py dump work/libil2cpp.so work/global-metadata.dat -o work/dump               # il2cpp-dumper-rs
uv run scripts/il2cpp_tools.py dump work/libil2cpp.so work/global-metadata.dat -o work/dump --engine both # compare engines
uv run scripts/il2cpp_tools.py dump game.apk -o work/dump --engine inspector --disassembler Ghidra
```

| Option | Use |
|---|---|
| `--force-version 29` | Metadata says 31 but the code registration is laid out like 29 (common on 2021–2022 builds). il2cpp-dumper-rs refines this automatically; force it only after a failed run. |
| `--dump-base 0x7a1c000000` | Input is a memory dump. Without it the dumper would prompt; with stdin closed, the wrapper fails instead of hanging. |
| `--force-dump` | Rewrite sections of a pure memory dump (`p_offset == p_vaddr`). Leave it off for a hybrid dump that kept the on-disk layout. |
| `--codm` | Call of Duty Mobile layout. |
| `--decompile` | il2cpp-dumper-rs v8 C#-style body recovery. Slow on large games; restrict to the types you need. |
| `--split` | One `.cs` file per type, easier to grep and diff across versions. |

The wrapper writes `il2cpp_tools.config.json` with `requireAnyKey: false`, `generateStruct: true`, and `generateDummyDll: true`. The upstream defaults are a press-any-key prompt and no `il2cpp.h` or DummyDll. It runs with stdin closed and a timeout, and writes the full log next to the output.

### 4.3 What each engine is better at

| | il2cpp-dumper-rs | Il2CppInspectorRedux |
|---|---|---|
| Speed | Fastest, multi-core | Slower |
| Inputs | Binary + metadata, ELF/PE/Mach-O/NSO/WASM, memory dumps with `--dump-base` | Same, plus APK/XAPK/AAB/IPA directly, GameGuardian maps |
| Newest metadata | v16–v39, 104–108 | 29–39, 104–110 |
| Protection | Auto XOR detection, CODM | Loader plugins for specific titles, string-encryption styles, packed PE |
| Output for IDA | `script.json` + `il2cpp.h` (import with `ida/il2cpp_import.py`) | `il2cpp.py` that runs without prompts; also Ghidra and Binary Ninja |
| Extras | Inline disassembly annotations, C#-style bodies, `DummyDll` | C++ scaffolding, Visual Studio solutions, `DummyDll` |

When the engines disagree on a method address, trust neither until you open that address in the disassembler and see a function prologue there.

### 4.4 Load into IDA through ida-mcp

Inspector: `open_database(<binary>)`, then pass the generated `il2cpp.py` text to `execute_python`.

il2cpp-dumper-rs: the upstream `ida_with_struct_py3.py` opens two file dialogs and calls an API IDA 9 removed, so it hangs or crashes in a headless worker. Use the wrapper:

```python
IL2CPP_SCRIPT_JSON = "/abs/work/dump/Dump0/script.json"
IL2CPP_HEADER = "/abs/work/dump/Dump0/il2cpp.h"
# then send the contents of ida/il2cpp_import.py in the same or the next execute_python call
```

The wrapper was verified on IDA 9.4 `idat`: method names and struct-typed prototypes were applied. Large games take minutes. Raise the `execute_python` timeout instead of splitting the import. Call `save_database()` afterwards.

### 4.5 Header-only permutation

Use this before a runtime dump when the version word is plausible, the magic is `AF 1B B1 FA` or a one-byte variant such as `AF 1B B1 EA`, names such as `Assembly-CSharp` are already plaintext, and a stock parse puts every section past EOF. il2cpp-dumper-rs then says the encryption is unrecognized. That sentence does not mean the whole file is encrypted.

Do not stop after writing the canonical magic over the variant. The shuffled offsets stay wrong.

The transform lives in the native hook or loader, not as a `0xFAB11BAF` immediate inside `libil2cpp.so`. Find the function that branches on both magics. The table beside it is fixed-width. One confirmed layout is 12-byte records: `uint8 dst`, `uint8 src`, padding, `int32 delta`, `uint32 xor`, applied as `out[dst] = (in[src] - delta) ^ xor`. The decoder then forces `0xFAB11BAF` and keeps the on-disk version. A v29 header is 64 little-endian words, 256 bytes: magic, version, then 31 offset/size pairs. Another version has another width. Use that width. Do not assume `0x110`.

Accept the candidate only when every non-empty pair satisfies `offset + size <= file_size`, several pairs are non-empty, and a name already found in the file falls inside the decoded string section. Splice that header onto the original body. The body was not encrypted. Dump the spliced file with the matching binary. `CodeRegistration` found, and a type count in the thousands, confirms the pair. A header that passes the range test and still fails registration is a body or binary mismatch.

A heap or scudo copy can match this header at every byte after the version word and still wear `AF 1B B1 EA`. The `r--s` file mapping of `global-metadata.dat` stays obfuscated. Scan both magics over each whole range, not only the first bytes of a mapping. A hit only on the file mapping is the on-disk bytes. An anonymous hit whose section ends sit inside the file is the decoded header.

## 5. Runtime route

Use it when the metadata on disk is encrypted, missing, or downloaded at runtime, or when the runtime image is packed. Both runtime tools read the structures IL2CPP itself has already decrypted and registered.

Prerequisites: a rooted device or emulator (see [../05-environment/host-and-lab-setup.md](../05-environment/host-and-lab-setup.md)). Check with `doctor`; it reports root, Magisk Zygisk, KernelSU, and Zygisk Next.

### 5.1 frida-il2cpp-bridge

```bash
uv run scripts/il2cpp_tools.py bridge-dump com.example.game -o work/runtime --spawn
```

- The helper runs the package's own `dump` CLI under uv with `frida==<host frida version>`. The `frida-server` on the device must be the same version, and a mismatch shows up as an attach error.
- `--spawn` hooks before the game's own anti-tamper starts. Without it the helper attaches to the running process, which is better when the game crashes on spawn.
- `--unity-version 2022.3.21f1` when version detection fails. `--module-name libfoo.so` when the runtime image was renamed (take the name from `extract`'s strongest candidate, or `Process.enumerateModules()` filtered by `il2cpp_` exports).
- Output is C#-like declarations with RVAs. It does not need `global-metadata.dat`.

For tracing and live hooks, scaffold an agent project:

```bash
uv run scripts/il2cpp_tools.py bridge-init work/agent --package com.example.game
frida -U -f com.example.game -l work/agent/_agent.js
```

`agent.ts` has working examples of tracing a class, tracing methods by name across `Assembly-CSharp`, replacing one method's implementation for a lab hypothesis, and mapping an RVA from IDA back to its C# method with `Il2Cpp.Method.tryFromRelativeVirtualAddress`. Rebuild after edits with `npm --prefix work/agent run build`. Everything goes inside `Il2Cpp.perform(() => { ... })`, which waits for the runtime to initialize.

### 5.2 Zygisk-Il2CppDumper

Use it when the game detects Frida (ptrace checks, `frida-server` port scans, `gum-js-loop` thread names). The module loads inside the game process through Zygisk before the game's code runs, and writes `dump.cs` from the live runtime.

```bash
uv run scripts/il2cpp_tools.py zygisk-build com.example.game        # sets GamePackageName, gradle :module:assembleRelease
# install the printed zip with Magisk or ksud, reboot, launch the game once
uv run scripts/il2cpp_tools.py zygisk-pull com.example.game -o work/zygisk
```

- Magisk: enable Zygisk in settings. KernelSU has no Zygisk of its own; install the Zygisk Next module first.
- The build needs JDK 17 and the NDK version pinned in `module/build.gradle`. If the local build fails, fork the repo and run its **Build** GitHub Action with the package name.
- The module dumps once per launch into `/data/data/<package>/files/dump.cs`. `adb logcat -s Perfare` shows progress. Remove the module after the dump; it stays active for that package.
- The dump has types and RVAs, not `script.json`. To symbolize IDA, also pull the decrypted runtime image and metadata from memory and run the static route on them with `--dump-base`.

### 5.3 Pull the decrypted inputs from memory

To feed a static engine, take the runtime image and metadata from a live process instead of guessing the decryption:

Finding the runtime image by counting `il2cpp_*` exports fails when the protected image exports none. Read `/proc/<pid>/maps` for a path ending in `libil2cpp.so` or `global-metadata.dat`.

If the thread's wchan is `do_freezer_trap`, or `cgroup.freeze` for that pid is `1`, the app is cached and frozen. Thaw it (`echo 0` into that `cgroup.freeze`) before attaching. A frozen target closes the Frida session and the scan never runs. Frida 17's Python `Device.attach` takes a process name or a pid, not an Android package id. Take the pid from `enumerate_applications()`.

```javascript
// frida -U -p <pid> -l pull_il2cpp.js   (frida 17)
// Scan both magics. A decoded header may still be AF 1B B1 EA.
const patterns = ["af 1b b1 fa", "af 1b b1 ea"];
for (const pattern of patterns) {
  for (const range of Process.enumerateRanges("r--")) {
    let hits;
    try { hits = Memory.scanSync(range.base, range.size, pattern); }
    catch (error) { continue; }
    for (const hit of hits) {
      const version = hit.address.add(4).readU32();
      console.log(`${pattern} ${hit.address} version=${version} prot=${range.protection} file=${range.file ? range.file.path : ""}`);
    }
  }
}
```

Read 256 bytes at a v29 hit (the header width for that version otherwise). A variant-magic hit whose section ends fall inside the file is the decoded header. The `r--s` mapping of `global-metadata.dat` is the on-disk bytes. A candidate whose version is not 16–39 or 104–110 is a false hit. When only the header was transformed, splice the normalized header onto the on-disk body and use the static route. Dump the whole runtime image only when registration still fails. Then `dump <runtime.dump> <metadata.dump> --dump-base <base>`.

## 6. Runtime layout facts

- **Object**: `Il2CppObject { Il2CppClass* klass; void* monitor; }`, then instance fields at `+0x10` (64-bit). The field offsets in `dump.cs` already include this header.
- **Static fields**: `klass->static_fields`, the offsets listed in `dump.cs` under `static`.
- **Calling convention**: every compiled method takes a trailing hidden `const MethodInfo* method`. `void TakeDamage(int)` becomes `void PlayerController_TakeDamage(PlayerController* this, int32_t damage, const MethodInfo* method)`. On ARM64 that is `X0` = this, `W1` = damage, `X2` = method. Static methods have no `this`. Frida `NativeFunction` and hook signatures must include the trailing argument. A `br xn` tail that leaves `X0`–`X2` untouched still forwards `this`, the user argument, and `MethodInfo*`. Hex-Rays showing `return orig()` with an empty parameter list is not evidence those arguments were dropped. Check the registers at the branch.
- **Small struct return (ARM64)**: a value type that fits in 16 bytes comes back in `X0`/`X1`, not as a hidden pointer. The first field occupies the low bits. A hook that wants a `ushort` id from that return masks with `#0xffff`. The C# signature still says the method returns the struct.
- **v29 header**: 256 bytes (64 little-endian words, 31 offset/size pairs). The repair procedure is [§4.5](#45-header-only-permutation).
- **Unresolved field offset**: `0x69696969`, and the nearby `0x696969xx` values, in `dump.cs` mean the dumper did not compute the offset. They are not a layout. Take that field from a runtime read or from the metadata field table.
- **Strings**: `Il2CppString { Il2CppObject obj; int32_t length; uint16_t chars[]; }`. UTF-16LE at `+0x14`.
- **Arrays**: `Il2CppArray { Il2CppObject obj; void* bounds; size_t max_length; T items[]; }`. Items begin at `+0x20` on 64-bit.
- **Generic sharing**: reference-type generic instantiations share one native body (`__Canon`). An RVA in `dump.cs` may serve many `List<T>` variants. Value-type instantiations get their own bodies.

Metadata versions in practice: 24.x for Unity 2018–2020.1, 27.x for 2020.2–2021.1, 29 for 2021.2–2022.1, 31 for 2022.2–2023.1, and 35–39 and 104+ for Unity 6 releases. Both engines read the version from the file; this table is for spotting a tampered header, not for forcing a version.

## 7. Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Dumper waits forever | `requireAnyKey`, dump-base prompt, or `ask_file` in the IDA script | Use the helper and `ida/il2cpp_import.py`; they close stdin and answer dialogs |
| `Invalid metadata file ... AF 1B B1 FA`, or sections past EOF after only the magic byte was patched | Header words are permuted; the body may already be plaintext. Built-in XOR detectors do not cover that | [§4.5](#45-header-only-permutation). Runtime only after the range test fails |
| Memory scan finds no `AF 1B B1 FA` | The decoded copy kept the variant magic, or the scan looked only at the start of each range | Scan `AF 1B B1 EA` too, over the whole range ([§5.3](#53-pull-the-decrypted-inputs-from-memory)) |
| `dump.cs` field offset is `0x69696969` | Dumper sentinel. The offset is unknown | Do not use it as the field's offset |
| Frida attach returns "server closed" and the thread sits in `do_freezer_trap` | The cached app is frozen | Thaw `cgroup.freeze`, then attach by pid ([§5.3](#53-pull-the-decrypted-inputs-from-memory)) |
| `CodeRegistration not found` / every RVA is `-1` | Wrong binary (an importer, not the runtime), packed image, or metadata/registration version mismatch | Check `extract`'s `il2cpp_exports`; try `--force-version`; use a memory dump with `--dump-base` |
| `dump.cs` has types but methods have no RVA | Metadata from one build, binary from another | Re-extract both from the same package; compare `binary_sha256` and the metadata sha256 to the package |
| Hundreds of `UnknownType` / wrong field types | Il2CppType encryption (CODM-style) or wrong version | `--codm`, or `--engine inspector` |
| `bridge-dump` hangs at "waiting for IL2CPP module" | Runtime image renamed or loaded late | `--module-name <lib>`; attach after the first scene instead of `--spawn` |
| Game exits when Frida attaches | Anti-Frida | Zygisk route, or a renamed/stealth frida-server build |
| Zygisk module never writes `dump.cs` | Zygisk not active (KernelSU without Zygisk Next), wrong package name, or the game is a separate `:process` | `doctor`; check `adb logcat -s Perfare`; the package name must be exact |
| IDA import crashes with `get_inf_structure` | Upstream script written for IDA 8 | `ida/il2cpp_import.py` shims it |

## 8. Boundaries
- Do not reverse the runtime image without metadata symbols. Get a dump first by any route above.
- Focus on `Assembly-CSharp` and the game's own assemblies. Skip `UnityEngine.*`, `mscorlib`, and `System.*` unless the behavior is there.
- `dump.cs` and DummyDll have no method bodies (DummyDll bodies are stubs). Logic lives at the RVA in the native image. il2cpp-dumper-rs `--decompile` output is a reading aid; confirm it against the disassembly before you rely on it.
- Runtime routes execute the game. Use them only on a lab device and only when the task allows execution. Do not log into real player accounts or touch live multiplayer services.
