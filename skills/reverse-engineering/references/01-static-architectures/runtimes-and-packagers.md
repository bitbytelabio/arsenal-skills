# Runtimes, Engines, And Installers

## When To Open
Open this file when the executable is a generic runtime and the program you want is a container beside it or inside it. Disassembling the engine wastes the session. Confirm with magic and layout. A string that names a framework is a lead. If the string and the layout disagree, trust the layout.

Every extraction below reads the file as data. Where a tool runs the target, the row says so. Extract into a new empty directory, and run Python tools with `-I` so nothing in the extracted tree gets imported.

## Where The Logic Is

| What you see | The program is | Do not start in |
|---|---|---|
| `libflutter.so` plus `libapp.so` or `App.framework/App` | Dart AOT snapshot | The Flutter engine |
| `index.android.bundle`, `main.jsbundle`, Hermes `c6 1f bc 03` | The JS or Hermes bundle | The React Native shell |
| `Assembly-CSharp.dll` | Unity Mono | `UnityPlayer` |
| `GameAssembly.dll` or `libil2cpp.so` plus `global-metadata.dat` | Unity IL2CPP | The player binary |
| `GDPC` at the start of a `.pck`, or in the last bytes of a Godot exe | GDScript in the pack | The Godot executable |
| Unreal `.pak` (footer magic `0x5A6F12E1`) or `.utoc`/`.ucas`, reflection strings in the exe | Native game code in the exe, Blueprints and assets in the pak | The asset container, for code |
| `MEI\x0c\x0b\x0a\x0b\x0e` cookie, `_MEIPASS`, `pyi-` strings, `_internal/` | PyInstaller: embedded `.pyc` | The bootloader |
| `nuitka`, `__compiled__`, `onefile_` temp paths, no `.pyc` | Nuitka: Python compiled to C | A Python decompiler |
| `library.zip` of `.pyc` next to the exe | py2exe or cx_Freeze | The launcher |
| `NODE_SEA_BLOB` + `NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:1` | Node single executable app | The Node runtime |
| `/snapshot/` paths, `PAYLOAD_POSITION` / `PRELUDE_POSITION` | vercel `pkg` | The Node runtime |
| `resources/app.asar` | Electron app JS | Electron / Chromium |
| `.jsc` files, `bytenode` | V8 bytecode (version-locked) | A JS beautifier |
| AutoIt interpreter plus `AU3!EA06` in a resource | The compiled AutoIt script | The interpreter |
| `XALZ` headers or `assemblies.blob` (`XABA`) in an APK | Xamarin / .NET MAUI assemblies | The Java shell |
| .NET single-file bundle (`DOTNET_BUNDLE` style host, managed DLLs appended) | Managed assemblies | The apphost |
| GraalVM `native-image` (`com.oracle.svm`, `SubstrateVM` strings) | Native code. Class and method names survive in strings. | A JVM decompiler |
| Delphi or C++Builder RTTI, `TForm`, `.dfm` in `RCDATA` | Form and event handler names in the resources | A raw C reading of the VCL |

Flutter, React Native, Unity IL2CPP, .NET/JVM, Go, Rust, and browser JS have architecture files. Use this table only to choose which one: [flutter-dart.md](flutter-dart.md), [react-native-hermes.md](react-native-hermes.md), [unity-il2cpp.md](unity-il2cpp.md), [managed-dotnet-jvm.md](managed-dotnet-jvm.md), [native-golang.md](native-golang.md), [native-rust.md](native-rust.md), [browser-js-wasm.md](browser-js-wasm.md).

---

## Python

### PyInstaller
The archive (CArchive) is appended to the bootloader. Its cookie sits at the end of the archive, which is not always the end of the file: Mach-O builds have the code signature after it, and signed PEs have the certificate after it.

Cookie (big-endian, PyInstaller 2.1+, 88 bytes): `magic "MEI\x0c\x0b\x0a\x0b\x0e"` (8), package length (4), TOC offset (4), TOC length (4), Python version (4, e.g. `312` = 3.12), Python library name (64, e.g. `libpython3.12.dylib`).

```bash
mkdir -p "$OUT" && cd "$OUT"
uv tool run --from pyinstxtractor-ng pyinstxtractor-ng -i "$BIN"   # archive info only
uv tool run --from pyinstxtractor-ng pyinstxtractor-ng "$BIN"      # writes ./<name>_extracted/ and <name>_extracted/PYZ.pyz_extracted/
```
Verified with PyInstaller 6.22 / Python 3.12 on macOS arm64: it listed `app.pyc` as an entry point, extracted 102 PYZ modules, and wrote pyc files with a valid 3.12 header. pyinstxtractor-ng does not need the matching Python version, and it decrypts PyInstaller < 6 encrypted PYZ archives by reading the key from `pyimod00_crypto_key`. The original `pyinstxtractor.py` must run under the same Python minor version to unpack the PYZ.

The entry script is the TOC entry that is not `pyiboot*`/`pyi_rth_*`/`pyimod*`. Runtime hooks (`pyi_rth_*`) are PyInstaller's, not the author's.

### py2exe / cx_Freeze
`library.zip` (or `lib/library.zip`) is a plain ZIP of `.pyc`. cx_Freeze puts the main script in it as `__main__.pyc` or `<name>__main__.pyc`. py2exe stores the main script in the `PYTHONSCRIPT` resource as a marshalled code-object list.

### Nuitka
Nuitka compiles each module to C. There is no bytecode to decompile. What survives: module and function names in strings, constant blobs, and the Python version of `libpython`. Analyze it as a native binary and use the module names to orient.

Onefile builds append a payload with magic `KAX` (uncompressed) or `KAY` (zstd). The payload size is a u64 in the last 8 bytes on ELF, or at the end of the `RCDATA` resource on PE. `nuitka-extractor "$BIN"` unpacks it. It recovers DLLs, shared libraries, and data files, not `.pyc`. Strip the Authenticode signature from a signed PE first.

### Decompile `.pyc`
Read the magic first. The header is 16 bytes since 3.7 (magic, flags, mtime + size or a hash), 12 bytes for 3.3–3.6, 8 bytes for 2.x.

| Python | Magic (hex, first 4 bytes) | Best tools |
|---|---|---|
| 2.7 | `03f30d0a` | uncompyle6 |
| 3.7 | `420d0d0a` | decompyle3, uncompyle6 |
| 3.8 | `550d0d0a` | decompyle3, uncompyle6 |
| 3.9 | `610d0d0a` | pycdc (partial), PyLingual |
| 3.10 | `6f0d0d0a` | pycdc (partial), PyLingual |
| 3.11 | `a70d0d0a` | pycdc (partial), PyLingual |
| 3.12 | `cb0d0d0a` | pycdc (partial), PyLingual |
| 3.13 | `f30d0d0a` | pycdc (partial), PyLingual |
| 3.14 | `2b0e0d0a` | Disassembly; check PyLingual and pycdc release notes |

Magics 3.8–3.14 were read from `importlib.util.MAGIC_NUMBER` of each CPython release.

```bash
uv tool run --from decompyle3 decompyle3 mod.pyc          # 3.7-3.8
uv tool run --from uncompyle6 uncompyle6 mod.pyc          # 1.0-3.8
./pycdc mod.pyc ; ./pycdas mod.pyc                         # zrax/pycdc, build with cmake + make
pylingual -o out/ mod.pyc                                  # git clone syssec-utd/pylingual; uv tool install ./pylingual
```
pycdc output for 3.9+ often has gaps (`# WARNING: Decompyle incomplete`). PyLingual's website uploads the file to a third party. Use the local CLI for confidential samples.

When every decompiler fails, disassemble with the matching interpreter. `marshal.loads` builds the code object without running it:
```bash
uv run --no-project --python 3.12 python -I -c "import dis, marshal, sys; dis.dis(marshal.loads(open(sys.argv[1], 'rb').read()[16:]))" mod.pyc
```
Verified on the PyInstaller test build. String constants (keys, URLs) are in `LOAD_CONST` operands.

Obfuscators: PyArmor (`pyarmor_runtime`, `__pyarmor__`, `_pytransform`) encrypts code objects and decrypts them per function at runtime. Static decompilation gives stubs. Recovery is a lab task (dump decrypted code objects from the running interpreter). Opcode-remapped interpreters (custom `libpython`) need the opcode map recovered from the bundled library first.

---

## JavaScript Runtimes

### Node Single Executable Application
`postject` injects the blob as a PE resource named `NODE_SEA_BLOB`, a Mach-O section `NODE_SEA_BLOB` in segment `NODE_SEA`, or an ELF note named `NODE_SEA_BLOB`. The fuse string `NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2` ends in `:1` when a blob is present. Node 25.5+ can also build SEAs with `node --build-sea`.

The blob starts with the SEA magic `0x0143DA20` (bytes `20 da 43 01`), then a `uint32` flags word, then length-prefixed strings: the code path, then the main script (or snapshot), then the optional code cache, assets, and exec argv. The exact field list depends on the Node version (`src/node_sea.cc`), so carve from the magic and read the strings:
```bash
python3 -I -c "
import sys
d = open(sys.argv[1], 'rb').read(); i = d.find(bytes.fromhex('20da4301'))
print('SEA blob at file offset', hex(i)) if i >= 0 else sys.exit('no SEA magic')
open(sys.argv[2], 'wb').write(d[i:])" "$BIN" sea.blob
strings -n 8 sea.blob | head -40
```
The main script is stored as source text unless the config used `useSnapshot` (V8 startup snapshot). `useCodeCache` adds a V8 code cache beside the source. Assets from the `assets` map follow as key/content pairs. If the magic search hits something else, `pkg-unpacker --format sea` parses the container.

### pkg, nexe, bun, caxa
```bash
bunx github:LockBlock-dev/pkg-unpacker -i "$BIN" -o "$OUT"      # --format pkg|sea|bun|nexe|caxa ; never pass --run (it executes the entrypoint)
```
pkg stores a virtual filesystem under `/snapshot/`. When built without `--no-bytecode`, scripts are V8 bytecode and the source is gone.

### V8 Bytecode (`.jsc`, bytenode, pkg bytecode)
V8 bytecode is tied to the exact V8 version. Read the version from the embedding Node (`strings "$BIN" | grep -m1 -E '^v?[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'` near `node.js`, or the `process.versions` table). View8: `python view8.py -i in.jsc -o out.js --path <disassembler>`. It ships disassemblers for V8 9.4 (Node 16), 10.2 (Node 18), and 11.3 (Node 20). Other versions need a matching patched `d8`.

### Electron
```bash
npx @electron/asar list "$APP/resources/app.asar"
npx @electron/asar extract "$APP/resources/app.asar" "$OUT"
npx @electron/fuses read --app "$APP"              # RunAsNode, EnableEmbeddedAsarIntegrityValidation, OnlyLoadAppFromAsar, ...
```
Verified with `@electron/asar` on a test archive. Files marked `unpacked` live in `app.asar.unpacked/` beside the archive. Native `.node` modules there are ordinary shared libraries.

ASAR layout without Node: `uint32 4`, `uint32 header_size`, `uint32 pickle_size`, `uint32 json_len`, JSON index, then file data starting at `8 + header_size`. Each file's `offset` (a string) is relative to that start.
```bash
python3 -I -c "
import json, struct, sys
f = open(sys.argv[1], 'rb'); _, hsize, _, jlen = struct.unpack('<4I', f.read(16)); idx = json.loads(f.read(jlen))
def walk(n, p=''):
    for k, v in n.get('files', {}).items():
        if 'files' in v: walk(v, p + '/' + k)
        else: print(p + '/' + k, v.get('size'), 'unpacked' if v.get('unpacked') else 'off=%d' % (8 + hsize + int(v.get('offset', 0))))
walk(idx)" app.asar
```
Then read the app as browser/Node JS ([browser-js-wasm.md](browser-js-wasm.md)). Start at `package.json` `main`, then the preload scripts and `ipcMain` handlers.

---

## Game Engines

### Godot
`.pck` header magic `GDPC` (`0x43504447`). An embedded pack sits at the end of the exe with `GDPC` in its last 4 bytes. Godot 3/4 can encrypt the pack or scripts with AES-256 (CFB). The 32-byte key is compiled into the export template exe.

```bash
gdre_tools --headless --list-files="$GAME"                       # .pck, .exe, .apk, or directory
gdre_tools --headless --recover="$GAME" --output="$OUT"           # files + decompiled GDScript (.gdc bytecode -> .gd)
gdre_tools --headless --recover="$GAME" --output="$OUT" --key="$GODOT_KEY"          # 64 hex chars
```
Without the key, find it in the exe: a 32-byte high-entropy constant referenced near the pack-loading code (`script_encryption_key` symbol in debug templates).

### Unreal Engine
Gameplay C++ is in the exe (or `<Game>-Win64-Shipping.exe`). Reflection strings (`/Script/<Module>.<Class>`) name classes and properties. Blueprint logic and assets are in `.pak` or IoStore `.utoc`/`.ucas`.

```bash
repak info "$PAK"
repak --aes-key "$AES_KEY" unpack "$PAK"                # 0x-prefixed hex or base64
retoc --aes-key "$AES_KEY" unpack "$PAKS_DIR" "$OUT"     # IoStore; confirm argument order with `retoc unpack --help`. `retoc to-legacy <Paks> legacy_P.pak` converts to .pak
```
The AES key is a 32-byte constant in the shipping exe. AESDumpster scans for it (UE 4.17–5.6). FModel (GUI) browses paks, previews assets, and shows Blueprint bytecode.

### Unity
Mono builds: `<Game>_Data/Managed/Assembly-CSharp.dll` → [managed-dotnet-jvm.md](managed-dotnet-jvm.md). IL2CPP → [unity-il2cpp.md](unity-il2cpp.md).

---

## Other Runtimes

| Runtime | Extract | Notes |
|---|---|---|
| AutoIt | `uv tool run --from autoit-ripper autoit-ripper "$BIN" "$OUT"` (`--ea EA05\|EA06\|guess`) | Script resource begins with a 16-byte GUID `A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D` then `AU3!EA06` (current) or `AU3!EA05` (older) |
| .NET single-file | `dotnet tool install -g sfextract`; `sfextract "$BIN" -o "$OUT"` (no `-o` lists) | Then [managed-dotnet-jvm.md](managed-dotnet-jvm.md) |
| Xamarin / MAUI | `apktool d app.apk`; `pyxamstore unpack -d app/unknown/assemblies/` | `XALZ` = `"XALZ"`, u32 descriptor index, u32 uncompressed length, LZ4 block. `assemblies.blob` store magic `XABA`. pyxamstore's README flags its Python 3 support as incomplete. |
| Delphi / C++Builder | IDR (Interactive Delphi Reconstructor) for VCL; `RCDATA` `.dfm` forms name every event handler | Event handler names map buttons to code. |
| GraalVM native-image | Native analysis. Grep class/method names from strings and the reflection config. | No bytecode exists. |

---

## Installers
Do not run an installer to see what it installs. Unpack into an empty directory, then triage that directory.

| Container | Detect | Extract | Install logic |
|---|---|---|---|
| NSIS | `Nullsoft`, `NullsoftInst` signature in the overlay | `7z x -o"$OUT" "$BIN"` | Old 7-Zip builds also wrote `[NSIS].nsi`. Current builds usually do not. Without it, read plugin DLLs (`$PLUGINSDIR`) and strings. |
| Inno Setup | `Inno Setup Setup Data`, `rDlPtS` | `innoextract -i "$BIN"` (info), `-l` (list), `innoextract -e -d "$OUT" "$BIN"`, `-P` password | innoextract does not output the script. `innounp -x` (Windows) reconstructs the `.iss` setup script. Pascal `[Code]` is compiled (ROPS bytecode). |
| MSI | OLE2 magic | `msiextract -C "$OUT" "$F"`, `lessmsi x "$F" "$OUT"` (Windows), `7z x` | `msiinfo tables "$F"`; `msiinfo export "$F" CustomAction` and `InstallExecuteSequence`. Custom actions run DLLs, scripts, or EXEs embedded in the `Binary` table: `msiinfo streams`, `msiinfo extract "$F" Binary.<name>`. |
| InstallShield | `data1.cab`, `ISSetupStream` | `unshield -d "$OUT" x data1.cab` | `setup.inx` holds InstallScript bytecode |
| MSIX / APPX / Squirrel `.nupkg` | ZIP | `unzip` | `AppxManifest.xml`; Squirrel `Update.exe` + `lib/net45/` |
| WiX Burn bundle | `.wixburn` section | `dark.exe -x` (WiX 3) or `7z x` on attached containers | Chained packages |
| `.deb` | `!<arch>` | `ar x`, then `tar -xf data.tar.*` and `control.tar.*` | `postinst`, `preinst` in `control.tar.*` |
| `.rpm` | `ed ab ee db` | `rpm2cpio "$F" \| cpio -idmv` or `7z x` | `rpm -qp --scripts "$F"` |
| AppImage | ELF with `AI\x02` at offset 8 | `unsquashfs -o $OFF -d "$OUT" "$F"` (squashfs-tools 4.4+), or `dwarfsextract -i "$F" -o "$OUT"` for DwarFS images | `AppRun` and the `.desktop` file. Do not use `--appimage-extract` or `--appimage-offset`: they run the AppImage runtime. |
| `.dmg` / `.pkg` | `koly` trailer / `xar!` | `7z x`; `pkgutil --expand-full "$F" "$OUT"` (macOS) or `xar -xf` | `Scripts/preinstall`, `postinstall` |

AppImage filesystem offset = `max(e_shoff + e_shentsize*e_shnum, end of the last section with file data)`, the same rule the type-2 runtime uses:
```python
# elf_end.py. python3 -I elf_end.py "$APPIMAGE"
import struct, sys
d = open(sys.argv[1], "rb").read()
assert d[:4] == b"\x7fELF", "not ELF"
is64, end = d[4] == 2, "<" if d[5] == 1 else ">"
if is64:
    shoff, = struct.unpack_from(end + "Q", d, 0x28); shentsize, shnum = struct.unpack_from(end + "HH", d, 0x3A)
else:
    shoff, = struct.unpack_from(end + "I", d, 0x20); shentsize, shnum = struct.unpack_from(end + "HH", d, 0x2E)
last = shoff + shentsize * shnum
for i in range(shnum):
    o = shoff + i * shentsize
    stype, = struct.unpack_from(end + "I", d, o + 4)
    off, size = struct.unpack_from(end + ("QQ" if is64 else "II"), d, o + (0x18 if is64 else 0x10))
    if stype != 8:                                   # SHT_NOBITS takes no file space
        last = max(last, off + size)
print(last, d[last:last + 6])                        # expect b'hsqs' (SquashFS) or b'DWARFS'
```
Tested on a plain ELF: the result equals the file size, as it should with nothing appended.

Read the NSIS, Inno, or MSI install logic. It names what is registered, scheduled, and launched. Then triage the payload, not the stub.

---

## Verify
- The extracted entry point (PyInstaller entry `.pyc`, `package.json` `main`, SEA main script, `AppRun`) is the file the launcher would run, per the container's own metadata.
- Decompiled Python: the bytecode version from the magic matches the decompiler's supported range, and the output has no `incomplete` markers in the functions you report.
- Unreal/Godot: a decrypted pack lists sensible paths. A wrong key gives garbage names, not an error.
- Installers: every custom action or script you report appears in the extracted tables or files.

## Boundaries And Anti-Patterns
- Do not reverse the runtime engine when the program is in a container.
- Do not run the installer, AppImage, or packed app to extract it. Use the static extractors above.
- Do not use online decompilers for confidential samples.
- Do not report "no source" for pkg/bytenode until you checked whether the V8 version has a disassembler.
- Do not import or execute extracted `.py`/`.js` from the output directory on the host.
