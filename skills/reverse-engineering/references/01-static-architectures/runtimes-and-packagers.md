# Runtimes, Engines, And Installers

## When To Open
Open this file when the executable is a generic runtime and the program you want is a container beside it or inside it. Disassembling the engine wastes the session. Confirm with magic and layout. A string that names a framework is a lead. If the string and the layout disagree, trust the layout.

## Where The Logic Is

| What you see | The program is | Do not start in |
|---|---|---|
| `libflutter.so` plus `libapp.so` or `App.framework/App` | Dart AOT snapshot | The Flutter engine |
| `index.android.bundle`, `main.jsbundle`, Hermes `c6 1f bc 03` | The JS or Hermes bundle | The React Native shell |
| `Assembly-CSharp.dll` | Unity Mono | `UnityPlayer` |
| `GameAssembly.dll` or `libil2cpp.so` plus `global-metadata.dat` | Unity IL2CPP | The player binary |
| A `.pck` embedded or beside a Godot binary | GDScript in the pack | The Godot executable |
| Unreal `.pak` or `.utoc`, reflection strings in the exe | Native game code plus assets | The asset container, for code |
| `_MEIPASS`, a PyInstaller bootloader, `_internal/` | Embedded `.pyc` | The bootloader, until the archive is out |
| Nuitka, no `.pyc` | Native code. Module names still leak in strings | A Python decompiler |
| `library.zip` of `.pyc` next to the exe | py2exe or cx_Freeze | The launcher |
| `NODE_SEA_BLOB`, a pkg trailer, `.jsc` / bytenode | Embedded JS, or V8 bytecode if compiled | The Node launcher |
| AutoIt interpreter plus a script resource | The script resource | The interpreter |
| `XALZ` or an assemblies blob in an APK | Xamarin or MAUI | The Java shell, after the assemblies are out |
| GraalVM `native-image` | Native code. Class names survive in strings | A JVM decompiler |
| Delphi or C++Builder RTTI and `.dfm` | Form and event names in the resources | A raw C reading of the VCL |

Flutter, React Native, Unity IL2CPP, Go, Rust, and browser JS already have architecture files. Use this table only to choose which one.

## Installers
Do not run an installer to see what it installs. Unpack into an empty directory, then triage that directory.

| Container | Extract |
|---|---|
| NSIS | `7z x` |
| Inno Setup | `innoextract` |
| MSI | `msiextract` or `7z x` |
| MSIX, APPX, Squirrel `.nupkg` | ZIP |
| `.deb` | `ar x`, then `data.tar.*` |
| `.rpm` | `rpm2cpio` or `7z x` |
| AppImage | SquashFS at the offset `binwalk` reports, then `unsquashfs -o`. Do not use `--appimage-extract` on an untrusted file. It runs the binary. |
| `.dmg` / `.pkg` | `7z x`, or `pkgutil --expand-full` / `xar` |

Read the NSIS or Inno script. It names what is registered and launched. Then triage the payload, not the stub.
