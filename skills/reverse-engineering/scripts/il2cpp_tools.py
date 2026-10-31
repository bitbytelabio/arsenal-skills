#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["lief>=0.17"]
# ///

"""Unity IL2CPP helper: locate inputs, dump statically, dump at runtime.

Wraps four upstream tools so an agent can run them without interactive prompts:

  il2cpp-dumper-rs        static dump of binary + global-metadata.dat (or a memory dump)
  Il2CppInspectorRedux    second static engine: newest metadata versions, packaged
                          inputs (APK/XAPK/AAB/IPA), IDA/Ghidra/Binary Ninja scripts
  frida-il2cpp-bridge     runtime dump/trace through Frida, no metadata file needed
  Zygisk-Il2CppDumper     runtime dump from inside the game process (Magisk/KernelSU + Zygisk)

Subcommands:
  doctor          report which tools and devices are available
  install-dumper  cargo install il2cpp-dumper-rs from git (crates.io lags behind)
  install-inspector  download the Il2CppInspectorRedux CLI release (needs .NET 10 runtime)
  extract         pull the IL2CPP binary and global-metadata.dat out of an APK/XAPK/APKS/IPA/dir
  dump            static dump with --engine dumper (default), inspector, or both
  bridge-init     scaffold a frida-il2cpp-bridge agent project (TypeScript, frida-compile)
  bridge-dump     run the frida-il2cpp-bridge dump CLI against a device app
  zygisk-build    clone Zygisk-Il2CppDumper, set the package name, build the module zip
  zygisk-pull     pull dump.cs written by the Zygisk module from the device

Usage:
  uv run scripts/il2cpp_tools.py doctor
  uv run scripts/il2cpp_tools.py extract game.apk -o work/
  uv run scripts/il2cpp_tools.py dump work/libil2cpp.so work/global-metadata.dat -o work/dump
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import platform
import re
import zipfile
from pathlib import Path
from typing import Any

import lief

DUMPER_GIT = "https://github.com/rodroidmods/il2cpp-dumper-rs"
ZYGISK_GIT = "https://github.com/Perfare/Zygisk-Il2CppDumper"
INSPECTOR_REPO = "LukeFZ/Il2CppInspectorRedux"
BRIDGE_NPM = "frida-il2cpp-bridge"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "re-il2cpp"

METADATA_NAME = "global-metadata.dat"
METADATA_MAGIC = b"\xaf\x1b\xb1\xfa"
# Preferred ABI order for Android when several lib/<abi>/ folders exist.
ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
BINARY_NAMES = ("libil2cpp.so", "GameAssembly.dll", "UnityFramework", "GameAssembly.dylib")

# il2cpp_dumper reads config.json and otherwise prompts at the end
# ("press any key") and leaves struct/DummyDll generation off.
DUMPER_CONFIG: dict[str, Any] = {
    "requireAnyKey": False,
    "generateStruct": True,
    "generateDummyDll": True,
    "dumpMethod": True,
    "dumpField": True,
    "dumpProperty": True,
    "dumpAttribute": True,
    "dumpMethodOffset": True,
    "dumpFieldOffset": True,
    "dumpTypeDefIndex": True,
    "dumpAssemblyName": True,
    "csharpInteractive": False,
    "enhancedIdaMetadata": True,
}


ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def log_tail(text: str, n: int = 15) -> list[str]:
    lines = [ANSI_RE.sub("", ln).rstrip() for ln in text.strip().splitlines()]
    return [ln for ln in lines if ln.strip()][-n:]


def emit(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
        return
    if isinstance(data, dict):
        for k, v in data.items():
            print(f"{k}: {v}")
    else:
        print(data)


def which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    cargo_bin = Path.home() / ".cargo" / "bin" / name
    return str(cargo_bin) if cargo_bin.exists() else None


def run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def metadata_info(path: Path) -> dict[str, Any]:
    """Magic and version only. There is no maintained Python library for the
    IL2CPP metadata format; the full parse is il2cpp_dumper's job."""
    head = path.read_bytes()[:8]
    info: dict[str, Any] = {"path": str(path), "size": path.stat().st_size, "sha256": sha256(path)}
    info["magic_ok"] = head[:4] == METADATA_MAGIC
    info["magic_hex"] = head[:4].hex()
    info["version"] = int.from_bytes(head[4:8], "little") if len(head) == 8 else None
    if not info["magic_ok"]:
        info["hint"] = (
            "Magic is not AF 1B B1 FA: the file is encrypted, XOR-masked, or replaced by a decoy. "
            "Try 'dump' anyway (il2cpp_dumper auto-detects simple XOR), otherwise dump at runtime "
            "with bridge-dump or the Zygisk module."
        )
    elif not (16 <= (info["version"] or 0) <= 39) and (info["version"] or 0) not in (104, 106, 107, 108):
        info["hint"] = "Magic is valid but the version is unusual; the header may be tampered."
    return info


# ---------------------------------------------------------------- doctor
def device_root(adb: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    devs = run([adb, "devices"]).stdout.splitlines()[1:]
    out["devices"] = [d.split()[0] for d in devs if d.strip().endswith("device")]
    if not out["devices"]:
        return out
    idr = run([adb, "shell", "su", "-c", "id"], timeout=15)
    out["root"] = "uid=0" in idr.stdout
    probe = run(
        [adb, "shell", "su", "-c",
         "ls -d /data/adb/modules/zygisksu /data/adb/modules/zygisk_next /data/adb/magisk 2>/dev/null; "
         "magisk --sqlite \"select value from settings where key='zygisk'\" 2>/dev/null; "
         "ls /data/adb/ksud 2>/dev/null"],
        timeout=15,
    ).stdout
    out["magisk"] = "/data/adb/magisk" in probe
    out["magisk_zygisk_enabled"] = "value=1" in probe
    out["kernelsu"] = "/data/adb/ksud" in probe
    out["zygisk_next"] = "zygisksu" in probe or "zygisk_next" in probe
    out["frida_server"] = bool(run([adb, "shell", "su", "-c", "pidof frida-server"], timeout=10).stdout.strip())
    return out


def cmd_doctor(args: argparse.Namespace) -> int:
    report: dict[str, Any] = {
        "il2cpp_dumper": which("il2cpp_dumper"),
        "il2cpp_inspector_redux": str(inspector_bin()) if inspector_bin() else None,
        "dotnet_root": dotnet_root(),
        "cargo": which("cargo"),
        "node": which("node"),
        "npm": which("npm"),
        "frida": which("frida"),
        "adb": which("adb"),
        "git": which("git"),
        "java": which("java"),
    }
    if report["frida"]:
        report["frida_version"] = run([report["frida"], "--version"]).stdout.strip()
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or str(Path.home() / "Library/Android/sdk")
    report["android_sdk"] = sdk if Path(sdk).is_dir() else None
    if report["adb"]:
        report["device"] = device_root(report["adb"])
    routes = []
    if report["il2cpp_dumper"]:
        routes.append("static: dump --engine dumper")
    if report["il2cpp_inspector_redux"] and report["dotnet_root"]:
        routes.append("static: dump --engine inspector")
    if report["frida"] and report["npm"]:
        routes.append("runtime: bridge-dump / bridge-init")
    dev = report.get("device") or {}
    if dev.get("root") and (dev.get("magisk_zygisk_enabled") or dev.get("zygisk_next")):
        routes.append("runtime: zygisk-build + zygisk-pull")
    report["available_routes"] = routes
    if not report["il2cpp_dumper"]:
        report["fix_dumper"] = "uv run scripts/il2cpp_tools.py install-dumper"
    if not report["il2cpp_inspector_redux"]:
        report["fix_inspector"] = "uv run scripts/il2cpp_tools.py install-inspector"
    if dev.get("kernelsu") and not dev.get("zygisk_next"):
        report["fix_zygisk"] = "KernelSU has no built-in Zygisk; install the Zygisk Next module first."
    emit(report, args.json)
    return 0


# ---------------------------------------------------------------- install
def cmd_install_dumper(args: argparse.Namespace) -> int:
    cargo = which("cargo")
    if not cargo:
        emit({"error": "cargo not found; install Rust with rustup first"}, args.json)
        return 1
    cmd = [cargo, "install", "--locked", "--git", DUMPER_GIT, "il2cpp_dumper"]
    if args.rev:
        cmd[4:4] = ["--rev", args.rev]
    print("+ " + " ".join(cmd), file=sys.stderr)
    rc = subprocess.run(cmd).returncode
    emit({"installed": rc == 0, "binary": which("il2cpp_dumper")}, args.json)
    return rc


# ---------------------------------------------------------------- extract
def _pick_binary(names: list[str]) -> str | None:
    for abi in ABI_ORDER:
        for n in names:
            if n.endswith(f"lib/{abi}/libil2cpp.so"):
                return n
    for target in BINARY_NAMES:
        for n in names:
            if n.endswith("/" + target) or n == target:
                if target == "UnityFramework" and "UnityFramework.framework/" not in n:
                    continue
                return n
    return None


# The runtime image exports the il2cpp_* API (hundreds of symbols). libmain.so,
# Lua bridges, and anti-cheat libraries only import a few of them, so count
# exports, not string hits.
MIN_IL2CPP_EXPORTS = 20
lief.logging.disable()


def il2cpp_export_count(data: bytes) -> int:
    binary = lief.parse(list(data))
    if binary is None:
        return 0
    if isinstance(binary, lief.ELF.Binary):
        names = (sym.name for sym in binary.exported_symbols)
    elif isinstance(binary, lief.PE.Binary):
        names = (e.name for e in binary.get_export().entries) if binary.has_exports else iter(())
    else:
        names = (sym.name.lstrip("_") for sym in binary.exported_symbols)
    return sum(1 for n in names if n.startswith("il2cpp_"))


def _find_candidates(zf: zipfile.ZipFile, names: list[str], found: dict[str, Any]) -> None:
    """When the standard names are missing, look for a renamed runtime image
    and a metadata file under another name (protected builds do both)."""
    libs, metas = [], []
    for n in names:
        if "binary" not in found and n.endswith((".so", ".dll")):
            with zf.open(n) as f:
                data = f.read()
            exports = il2cpp_export_count(data)
            if exports:
                libs.append({"member": n, "size": len(data), "il2cpp_exports": exports})
        if "metadata" not in found and not n.endswith((".so", ".dll", ".dex", ".png", ".jpg")):
            with zf.open(n) as f:
                if f.read(4) == METADATA_MAGIC:
                    metas.append(n)
    if libs:
        found["binary_candidates"] = sorted(libs, key=lambda c: -c["il2cpp_exports"])
    if metas:
        found["metadata_candidates"] = metas


def _scan_zip(zf: zipfile.ZipFile, out: Path, found: dict[str, Any], depth: int = 0) -> None:
    names = zf.namelist()
    meta = next((n for n in names if n.endswith("/" + METADATA_NAME) or n == METADATA_NAME), None)
    binary = _pick_binary(names)
    if meta and "metadata" not in found:
        found["metadata"] = str(_extract_member(zf, meta, out))
        found["metadata_member"] = meta
    if binary and "binary" not in found:
        found["binary"] = str(_extract_member(zf, binary, out))
        found["binary_member"] = binary
    found.setdefault("abis", sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2}))
    if "binary" not in found or "metadata" not in found:
        _find_candidates(zf, names, found)
        # Use a single unambiguous candidate directly.
        strong = [c for c in found.get("binary_candidates", []) if c["il2cpp_exports"] >= MIN_IL2CPP_EXPORTS]
        if "binary" not in found and len(strong) == 1:
            member = strong[0]["member"]
            found["binary"] = str(_extract_member(zf, member, out))
            found["binary_member"] = member
        if "metadata" not in found and len(found.get("metadata_candidates", [])) == 1:
            member = found["metadata_candidates"][0]
            found["metadata"] = str(_extract_member(zf, member, out))
            found["metadata_member"] = member
    # Split APK bundles (.xapk/.apks/.apkm) nest the native libs in config.<abi>.apk.
    if depth == 0:
        for n in names:
            if n.endswith(".apk") and ("binary" not in found or "metadata" not in found):
                with zf.open(n) as inner_f, tempfile.TemporaryFile() as tmp:
                    shutil.copyfileobj(inner_f, tmp)
                    tmp.seek(0)
                    try:
                        with zipfile.ZipFile(tmp) as inner:
                            _scan_zip(inner, out, found, depth + 1)
                    except zipfile.BadZipFile:
                        continue


def _extract_member(zf: zipfile.ZipFile, member: str, out: Path) -> Path:
    dest = out / Path(member).name
    with zf.open(member) as src, dest.open("wb") as dst:
        shutil.copyfileobj(src, dst)
    return dest


def cmd_extract(args: argparse.Namespace) -> int:
    src = Path(args.package).expanduser()
    out = Path(args.output).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    found: dict[str, Any] = {"source": str(src)}
    if src.is_dir():
        files = [str(p.relative_to(src)) for p in src.rglob("*") if p.is_file()]
        meta = next((f for f in files if f.endswith(METADATA_NAME)), None)
        binary = _pick_binary(files)
        if meta:
            found["metadata"] = str(shutil.copy2(src / meta, out / METADATA_NAME))
        if binary:
            found["binary"] = str(shutil.copy2(src / binary, out / Path(binary).name))
    elif zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as zf:
            _scan_zip(zf, out, found)
    else:
        emit({"error": f"{src} is not a directory or zip-based package (apk/xapk/apks/ipa)"}, args.json)
        return 1

    if "metadata" in found:
        found["metadata_info"] = metadata_info(Path(found["metadata"]))
    else:
        found["hint_metadata"] = (
            "No global-metadata.dat in the package. It may be renamed, embedded in the binary, or "
            "downloaded at runtime. Search for the magic AF 1B B1 FA, or use a runtime route."
        )
    if "binary" in found:
        found["binary_sha256"] = sha256(Path(found["binary"]))
    else:
        found["hint_binary"] = (
            "No library exports the il2cpp_* API (binary_candidates only import it). Either a Mono build "
            "(assets/bin/Data/Managed/*.dll with IL code), or the runtime image is packed/encrypted "
            "on disk and only exists in memory: use bridge-dump or the Zygisk module."
        )
    emit(found, args.json)
    return 0 if "binary" in found and "metadata" in found else 1


# ---------------------------------------------------------------- Il2CppInspectorRedux
def dotnet_root() -> str | None:
    """The Redux CLI is framework-dependent (.NET 10). Homebrew's dotnet keeps
    the runtime under libexec, which the app host does not search by itself."""
    if os.environ.get("DOTNET_ROOT"):
        return os.environ["DOTNET_ROOT"]
    exe = shutil.which("dotnet")
    if not exe:
        return None
    real = Path(exe).resolve().parent
    for cand in (real, real.parent / "libexec", real.parent):
        if (cand / "shared" / "Microsoft.NETCore.App").is_dir():
            return str(cand)
    return None


def inspector_bin() -> Path | None:
    for name in ("Il2CppInspector.Redux.CLI", "Il2CppInspector.Redux.CLI.exe"):
        found = sorted(CACHE_DIR.glob(f"Il2CppInspectorRedux.CLI-*/{name}"))
        if found:
            # Release zips do not keep the executable bit.
            found[-1].chmod(found[-1].stat().st_mode | 0o755)
            return found[-1]
    return None


def _inspector_rid() -> str:
    os_part = {"darwin": "osx", "linux": "linux", "win32": "win"}.get(sys.platform, "linux")
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    return f"{os_part}-{arch}"


def cmd_install_inspector(args: argparse.Namespace) -> int:
    gh = which("gh")
    rid = _inspector_rid()
    asset = f"Il2CppInspectorRedux.CLI-{rid}.zip"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [gh, "release", "download", "-R", INSPECTOR_REPO, "-p", asset, "-D", str(CACHE_DIR), "--clobber"]
    if args.tag:
        cmd.insert(3, args.tag)
    if not gh:
        emit({"error": "gh not found", "manual": f"download {asset} from https://github.com/{INSPECTOR_REPO}/releases"}, args.json)
        return 1
    p = run(cmd)
    if p.returncode != 0:
        emit({"error": p.stderr.strip()}, args.json)
        return 1
    with zipfile.ZipFile(CACHE_DIR / asset) as zf:
        zf.extractall(CACHE_DIR)
    binp = inspector_bin()
    if binp:
        binp.chmod(0o755)
    report = {"installed": bool(binp), "binary": str(binp) if binp else None, "dotnet_root": dotnet_root()}
    if not report["dotnet_root"]:
        report["fix_dotnet"] = "brew install dotnet  (or the .NET 10 runtime from dot.net)"
    emit(report, args.json)
    return 0 if binp else 1


def run_inspector(inputs: list[Path], out: Path, args: argparse.Namespace) -> dict[str, Any]:
    binp = inspector_bin()
    if not binp:
        return {"error": "Il2CppInspectorRedux not installed", "fix": "uv run scripts/il2cpp_tools.py install-inspector"}
    env = os.environ.copy()
    root = dotnet_root()
    if not root:
        return {"error": ".NET 10 runtime not found", "fix": "brew install dotnet"}
    env["DOTNET_ROOT"] = root
    env["NO_COLOR"] = "1"
    out.mkdir(parents=True, exist_ok=True)
    cmd = [str(binp), "process", *map(str, inputs), "-o", str(out),
           "--output-csharp-stub", "--layout", "Assembly",
           "--output-disassembler-metadata", "--disassembler", args.disassembler,
           "--output-dummy-dlls", "--output-cpp-scaffolding",
           "--extract-il2cpp-files", str(out / "extracted")]
    if args.dump_base:
        cmd += ["--image-base", args.dump_base if args.dump_base.startswith("0x") else "0x" + args.dump_base]
    print("+ " + " ".join(cmd), file=sys.stderr)
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, stdin=subprocess.DEVNULL,
                              timeout=args.timeout, env=env, cwd=binp.parent)
    except subprocess.TimeoutExpired:
        return {"error": f"Il2CppInspectorRedux timed out after {args.timeout}s"}
    (out / "inspector.log").write_text(proc.stdout + "\n--- stderr ---\n" + proc.stderr, encoding="utf-8")
    files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file() and p.suffix in {".cs", ".py", ".json", ".h"})
    failed = "FAILED" in proc.stdout or proc.returncode != 0
    return {
        "returncode": proc.returncode,
        "loaded": not failed,
        "output_dir": str(out),
        "file_count": len(files),
        "sample": files[:12],
        "dummy_dll_count": len(list(out.rglob("*.dll"))),
        "log_tail": log_tail(proc.stdout + proc.stderr, 12),
    }


# ---------------------------------------------------------------- dump
def cmd_dump(args: argparse.Namespace) -> int:
    if args.engine in {"inspector", "both"}:
        inputs = [Path(x).expanduser().resolve() for x in (args.binary, args.metadata) if x]
        res_i = run_inspector(inputs, Path(args.output).expanduser().resolve() / "inspector", args)
        if args.engine == "inspector":
            emit(res_i, args.json)
            return 0 if res_i.get("loaded") and res_i.get("file_count") else 1
        print(json.dumps({"inspector": res_i}, indent=2, default=str), file=sys.stderr)
        args.output = str(Path(args.output) / "dumper")
    if not args.metadata:
        emit({"error": "il2cpp_dumper needs a metadata path; only --engine inspector accepts a package alone"}, args.json)
        return 1
    dumper = which("il2cpp_dumper")
    if not dumper:
        emit({"error": "il2cpp_dumper not found", "fix": "uv run scripts/il2cpp_tools.py install-dumper"}, args.json)
        return 1
    binary = Path(args.binary).expanduser().resolve()
    metadata = Path(args.metadata).expanduser().resolve()
    out = Path(args.output).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    config = dict(DUMPER_CONFIG)
    if args.decompile:
        config["methodBodyMode"] = "csharp"
    if args.force_version:
        config["forceIl2cppVersion"] = True
        config["forceVersion"] = float(args.force_version)
    if args.split:
        config["splitDumpPerType"] = True
    cfg_path = out / "il2cpp_tools.config.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    cmd = [dumper, "--config", str(cfg_path), "--no-pseudo-prompt",
           "--binary", str(binary), "--metadata", str(metadata), "--output", str(out)]
    if args.dump_base:
        cmd += ["--dump-base", args.dump_base]
    if args.force_dump:
        cmd.append("--force-dump")
    if args.codm:
        cmd.append("--codm")
    if args.decompile:
        cmd.append("--cs")
    print("+ " + " ".join(cmd), file=sys.stderr)
    # stdin is closed so any prompt the config did not cover fails fast
    # instead of hanging the agent.
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        emit({"error": f"il2cpp_dumper timed out after {args.timeout}s"}, args.json)
        return 1
    log = out / "il2cpp_dumper.log"
    log.write_text(proc.stdout + "\n--- stderr ---\n" + proc.stderr, encoding="utf-8")

    produced = sorted(str(p.relative_to(out)) for p in out.rglob("*")
                      if p.is_file() and p.name in {"dump.cs", "script.json", "il2cpp.h", "stringliteral.json"})
    dummy = sorted(p.name for p in out.rglob("DummyDll/*.dll"))
    result = {
        "returncode": proc.returncode,
        "output_dir": str(out),
        "files": produced,
        "dummy_dll_count": len(dummy),
        "assembly_csharp": any(d == "Assembly-CSharp.dll" for d in dummy),
        "log": str(log),
        "log_tail": log_tail(proc.stdout + proc.stderr, 15),
    }
    if not any(f.endswith("dump.cs") for f in produced):
        result["next"] = (
            "No dump.cs. Read the log tail. 'CodeRegistration not found' or wrong magic usually means "
            "a protected build: get a runtime image (bridge-dump, zygisk, or a memory dump of "
            "libil2cpp.so plus --dump-base)."
        )
    emit(result, args.json)
    return 0 if proc.returncode == 0 and produced else 1


# ---------------------------------------------------------------- frida-il2cpp-bridge
AGENT_TEMPLATE = """import "frida-il2cpp-bridge";

// One-shot recon. Keep each run focused; dump to a file with bridge-dump.
Il2Cpp.perform(() => {
    console.log(`Unity ${Il2Cpp.unityVersion}, ${Il2Cpp.domain.assemblies.length} assemblies`);

    const csharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;

    // 1. Trace every method of one class (edit the name).
    // Il2Cpp.trace(true).classes(csharp.class("GameManager")).and().attach();

    // 2. Trace methods whose name matches, across the game assembly only.
    Il2Cpp.trace(false)
        .assemblies(csharp.assembly)
        .filterMethods(m => /Login|Purchase|Verify|Decrypt/i.test(m.name))
        .and()
        .attach();

    // 3. Replace one method for a lab hypothesis (restore with .revert()).
    // const m = csharp.class("LicenseCheck").method<boolean>("IsValid");
    // m.implementation = function (...args) { console.log("IsValid", args); return true; };

    // 4. Map a native address from IDA/Ghidra back to its C# method.
    // console.log(Il2Cpp.Method.tryFromRelativeVirtualAddress(0x1a2b3c));
});
"""


def cmd_bridge_init(args: argparse.Namespace) -> int:
    npm = which("npm")
    if not npm:
        emit({"error": "npm not found"}, args.json)
        return 1
    d = Path(args.directory).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    pkg = {
        "name": d.name.lower().replace(" ", "-") or "il2cpp-agent",
        "private": True,
        "type": "module",
        "scripts": {
            "build": "frida-compile agent.ts -o _agent.js -c",
            "watch": "frida-compile agent.ts -o _agent.js -w",
        },
    }
    (d / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    agent = d / "agent.ts"
    if not agent.exists():
        agent.write_text(AGENT_TEMPLATE, encoding="utf-8")
    # Same shape as frida-agent-example. Restricting "types" or omitting "lib"
    # hides the Gum globals (console, Process, Interceptor) from tsc.
    tsconfig = {"compilerOptions": {"target": "es2022", "lib": ["es2022"], "module": "Node16",
                                    "allowJs": True, "noEmit": True, "strict": True,
                                    "esModuleInterop": True, "skipLibCheck": True}}
    (d / "tsconfig.json").write_text(json.dumps(tsconfig, indent=2) + "\n", encoding="utf-8")
    steps = [
        [npm, "install", "--save", f"{BRIDGE_NPM}@{args.bridge_version}"],
        [npm, "install", "--save-dev", "frida-compile", "@types/frida-gum", "typescript"],
        [npm, "run", "build"],
    ]
    for cmd in steps:
        p = subprocess.run(cmd, cwd=d, text=True, capture_output=True)
        if p.returncode != 0:
            emit({"error": " ".join(cmd), "output": (p.stdout + p.stderr)[-2000:]}, args.json)
            return 1
    target = f"-f {args.package}" if args.package else "-f <package>"
    emit({
        "project": str(d),
        "agent": str(agent),
        "compiled": str(d / "_agent.js"),
        "run": f"frida -U {target} -l {d / '_agent.js'}",
        "rebuild": f"npm --prefix {d} run build",
    }, args.json)
    return 0


def _bridge_cli(cache: Path, version: str) -> Path:
    """Fetch the npm package once; its Python CLI lives in cli/main.py."""
    pkg_dir = cache / f"frida-il2cpp-bridge-{version}"
    main = pkg_dir / "node_modules" / BRIDGE_NPM / "cli" / "main.py"
    if not main.exists():
        pkg_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run([which("npm") or "npm", "install", "--prefix", str(pkg_dir), f"{BRIDGE_NPM}@{version}"],
                       check=True, capture_output=True)
    return main


def cmd_bridge_dump(args: argparse.Namespace) -> int:
    frida = which("frida")
    if not frida or not which("npm"):
        emit({"error": "frida and npm are required"}, args.json)
        return 1
    # The device frida-server must match this frida version.
    frida_ver = run([frida, "--version"]).stdout.strip()
    main = _bridge_cli(CACHE_DIR, args.bridge_version)
    out = Path(args.output).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    target = ["-U"] if not args.host else ["-H", args.host]
    target += ["-f", args.package] if args.spawn else ["-n", args.package]
    cmd = ["uv", "run", "--python", "3.12", "--with", f"frida=={frida_ver}", "--with", "frida-tools",
           "--with", "colorama", "python", str(main), *target]
    if args.unity_version:
        cmd += ["--unity-version", args.unity_version]
    if args.module_name:
        cmd += ["--module-name", args.module_name]
    cmd += ["dump", "--out-dir", str(out), "--cs-output", args.cs_output]
    print("+ " + " ".join(cmd), file=sys.stderr)
    try:
        proc = subprocess.run(cmd, cwd=main.parent, text=True, capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        emit({"error": f"bridge dump timed out after {args.timeout}s", "hint": "the IL2CPP module may never load; pass --module-name"}, args.json)
        return 1
    files = sorted(str(p.relative_to(out)) for p in out.rglob("*.cs"))
    emit({"returncode": proc.returncode, "output_dir": str(out), "cs_files": len(files),
          "sample": files[:10], "log_tail": log_tail(proc.stdout + proc.stderr, 15)}, args.json)
    return 0 if proc.returncode == 0 and files else 1


# ---------------------------------------------------------------- Zygisk-Il2CppDumper
def cmd_zygisk_build(args: argparse.Namespace) -> int:
    git = which("git")
    if not git:
        emit({"error": "git not found"}, args.json)
        return 1
    src = CACHE_DIR / "Zygisk-Il2CppDumper"
    if not src.exists():
        subprocess.run([git, "clone", "--depth", "1", ZYGISK_GIT, str(src)], check=True)
    game_h = src / "module" / "src" / "main" / "cpp" / "game.h"
    text = game_h.read_text(encoding="utf-8")
    lines = [f'#define GamePackageName "{args.package}"' if ln.startswith("#define GamePackageName") else ln
             for ln in text.splitlines()]
    game_h.write_text("\n".join(lines) + "\n", encoding="utf-8")

    env = os.environ.copy()
    sdk = env.get("ANDROID_HOME") or env.get("ANDROID_SDK_ROOT") or str(Path.home() / "Library/Android/sdk")
    env["ANDROID_HOME"] = sdk
    (src / "local.properties").write_text(f"sdk.dir={sdk}\n", encoding="utf-8")
    gradlew = src / "gradlew"
    gradlew.chmod(0o755)
    proc = subprocess.run([str(gradlew), ":module:assembleRelease", "--no-daemon"], cwd=src, env=env,
                          text=True, capture_output=True, timeout=args.timeout)
    zips = sorted((src / "out").glob("*.zip"), key=lambda p: p.stat().st_mtime)
    result: dict[str, Any] = {"returncode": proc.returncode, "package": args.package,
                              "module_zip": str(zips[-1]) if zips else None,
                              "log_tail": log_tail(proc.stdout + proc.stderr, 15)}
    if proc.returncode != 0:
        result["hint"] = ("Gradle needs JDK 17 and the NDK version pinned in module/build.gradle. "
                          "Alternative: fork the repo and run its 'Build' GitHub Action with the package name.")
    elif zips:
        result["install"] = [
            f"adb push {zips[-1]} /data/local/tmp/zygisk-il2cppdumper.zip",
            "Magisk:   adb shell su -c 'magisk --install-module /data/local/tmp/zygisk-il2cppdumper.zip'",
            "KernelSU: adb shell su -c '/data/adb/ksud module install /data/local/tmp/zygisk-il2cppdumper.zip'",
            "reboot, start the game once, then: uv run scripts/il2cpp_tools.py zygisk-pull " + args.package,
        ]
    emit(result, args.json)
    return proc.returncode


def cmd_zygisk_pull(args: argparse.Namespace) -> int:
    adb = which("adb")
    if not adb:
        emit({"error": "adb not found"}, args.json)
        return 1
    out = Path(args.output).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    remote = f"/data/data/{args.package}/files/dump.cs"
    staging = f"/data/local/tmp/{args.package}.dump.cs"
    cp = run([adb, "shell", "su", "-c", f"cp {remote} {staging} && chmod 644 {staging}"], timeout=30)
    if cp.returncode != 0:
        emit({"error": f"{remote} not found", "output": (cp.stdout + cp.stderr).strip(),
              "hint": "Start the game and wait ~10 s after the first scene; check `adb logcat -s Perfare`."}, args.json)
        return 1
    dest = out / "dump.cs"
    pull = run([adb, "pull", staging, str(dest)], timeout=120)
    run([adb, "shell", "su", "-c", f"rm -f {staging}"], timeout=15)
    emit({"pulled": pull.returncode == 0, "path": str(dest),
          "size": dest.stat().st_size if dest.exists() else 0}, args.json)
    return pull.returncode


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="il2cpp_tools.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--json", action="store_true", default=False, help="JSON output")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", parents=[common], help="Report tools, device root, Zygisk, and usable routes")

    s = sub.add_parser("install-dumper", parents=[common], help="cargo install il2cpp-dumper-rs from git")
    s.add_argument("--rev", help="git commit to pin")

    s = sub.add_parser("extract", parents=[common], help="Extract IL2CPP binary + global-metadata.dat")
    s.add_argument("package", help="APK, XAPK, APKS, IPA, or an extracted game directory")
    s.add_argument("-o", "--output", required=True)

    s = sub.add_parser("install-inspector", parents=[common], help="Download the Il2CppInspectorRedux CLI")
    s.add_argument("--tag", help="release tag, default latest")

    s = sub.add_parser("dump", parents=[common], help="Static dump without prompts")
    s.add_argument("binary", help="libil2cpp.so / GameAssembly.dll / UnityFramework, a memory dump, or (inspector) an APK/XAPK/AAB/IPA")
    s.add_argument("metadata", nargs="?", help="global-metadata.dat (or a dumped copy); optional for --engine inspector on a package")
    s.add_argument("--engine", choices=["dumper", "inspector", "both"], default="dumper",
                   help="dumper = il2cpp-dumper-rs, inspector = Il2CppInspectorRedux, both = run and compare")
    s.add_argument("--disassembler", choices=["IDA", "Ghidra", "BinaryNinja"], default="IDA", help="script target for inspector")
    s.add_argument("-o", "--output", required=True)
    s.add_argument("--dump-base", help="runtime base (hex) of a memory-dumped binary")
    s.add_argument("--force-dump", action="store_true", help="treat input as a memory dump (rewrite sections)")
    s.add_argument("--force-version", help="override the metadata version, e.g. 29 or 31")
    s.add_argument("--codm", action="store_true", help="CODM layout")
    s.add_argument("--decompile", action="store_true", help="also recover C#-style method bodies (slow)")
    s.add_argument("--split", action="store_true", help="one .cs file per type")
    s.add_argument("--timeout", type=int, default=1800)

    s = sub.add_parser("bridge-init", parents=[common], help="Scaffold a frida-il2cpp-bridge agent project")
    s.add_argument("directory")
    s.add_argument("--package", help="app id, only used in the printed run command")
    s.add_argument("--bridge-version", default="latest")

    s = sub.add_parser("bridge-dump", parents=[common], help="Dump C# types at runtime with frida-il2cpp-bridge")
    s.add_argument("package", help="app id (spawned with --spawn, else attached by name)")
    s.add_argument("-o", "--output", required=True)
    s.add_argument("--spawn", action="store_true", help="spawn instead of attaching")
    s.add_argument("--host", help="frida -H host:port instead of USB")
    s.add_argument("--unity-version", help="when auto-detection fails, e.g. 2021.3.45f1")
    s.add_argument("--module-name", help="when the IL2CPP module is renamed")
    s.add_argument("--cs-output", choices=["flat", "tree"], default="flat")
    s.add_argument("--bridge-version", default="latest")
    s.add_argument("--timeout", type=int, default=600)

    s = sub.add_parser("zygisk-build", parents=[common], help="Build Zygisk-Il2CppDumper for one package")
    s.add_argument("package")
    s.add_argument("--timeout", type=int, default=1800)

    s = sub.add_parser("zygisk-pull", parents=[common], help="Pull dump.cs written by the Zygisk module")
    s.add_argument("package")
    s.add_argument("-o", "--output", default=".")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "doctor": cmd_doctor,
        "install-dumper": cmd_install_dumper,
        "install-inspector": cmd_install_inspector,
        "extract": cmd_extract,
        "dump": cmd_dump,
        "bridge-init": cmd_bridge_init,
        "bridge-dump": cmd_bridge_dump,
        "zygisk-build": cmd_zygisk_build,
        "zygisk-pull": cmd_zygisk_pull,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
