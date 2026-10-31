#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""Detect this host and, only with --install, install one allowlisted profile.

Stdout is one JSON object. A bare run never installs. Package-manager
commands exist only as argument lists in this file. KernelSU replacement
copies a local Image onto an emulator kernel-ranchu after writing
kernel-ranchu.orig; writing to a physical device is forbidden.
"""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

IOS_UNSUPPORTED = "iOS tooling runs on macOS only"
COLD_BOOT = (
    "A cold boot is required before adb shell su -c id. This skill does not boot the emulator."
)
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "android-ksu"
MANAGERS: tuple[str, ...] = ("brew", "apt-get", "dnf", "pacman", "winget")
ROOT_MANAGERS: frozenset[str] = frozenset({"apt-get", "dnf", "pacman"})
STATIC_ORDER: tuple[str, ...] = (
    "radare2",
    "apktool",
    "mitmproxy",
    "tshark",
    "binwalk",
    "jadx",
)
TOOL_COMMANDS: dict[str, str] = {
    "radare2": "r2",
    "jadx": "jadx",
    "apktool": "apktool",
    "binwalk": "binwalk",
    "frida": "frida",
    "mitmproxy": "mitmdump",
    "tshark": "tshark",
    "adb": "adb",
    "emulator": "emulator",
    "avdmanager": "avdmanager",
    "sdkmanager": "sdkmanager",
    "qemu": "qemu-system-x86_64",
    "vmrun": "vmrun",
    "xcrun": "xcrun",
    "ida-mcp": "ida-mcp",
    "vphone-cli": "vphone-cli",
    "ipsw": "ipsw",
    "utmctl": "utmctl",
    "qemu-img": "qemu-img",
    "ansible": "ansible",
    "ansible-playbook": "ansible-playbook",
}
PRESENT_VIA_COMMAND: dict[str, str] = {
    "radare2": "r2",
    "jadx": "jadx",
    "apktool": "apktool",
    "binwalk": "binwalk",
    "mitmproxy": "mitmdump",
    "tshark": "tshark",
    "adb": "adb",
    "emulator": "emulator",
    "avdmanager": "avdmanager",
    "sdkmanager": "sdkmanager",
    "qemu-system-x86": "qemu-system-x86_64",
    "ipsw": "ipsw",
    "ansible": "ansible",
    "ansible-playbook": "ansible-playbook",
}
STATIC_CANDIDATES: dict[str, dict[str, tuple[str, ...]]] = {
    "brew": {
        "radare2": ("radare2",),
        "apktool": ("apktool",),
        "mitmproxy": ("mitmproxy",),
        "tshark": (),
        "binwalk": ("binwalk",),
        "jadx": ("jadx",),
        "ipsw": ("blacktop/tap/ipsw", "ipsw"),
    },
    "apt-get": {
        "radare2": ("radare2",),
        "apktool": ("apktool",),
        "mitmproxy": ("mitmproxy",),
        "tshark": ("tshark",),
        "binwalk": ("binwalk",),
        "jadx": ("jadx",),
        "ipsw": (),
    },
    "dnf": {
        "radare2": ("radare2",),
        "apktool": ("apktool",),
        "mitmproxy": ("mitmproxy",),
        "tshark": ("tshark",),
        "binwalk": ("binwalk",),
        "jadx": ("jadx",),
        "ipsw": (),
    },
    "pacman": {
        "radare2": ("radare2",),
        "apktool": ("apktool",),
        "mitmproxy": ("mitmproxy",),
        "tshark": ("tshark",),
        "binwalk": ("binwalk",),
        "jadx": ("jadx",),
        "ipsw": (),
    },
    "winget": {
        "radare2": (),
        "apktool": (),
        "mitmproxy": (),
        "tshark": (),
        "binwalk": (),
        "jadx": (),
        "ipsw": (),
    },
}
Profile = Literal["static", "dynamic", "android", "ios"]
Candidates = tuple[str, tuple[str, ...]]


class ToolInfo(TypedDict):
    present: bool
    path: str | None


class HypervisorInfo(TypedDict):
    preferred: str
    present: bool
    qemu_present: bool
    utm_present: NotRequired[bool]
    utmctl_path: NotRequired[str | None]
    qemu_img_present: NotRequired[bool]

class AndroidInfo(TypedDict):
    adb: bool
    emulator: bool
    su: bool | None
    setup_script: NotRequired[str]


class IosSupported(TypedDict):
    supported: bool
    simctl: bool
    vphone_present: bool
    vphone_preflight_passed: bool
    rooted_vm_supported: bool
    rooted_vm_solution: str


class IosUnsupported(TypedDict):
    supported: bool
    reason: str


class KernelsuInfo(TypedDict):
    status: str
    auto_download: bool
    cache_dir: str
    system_image_roots: list[str]
    kernel_ranchu: list[str]
    path: NotRequired[str]
    replaced: NotRequired[list[str]]
    backups: NotRequired[list[str]]
    cold_boot: NotRequired[str]
    error: NotRequired[str]


class InstalledItem(TypedDict):
    name: str
    package: str


class SkipItem(TypedDict):
    name: str
    reason: str
    package: NotRequired[str]


class ProxyCaInfo(TypedDict):
    cert_present: bool
    cert_path: str | None
    subject_hash: str | None
    hash_filename: str | None
    script: str


class Report(TypedDict):
    os: str
    package_manager: str | None
    tools: dict[str, ToolInfo]
    hypervisor: HypervisorInfo
    android: AndroidInfo
    ios: IosSupported | IosUnsupported
    kernelsu: KernelsuInfo
    proxy_ca: ProxyCaInfo
    installed: NotRequired[list[InstalledItem]]
    skipped: NotRequired[list[SkipItem]]
    needs_root: NotRequired[str]


@dataclass
class Cli:
    install: Profile | None
    probe_android: bool
    error: str | None = None


@dataclass
class ApplyResult:
    installed: list[InstalledItem] = field(default_factory=list)
    skipped: list[SkipItem] = field(default_factory=list)
    needs_root: str | None = None


def emit(payload: Report) -> None:
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


def emit_error(message: str) -> None:
    json.dump({"error": message}, sys.stdout)
    sys.stdout.write("\n")


def as_profile(value: str) -> Profile | None:
    if value == "static":
        return "static"
    if value == "dynamic":
        return "dynamic"
    if value == "android":
        return "android"
    if value == "ios":
        return "ios"
    return None


def parse_cli(argv: list[str]) -> Cli:
    cli = Cli(install=None, probe_android=False)
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--probe-android":
            cli.probe_android = True
            index += 1
            continue
        if arg in {"--help", "-h"}:
            cli.error = (
                "usage: uv run scripts/detect_host.py [--probe-android] "
                "[--install static|dynamic|android|ios]"
            )
            return cli
        profile_text: str | None = None
        if arg == "--install":
            if index + 1 >= len(argv):
                cli.error = "--install requires one profile: static, dynamic, android, or ios"
                return cli
            profile_text = argv[index + 1]
            index += 2
        elif arg.startswith("--install="):
            profile_text = arg.split("=", 1)[1]
            index += 1
        else:
            cli.error = f"unrecognized argument: {arg}"
            return cli
        if cli.install is not None:
            cli.error = "--install accepts only one profile"
            return cli
        if profile_text is None:
            cli.error = "--install requires one profile: static, dynamic, android, or ios"
            return cli
        profile = as_profile(profile_text)
        if profile is None:
            cli.error = "--install requires one profile: static, dynamic, android, or ios"
            return cli
        cli.install = profile
    return cli


def run_cmd(
    argv: list[str],
    timeout: float,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            stdin=subprocess.DEVNULL,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def brew_env() -> dict[str, str]:
    env = dict(os.environ)
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    env["HOMEBREW_NO_ENV_HINTS"] = "1"
    env["HOMEBREW_NO_ANALYTICS"] = "1"
    return env


def is_root() -> bool:
    if os.name != "posix":
        return False
    return os.geteuid() == 0


def detect_os() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith(("win", "cygwin", "msys")):
        return "windows"
    return sys.platform


def detect_package_manager() -> str | None:
    for name in MANAGERS:
        if shutil.which(name) is not None:
            return name
    return None


def detect_tools() -> dict[str, ToolInfo]:
    tools: dict[str, ToolInfo] = {}
    for name, command in TOOL_COMMANDS.items():
        found = shutil.which(command)
        if found is None and name == "vphone-cli":
            found = shutil.which("vphone")
        tools[name] = {"present": found is not None, "path": found}
    return tools


def hypervisor_for(os_name: str, qemu_present: bool) -> HypervisorInfo:
    preferred = "unsupported"
    present = False
    info: HypervisorInfo = {
        "preferred": preferred,
        "present": present,
        "qemu_present": qemu_present,
    }
    if os_name == "linux":
        preferred = "kvm"
        present = Path("/dev/kvm").exists()
        info["preferred"] = preferred
        info["present"] = present
    elif os_name == "darwin":
        utm_app = Path("/Applications/UTM.app")
        utmctl_which = shutil.which("utmctl")
        utm_bundled = Path("/Applications/UTM.app/Contents/MacOS/utmctl")
        utmctl_path = utmctl_which or (str(utm_bundled) if utm_bundled.exists() else None)
        utm_present = utm_app.exists() or utmctl_path is not None
        qemu_img_present = shutil.which("qemu-img") is not None

        info["utm_present"] = utm_present
        info["utmctl_path"] = utmctl_path
        info["qemu_img_present"] = qemu_img_present

        info["preferred"] = "utm"
        info["present"] = utm_present
    elif os_name == "windows":
        preferred = "vmware"
        present = shutil.which("vmrun") is not None
        info["preferred"] = preferred
        info["present"] = present
    return info


def simctl_available() -> bool:
    xcrun = shutil.which("xcrun")
    if xcrun is None:
        return False
    found = run_cmd([xcrun, "--find", "simctl"], 30)
    if found is not None and found.returncode == 0 and found.stdout.strip() != "":
        return True
    helped = run_cmd([xcrun, "simctl", "help"], 30)
    return helped is not None and helped.returncode == 0


def ios_report(os_name: str) -> IosSupported | IosUnsupported:
    if os_name != "darwin":
        return {"supported": False, "reason": IOS_UNSUPPORTED}
    vphone_cmd = shutil.which("vphone-cli") or shutil.which("vphone")
    vphone_present = vphone_cmd is not None
    vphone_preflight_passed = False
    if vphone_present and vphone_cmd is not None:
        res = run_cmd([vphone_cmd, "host", "preflight"], timeout=5.0)
        vphone_preflight_passed = res is not None and res.returncode == 0
    rooted_vm_supported = platform.machine() in ("arm64", "aarch64")
    return {
        "supported": True,
        "simctl": simctl_available(),
        "vphone_present": vphone_present,
        "vphone_preflight_passed": vphone_preflight_passed,
        "rooted_vm_supported": rooted_vm_supported,
        "rooted_vm_solution": "https://github.com/Lakr233/vphone-cli",
    }


def connected_device_count(text: str) -> int:
    count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if line == "" or line.startswith("*") or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            count += 1
    return count


def probe_su(adb_path: str | None) -> bool | None:
    if adb_path is None:
        return None
    listed = run_cmd([adb_path, "devices"], 20)
    if listed is None or listed.returncode != 0:
        return None
    if connected_device_count(listed.stdout) != 1:
        return None
    checked = run_cmd([adb_path, "shell", "su", "-c", "id"], 20)
    if checked is None or checked.returncode != 0:
        return False
    return True


def system_image_roots() -> list[Path]:
    candidates: list[Path] = []
    for env_var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(env_var, "").strip()
        if val:
            candidates.append(Path(val) / "system-images")
    candidates.append(Path.home() / "Library" / "Android" / "sdk" / "system-images")
    candidates.append(Path.home() / "Android" / "Sdk" / "system-images")
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            key = str(candidate.resolve())
        except OSError:
            key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def inside_root(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        root_resolved = root.resolve(strict=True)
    except OSError:
        return False
    if root_resolved.name != "system-images":
        return False
    if "system-images" not in resolved.parts:
        return False
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        return False
    return True


def destination_allowed(dest: Path, roots: list[Path]) -> bool:
    if dest.name != "kernel-ranchu":
        return False
    try:
        info = dest.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False
    try:
        if not stat.S_ISREG(dest.stat().st_mode):
            return False
    except OSError:
        return False
    for root in roots:
        if inside_root(dest, root):
            return True
    return False


def find_kernel_ranchu(roots: list[Path]) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            kept: list[str] = []
            for name in dirnames:
                if not (Path(dirpath) / name).is_symlink():
                    kept.append(name)
            dirnames[:] = kept
            if "kernel-ranchu" not in filenames:
                continue
            candidate = Path(dirpath) / "kernel-ranchu"
            if not destination_allowed(candidate, [root]):
                continue
            try:
                key = str(candidate.resolve(strict=True))
            except OSError:
                continue
            if key in seen:
                continue
            seen.add(key)
            found.append(candidate)
    return found


def get_cache_dir() -> Path:
    env_dir = os.environ.get("ANDROID_KSU_CACHE_DIR")
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    return DEFAULT_CACHE_DIR


def local_kernelsu_image() -> Path | None:
    cache_dir = get_cache_dir()
    image_path = cache_dir / "Image"
    try:
        info = image_path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None
    try:
        resolved = image_path.resolve(strict=True)
        download = cache_dir.resolve(strict=True)
    except OSError:
        return None
    if resolved.parent != download or resolved.name != "Image":
        return None
    try:
        if not stat.S_ISREG(resolved.stat().st_mode):
            return None
    except OSError:
        return None
    return resolved


def kernelsu_report() -> KernelsuInfo:
    roots = system_image_roots()
    kernels = find_kernel_ranchu(roots)
    cache_dir = get_cache_dir()
    return {
        "status": "available",
        "auto_download": True,
        "cache_dir": str(cache_dir),
        "system_image_roots": [str(root) for root in roots],
        "kernel_ranchu": [str(kernel) for kernel in kernels],
    }


def proxy_ca_report() -> ProxyCaInfo:
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    script_path = Path(__file__).with_name("setup_proxy_ca.py")
    script = str(script_path.resolve()) if script_path.exists() else str(script_path)
    if not ca_path.exists():
        return {
            "cert_present": False,
            "cert_path": None,
            "subject_hash": None,
            "hash_filename": None,
            "script": script,
        }
    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    proc = run_cmd(
        [openssl, "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(ca_path), "-noout"], 10
    )
    if proc is None or proc.returncode != 0:
        proc = run_cmd(
            [openssl, "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(ca_path)], 10
        )
    subject_hash: str | None = None
    hash_filename: str | None = None
    if proc is not None and proc.returncode == 0:
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if lines:
            subject_hash = lines[0]
            hash_filename = f"{subject_hash}.0"
    return {
        "cert_present": True,
        "cert_path": str(ca_path),
        "subject_hash": subject_hash,
        "hash_filename": hash_filename,
        "script": script,
    }


def detect(probe_android: bool) -> Report:
    os_name = detect_os()
    tools = detect_tools()
    su: bool | None = None
    if probe_android:
        su = probe_su(tools["adb"]["path"])
    script_path = Path(__file__).with_name("setup_android_emulator.py")
    android_info: AndroidInfo = {
        "adb": tools["adb"]["present"],
        "emulator": tools["emulator"]["present"],
        "su": su,
    }
    if script_path.exists():
        android_info["setup_script"] = str(script_path.resolve())
    return {
        "os": os_name,
        "package_manager": detect_package_manager(),
        "tools": tools,
        "hypervisor": hypervisor_for(os_name, tools["qemu"]["present"]),
        "android": android_info,
        "ios": ios_report(os_name),
        "kernelsu": kernelsu_report(),
        "proxy_ca": proxy_ca_report(),
    }


def already_present(name: str) -> bool:
    command = PRESENT_VIA_COMMAND.get(name)
    if command is None:
        return False
    return shutil.which(command) is not None


def package_known(manager: str, package: str) -> tuple[bool, str | None]:
    if manager == "winget":
        return False, None
    if manager == "brew":
        env = brew_env()
        formula = run_cmd(["brew", "info", "--formula", package], 60, env)
        if formula is not None and formula.returncode == 0:
            return True, "formula"
        cask = run_cmd(["brew", "info", "--cask", package], 60, env)
        if cask is not None and cask.returncode == 0:
            return True, "cask"
        return False, None
    if manager == "apt-get":
        shown = run_cmd(["apt-cache", "show", package], 30)
        if shown is None or shown.returncode != 0:
            return False, None
        return "Package:" in shown.stdout, None
    if manager == "dnf":
        info = run_cmd(["dnf", "info", "--cacheonly", "--quiet", package], 30)
        return info is not None and info.returncode == 0, None
    if manager == "pacman":
        info = run_cmd(["pacman", "-Si", package], 30)
        return info is not None and info.returncode == 0, None
    return False, None


def package_installed(manager: str, package: str, brew_kind: str | None) -> bool:
    if manager == "brew":
        flag = "--cask" if brew_kind == "cask" else "--formula"
        listed = run_cmd(["brew", "list", flag, package], 60, brew_env())
        return listed is not None and listed.returncode == 0
    if manager == "apt-get":
        queried = run_cmd(["dpkg-query", "-W", "-f", "${Status}", package], 30)
        return (
            queried is not None
            and queried.returncode == 0
            and "install ok installed" in queried.stdout
        )
    if manager == "dnf":
        queried = run_cmd(["rpm", "-q", package], 30)
        return queried is not None and queried.returncode == 0
    if manager == "pacman":
        queried = run_cmd(["pacman", "-Q", package], 30)
        return queried is not None and queried.returncode == 0
    return False


def resolve_candidate(
    manager: str, candidates: tuple[str, ...]
) -> tuple[str | None, str | None, str]:
    if manager == "winget" or not candidates:
        return None, None, "unmapped"
    for package in candidates:
        known, kind = package_known(manager, package)
        if known:
            return package, kind, ""
    return None, None, "unknown"


def combined_command(manager: str, packages: list[str]) -> str:
    if manager == "apt-get":
        argv = ["apt-get", "install", "-y", *packages]
    elif manager == "dnf":
        argv = ["dnf", "install", "-y", *packages]
    elif manager == "pacman":
        argv = ["pacman", "-S", "--noconfirm", "--needed", *packages]
    else:
        argv = [manager, "install", *packages]
    return shlex.join(argv)


def run_install(manager: str, package: str, brew_kind: str | None) -> bool:
    env: dict[str, str] | None = None
    if manager == "brew":
        argv = ["brew", "install"]
        if brew_kind == "cask":
            argv.append("--cask")
        argv.append(package)
        env = brew_env()
    elif manager == "apt-get":
        argv = ["apt-get", "install", "-y", package]
        env = dict(os.environ)
        env["DEBIAN_FRONTEND"] = "noninteractive"
    elif manager == "dnf":
        argv = ["dnf", "install", "-y", package]
    elif manager == "pacman":
        argv = ["pacman", "-S", "--noconfirm", "--needed", package]
    else:
        return False
    result = run_cmd(argv, 900, env)
    return result is not None and result.returncode == 0


def apply_packages(manager: str | None, requests: list[Candidates]) -> ApplyResult:
    result = ApplyResult()
    if manager is None:
        for name, _candidates in requests:
            reason = "present" if already_present(name) else "no-package-manager"
            result.skipped.append({"name": name, "reason": reason})
        return result
    needs_privilege = manager in ROOT_MANAGERS and not is_root()
    pending: list[str] = []
    for name, candidates in requests:
        if already_present(name):
            result.skipped.append({"name": name, "reason": "present"})
            continue
        package, kind, missing = resolve_candidate(manager, candidates)
        if package is None:
            result.skipped.append({"name": name, "reason": missing})
            continue
        if package_installed(manager, package, kind):
            item: SkipItem = {"name": name, "reason": "present", "package": package}
            result.skipped.append(item)
            continue
        if needs_privilege:
            pending.append(package)
            denied: SkipItem = {"name": name, "reason": "needs_root", "package": package}
            result.skipped.append(denied)
            continue
        if run_install(manager, package, kind):
            result.installed.append({"name": name, "package": package})
        else:
            failed: SkipItem = {"name": name, "reason": "install-failed", "package": package}
            result.skipped.append(failed)
    if pending:
        result.needs_root = combined_command(manager, pending)
    return result


def static_requests(manager: str | None) -> list[Candidates]:
    table = STATIC_CANDIDATES.get(manager or "", {})
    return [(name, table.get(name, ())) for name in STATIC_ORDER]


def dynamic_requests(os_name: str, manager: str | None) -> tuple[list[Candidates], list[SkipItem]]:
    if os_name == "darwin":
        return [], [{"name": "utm", "reason": "manual"}]
    if os_name == "windows":
        return [], [{"name": "vmware", "reason": "manual"}]
    if os_name != "linux":
        return [], [{"name": "hypervisor", "reason": "unsupported"}]
    names = ("qemu-kvm", "qemu-system-x86")
    if manager == "winget":
        return [(name, ()) for name in names], []
    return [(name, (name,)) for name in names], []


def android_requests(manager: str | None) -> list[Candidates]:
    if manager == "brew":
        return [("adb", ("android-platform-tools",)), ("emulator", ())]
    if manager == "apt-get":
        return [("adb", ("adb",)), ("emulator", ("emulator",))]
    if manager in {"dnf", "pacman"}:
        return [("adb", ("adb", "android-tools")), ("emulator", ("emulator",))]
    return [("adb", ()), ("emulator", ())]


def ios_requests(manager: str | None) -> list[Candidates]:
    if manager == "brew":
        return [("ipsw", ("blacktop/tap/ipsw", "ipsw"))]
    return []


def simctl_flag(ios_info: object) -> bool:
    if not isinstance(ios_info, dict):
        return False
    return ios_info.get("simctl") is True


def replace_one(image: Path, dest: Path) -> tuple[bool, str | None, str | None]:
    roots = system_image_roots()
    if dest.name != "kernel-ranchu" or not destination_allowed(dest, roots):
        return False, None, "refused destination"
    backup = dest.with_name("kernel-ranchu.orig")
    temporary = dest.with_name("kernel-ranchu.tool-setup-tmp")
    try:
        if backup.exists():
            if backup.is_symlink() or not backup.is_file():
                return False, None, "backup path is not a regular file"
        else:
            shutil.copy2(dest, backup)
        if image.resolve(strict=True) == dest.resolve(strict=True):
            return False, str(backup), "image and destination are the same file"
        shutil.copy2(image, temporary)
        os.replace(temporary, dest)
    except OSError as exc:
        return False, None, exc.strerror or "copy failed"
    finally:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass
    return True, str(backup), None


def apply_kernelsu(report: Report, result: ApplyResult) -> None:
    info = report["kernelsu"]
    targets = find_kernel_ranchu(system_image_roots())
    if not targets:
        info["status"] = "local"
        result.skipped.append({"name": "kernelsu", "reason": "no-kernel-ranchu"})
        return

    image = local_kernelsu_image()
    clean_dir: Path | None = None
    if image is None:
        try:
            from setup_android_emulator import resolve_kernel_source

            cache_dir = get_cache_dir()
            image, clean_dir = resolve_kernel_source(
                download_dir=cache_dir, target_dir=targets[0].parent
            )
        except Exception as exc:
            info["status"] = "download-failed"
            info["error"] = str(exc)
            result.skipped.append({"name": "kernelsu", "reason": "download-failed"})
            return
    replaced: list[str] = []
    backups: list[str] = []
    errors: list[str] = []
    try:
        for dest in targets:
            ok, backup, error = replace_one(image, dest)
            if ok and backup is not None:
                replaced.append(str(dest))
                if backup not in backups:
                    backups.append(backup)
                continue
            if error is not None:
                errors.append(f"{dest}: {error}")
        if replaced:
            info["status"] = "replaced"
            info["replaced"] = replaced
            info["backups"] = backups
            info["cold_boot"] = COLD_BOOT
            result.installed.append({"name": "kernelsu", "package": "Image"})
        else:
            info["status"] = "local"
            result.skipped.append({"name": "kernelsu", "reason": "install-failed"})
        if errors:
            info["error"] = "; ".join(errors)
    finally:
        if clean_dir and clean_dir.is_dir():
            try:
                shutil.rmtree(clean_dir)
            except OSError:
                pass


def install_profile(profile: Profile, report: Report) -> int:
    if profile == "ios" and report["os"] != "darwin":
        report["installed"] = []
        report["skipped"] = [{"name": "ios", "reason": "unsupported"}]
        emit(report)
        return 2
    manager = report["package_manager"]
    extra: list[SkipItem] = []
    requests: list[Candidates] = []
    if profile == "static":
        requests = static_requests(manager)
    elif profile == "dynamic":
        requests, extra = dynamic_requests(report["os"], manager)
    elif profile == "android":
        requests = android_requests(manager)
    elif profile == "ios":
        extra = [{"name": "xcode", "reason": "manual"}]
        if not simctl_flag(report["ios"]):
            extra.append({"name": "simctl", "reason": "missing"})
        requests = ios_requests(manager)
    result = apply_packages(manager, requests)
    result.skipped = extra + result.skipped
    if profile == "android":
        apply_kernelsu(report, result)
    report["installed"] = result.installed
    report["skipped"] = result.skipped
    if result.needs_root is not None:
        report["needs_root"] = result.needs_root
    tools = detect_tools()
    report["tools"] = tools
    report["hypervisor"] = hypervisor_for(report["os"], tools["qemu"]["present"])
    report["android"]["adb"] = tools["adb"]["present"]
    report["android"]["emulator"] = tools["emulator"]["present"]
    script_path = Path(__file__).with_name("setup_android_emulator.py")
    if script_path.exists():
        report["android"]["setup_script"] = str(script_path.resolve())
    emit(report)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cli = parse_cli(args)
    if cli.error is not None:
        emit_error(cli.error)
        return 1
    report = detect(cli.probe_android)
    if cli.install is None:
        emit(report)
        return 0
    return install_profile(cli.install, report)


if __name__ == "__main__":
    raise SystemExit(main())
