#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""Manage and root Android Studio emulators with KernelSU on Apple Silicon / Linux / Windows."""

from __future__ import annotations

import argparse
import gzip
import json
import lzma
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, NotRequired, TypedDict

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "android-ksu"
DEFAULT_AVD_NAME = "Pixel_10_KernelSU_Next"
DEFAULT_DEVICE = "pixel_7"
GITHUB_USER_AGENT = "android-ksu-setup/1.0"


def get_default_download_dir() -> Path:
    env_dir = os.environ.get("ANDROID_KSU_CACHE_DIR")
    if env_dir:
        p = Path(env_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p
    DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_CACHE_DIR


class AssetInfo(TypedDict):
    name: str
    path: str
    kind: str
    size_bytes: int


class SystemImageInfo(TypedDict):
    tag: str
    api: str
    abi: str
    path: str
    kernel_ranchu_exists: bool
    has_backup: bool


class ListReport(TypedDict):
    sdk_root: str | None
    avdmanager: str | None
    sdkmanager: str | None
    emulator: str | None
    adb: str | None
    system_images: list[SystemImageInfo]
    avds: list[str]
    assets: list[AssetInfo]


class CreateAvdResult(TypedDict):
    avd: str
    system_image_package: str
    device: str
    success: bool


class ColdBootResult(TypedDict):
    avd: str
    pid: int | None
    status: str
    headless: bool
    message: str


class WaitBootResult(TypedDict):
    serial: str
    boot_completed: bool
    elapsed_seconds: float
    message: str


class PatchResult(TypedDict):
    target: str
    backup: str | None
    source_kernel: str
    status: str
    error: NotRequired[str]


class InstallApkResult(TypedDict):
    apk: str
    serial: str
    success: bool
    output: str


class VerifyRootResult(TypedDict):
    serial: str
    rooted: bool
    uid: int | None
    gid: int | None
    raw_output: str


def find_sdk_root() -> Path | None:
    for env_var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(env_var)
        if val:
            p = Path(val).expanduser().resolve()
            if p.is_dir():
                return p
    fallback = Path.home() / "Library" / "Android" / "sdk"
    if fallback.is_dir():
        return fallback.resolve()
    linux_fallback = Path.home() / "Android" / "Sdk"
    if linux_fallback.is_dir():
        return linux_fallback.resolve()
    return None


def resolve_binary(name: str, sdk_root: Path | None) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    if not sdk_root:
        return None
    candidates: list[Path] = []
    if name == "adb":
        candidates.append(sdk_root / "platform-tools" / "adb")
    elif name == "emulator":
        candidates.append(sdk_root / "emulator" / "emulator")
    elif name in {"avdmanager", "sdkmanager"}:
        candidates.append(sdk_root / "cmdline-tools" / "latest" / "bin" / name)
        cmdline_root = sdk_root / "cmdline-tools"
        if cmdline_root.is_dir():
            for child in cmdline_root.iterdir():
                candidates.append(child / "bin" / name)
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c.resolve())
    return None


def run_command(
    cmd: list[str], timeout: float = 30.0, check: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def list_system_images(sdk_root: Path | None) -> list[SystemImageInfo]:
    if not sdk_root:
        return []
    sys_img_dir = sdk_root / "system-images"
    if not sys_img_dir.is_dir():
        return []
    results: list[SystemImageInfo] = []
    for api_dir in sorted(sys_img_dir.iterdir()):
        if not api_dir.is_dir():
            continue
        api = api_dir.name
        for tag_dir in sorted(api_dir.iterdir()):
            if not tag_dir.is_dir():
                continue
            tag = tag_dir.name
            for abi_dir in sorted(tag_dir.iterdir()):
                if not abi_dir.is_dir():
                    continue
                abi = abi_dir.name
                kernel = abi_dir / "kernel-ranchu"
                backup = abi_dir / "kernel-ranchu.orig"
                results.append(
                    {
                        "tag": tag,
                        "api": api,
                        "abi": abi,
                        "path": str(abi_dir),
                        "kernel_ranchu_exists": kernel.is_file(),
                        "has_backup": backup.is_file(),
                    }
                )
    return results


def list_avds(emulator_bin: str | None) -> list[str]:
    if not emulator_bin:
        return []
    try:
        proc = run_command([emulator_bin, "-list-avds"], timeout=10.0)
        if proc.returncode == 0:
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    avd_home = Path.home() / ".android" / "avd"
    if avd_home.is_dir():
        names: list[str] = []
        for ini in avd_home.glob("*.ini"):
            names.append(ini.stem)
        return sorted(names)
    return []


def list_assets(download_dir: Path) -> list[AssetInfo]:
    if not download_dir.is_dir():
        return []
    assets: list[AssetInfo] = []
    for item in sorted(download_dir.iterdir()):
        if not item.is_file():
            continue
        kind = "other"
        name = item.name
        if name == "Image":
            kind = "gki_kernel_image"
        elif name.endswith(".zip") and ("KernelSU" in name or "Bypass" in name):
            kind = "anykernel3_archive"
        elif name.endswith(".apk") and ("KernelSU" in name or name == "KernelSU.apk"):
            kind = "kernelsu_manager_apk"
        elif name.startswith("ksud"):
            kind = "ksud_daemon_binary"
        assets.append(
            {
                "name": name,
                "path": str(item),
                "kind": kind,
                "size_bytes": item.stat().st_size,
            }
        )
    return assets


def get_default_system_image_path(sdk_root: Path | None) -> Path | None:
    images = list_system_images(sdk_root)
    # Preference: arm64-v8a google_apis_playstore, highest api
    arch = "arm64-v8a" if platform.machine() in {"arm64", "aarch64"} else "x86_64"
    candidates = [
        img
        for img in images
        if img["abi"] == arch and "playstore" in img["tag"] and img["kernel_ranchu_exists"]
    ]
    if not candidates:
        candidates = [img for img in images if img["abi"] == arch and img["kernel_ranchu_exists"]]
    if not candidates:
        return None

    # Sort descending by api version
    def api_key(img: SystemImageInfo) -> str:
        return img["api"]

    candidates.sort(key=api_key, reverse=True)
    return Path(candidates[0]["path"])


def detect_target_kernel_version(target_dir: Path) -> str | None:
    dest = target_dir / "kernel-ranchu"
    if not dest.is_file():
        dest = target_dir / "kernel-ranchu.orig"
    if not dest.is_file():
        return None
    try:
        with open(dest, "rb") as f:
            header = f.read(4)
        data: bytes | None = None
        if header.startswith(b"\x1f\x8b"):
            with gzip.open(dest, "rb") as gz:
                data = gz.read(25_000_000)
        elif header.startswith(b"\xfd7zXZ"):
            with lzma.open(dest, "rb") as xz:
                data = xz.read(25_000_000)
        else:
            with open(dest, "rb") as f:
                data = f.read(25_000_000)
        if data:
            m = re.search(
                rb"Linux version ([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-android[0-9]+)?)",
                data,
            )
            if m:
                return m.group(1).decode("ascii", errors="ignore")
    except Exception:
        pass
    return None


def download_file(url: str, dest_path: Path) -> Path:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest_path.with_name(f"{dest_path.name}.tmp-{int(time.time())}")
    req = urllib.request.Request(url, headers={"User-Agent": GITHUB_USER_AGENT})
    with urllib.request.urlopen(req, timeout=300.0) as resp, open(tmp_path, "wb") as out:
        shutil.copyfileobj(resp, out)
    os.replace(tmp_path, dest_path)
    return dest_path


def download_kernelsu_apk(dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    api_endpoints = [
        "https://api.github.com/repos/KernelSU-Next/KernelSU-Next/releases/latest",
        "https://api.github.com/repos/tiann/KernelSU/releases/latest",
    ]
    last_err: Exception | None = None
    for api_url in api_endpoints:
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": GITHUB_USER_AGENT})
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                rel_data = json.loads(resp.read().decode())
            apk_assets = [
                a
                for a in rel_data.get("assets", [])
                if isinstance(a.get("name"), str) and a["name"].endswith(".apk")
            ]
            if not apk_assets:
                continue
            apk_assets.sort(
                key=lambda a: (
                    0
                    if "spoofed" not in a["name"].lower() and "release" in a["name"].lower()
                    else 1,
                    0 if "release" in a["name"].lower() else 1,
                    a["name"],
                )
            )
            chosen = apk_assets[0]
            asset_name = chosen["name"]
            dl_url = chosen["browser_download_url"]
            target_path = dest_dir / asset_name
            if target_path.is_file() and target_path.stat().st_size > 0:
                return target_path
            return download_file(dl_url, target_path)
        except Exception as exc:
            last_err = exc
            continue
    raise RuntimeError(f"Failed to download KernelSU Manager APK: {last_err}")


def download_kernel_zip(kernel_version: str, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    api_url = "https://api.github.com/repos/WildKernels/GKI_KernelSU_SUSFS/releases"
    req = urllib.request.Request(api_url, headers={"User-Agent": GITHUB_USER_AGENT})
    with urllib.request.urlopen(req, timeout=45.0) as resp:
        releases = json.loads(resp.read().decode())

    t = kernel_version.strip().lower()
    m_target = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:-([a-z0-9]+))?", t)
    t_major = m_target.group(1) if m_target else None
    t_minor = m_target.group(2) if m_target else None
    t_android = m_target.group(4) if m_target else None

    candidates: list[tuple[int, int, int, str, str]] = []
    for r in releases:
        for a in r.get("assets", []):
            name = a.get("name", "")
            if not isinstance(name, str) or not name.endswith(".zip"):
                continue
            name_l = name.lower()
            dl_url = a.get("browser_download_url")
            if not dl_url:
                continue

            prio = 10 if "kernelsu-next" in name_l else (20 if "kernelsu" in name_l else 30)
            if t in name_l:
                candidates.append((1, prio, 0, name, dl_url))
                continue

            m_a = re.match(r"^(\d+)\.(\d+)\.(\d+)-([a-z0-9]+)", name_l)
            if m_a and t_major and t_minor:
                a_maj, a_min, a_pat, a_and = (
                    m_a.group(1),
                    m_a.group(2),
                    int(m_a.group(3)),
                    m_a.group(4),
                )
                if a_maj == t_major and a_min == t_minor:
                    and_match = (t_android == a_and) if t_android else True
                    tier = 2 if and_match else 3
                    candidates.append((tier, prio, -a_pat, name, dl_url))

    if not candidates:
        raise RuntimeError(
            f"No matching AnyKernel3 zip found for kernel version '{kernel_version}' in WildKernels releases"
        )

    candidates.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
    chosen_name = candidates[0][3]
    chosen_url = candidates[0][4]
    target_path = dest_dir / chosen_name
    if target_path.is_file() and target_path.stat().st_size > 0:
        return target_path
    return download_file(chosen_url, target_path)


def resolve_kernel_source(
    download_dir: Path,
    explicit_source: Path | None = None,
    target_dir: Path | None = None,
) -> tuple[Path, Path | None]:
    """Return (source_kernel_image_path, temp_dir_to_clean)."""
    if explicit_source:
        p = explicit_source.expanduser().resolve()
        if p.is_file() and p.name == "Image":
            return p, None
        if p.is_file() and p.suffix == ".zip":
            tmp_extract = Path("/tmp") / f"ksu_extract_{int(time.time())}"
            tmp_extract.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(p, "r") as zf:
                zf.extract("Image", path=tmp_extract)
            return tmp_extract / "Image", tmp_extract

    # Check direct Image in download dir
    direct_image = download_dir / "Image"
    if direct_image.is_file() and direct_image.stat().st_size > 0:
        return direct_image, None

    # Check AnyKernel3 zip files in download dir
    if download_dir.is_dir():
        zip_files = sorted(
            [f for f in download_dir.glob("*.zip") if "KernelSU" in f.name or "Bypass" in f.name],
            reverse=True,
        )
        for zpath in zip_files:
            try:
                with zipfile.ZipFile(zpath, "r") as zf:
                    if "Image" in zf.namelist():
                        tmp_extract = Path("/tmp") / f"ksu_extract_{zpath.stem}_{int(time.time())}"
                        tmp_extract.mkdir(parents=True, exist_ok=True)
                        zf.extract("Image", path=tmp_extract)
                        return tmp_extract / "Image", tmp_extract
            except Exception:
                continue

    # If neither direct Image nor zip is found, attempt auto-download matching kernel
    kernel_ver: str | None = None
    if target_dir:
        kernel_ver = detect_target_kernel_version(target_dir)
    if not kernel_ver:
        kernel_ver = "6.6.66-android15"

    zip_path = download_kernel_zip(kernel_ver, download_dir)
    tmp_extract = Path("/tmp") / f"ksu_extract_{zip_path.stem}_{int(time.time())}"
    tmp_extract.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extract("Image", path=tmp_extract)
    return tmp_extract / "Image", tmp_extract


def patch_kernel(
    target_dir: Path, download_dir: Path, explicit_source: Path | None = None
) -> PatchResult:
    dest = target_dir / "kernel-ranchu"
    if not dest.is_file():
        return {
            "target": str(dest),
            "backup": None,
            "source_kernel": "",
            "status": "error",
            "error": f"Target kernel-ranchu not found at {dest}",
        }

    backup = target_dir / "kernel-ranchu.orig"
    tmp_clean: Path | None = None
    try:
        src_image, tmp_clean = resolve_kernel_source(download_dir, explicit_source, target_dir)
        if not backup.exists():
            shutil.copy2(dest, backup)

        temp_dest = target_dir / "kernel-ranchu.ksu-tmp"
        shutil.copy2(src_image, temp_dest)
        os.replace(temp_dest, dest)
        return {
            "target": str(dest),
            "backup": str(backup),
            "source_kernel": str(src_image),
            "status": "patched",
        }
    except Exception as exc:
        return {
            "target": str(dest),
            "backup": str(backup) if backup.exists() else None,
            "source_kernel": "",
            "status": "error",
            "error": str(exc),
        }
    finally:
        if tmp_clean and tmp_clean.is_dir():
            try:
                shutil.rmtree(tmp_clean)
            except OSError:
                pass


def create_avd(
    avdmanager_bin: str,
    name: str,
    package_path: str,
    device: str = DEFAULT_DEVICE,
    force: bool = True,
) -> bool:
    cmd = [
        avdmanager_bin,
        "create",
        "avd",
        "-n",
        name,
        "-k",
        package_path,
        "--device",
        device,
    ]
    if force:
        cmd.append("--force")
    proc = subprocess.run(
        cmd,
        input="no\n",  # Do you wish to create a custom hardware profile? [no]
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    return proc.returncode == 0


def cold_boot(
    emulator_bin: str,
    avd_name: str,
    headless: bool = False,
    extra_args: list[str] | None = None,
) -> subprocess.Popen[str]:
    cmd = [emulator_bin, "-avd", avd_name, "-no-snapshot-load"]
    if headless:
        cmd.extend(["-no-window", "-no-audio"])
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    return proc


def get_first_device_serial(adb_bin: str) -> str | None:
    try:
        proc = run_command([adb_bin, "devices"], timeout=10.0)
        for line in proc.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
            if len(parts) >= 2 and parts[1] in {"offline", "unauthorized", "bootloader"}:
                return parts[0]
    except Exception:
        pass
    return None


def wait_boot(adb_bin: str, serial: str | None = None, timeout: float = 180.0) -> WaitBootResult:
    start_time = time.time()
    # Wait for adb device
    wait_cmd = [adb_bin]
    if serial:
        wait_cmd.extend(["-s", serial])
    else:
        wait_cmd.extend(["-e"])  # wait-for-emulator
    wait_cmd.append("wait-for-device")

    try:
        subprocess.run(wait_cmd, timeout=timeout, capture_output=True, check=True)
    except subprocess.TimeoutExpired:
        return {
            "serial": serial or "emulator",
            "boot_completed": False,
            "elapsed_seconds": round(time.time() - start_time, 2),
            "message": f"Timed out waiting for device after {timeout}s",
        }

    # If no serial provided, detect it now
    if not serial:
        serial = get_first_device_serial(adb_bin) or "emulator-5554"

    # Poll getprop sys.boot_completed
    time.time()
    while time.time() - start_time < timeout:
        try:
            p = run_command(
                [adb_bin, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                timeout=5.0,
            )
            if p.stdout.strip() == "1":
                return {
                    "serial": serial,
                    "boot_completed": True,
                    "elapsed_seconds": round(time.time() - start_time, 2),
                    "message": "Boot completed successfully",
                }
        except Exception:
            pass
        time.sleep(2.0)

    return {
        "serial": serial,
        "boot_completed": False,
        "elapsed_seconds": round(time.time() - start_time, 2),
        "message": f"sys.boot_completed did not reach 1 within {timeout}s",
    }


def find_kernelsu_apk(download_dir: Path) -> Path | None:
    if not download_dir.is_dir():
        return None
    apks = sorted(
        [f for f in download_dir.glob("*.apk") if "KernelSU" in f.name or f.name == "KernelSU.apk"],
        reverse=True,
    )
    return apks[0] if apks else None


def ensure_kernelsu_apk(download_dir: Path) -> Path:
    apk = find_kernelsu_apk(download_dir)
    if apk and apk.is_file():
        return apk
    return download_kernelsu_apk(download_dir)


def install_apk(adb_bin: str, apk_path: Path, serial: str | None = None) -> InstallApkResult:
    cmd = [adb_bin]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(["install", "-r", str(apk_path)])
    try:
        proc = run_command(cmd, timeout=60.0)
        success = proc.returncode == 0 and "Success" in proc.stdout
        return {
            "apk": str(apk_path),
            "serial": serial or "default",
            "success": success,
            "output": (proc.stdout + "\n" + proc.stderr).strip(),
        }
    except Exception as exc:
        return {
            "apk": str(apk_path),
            "serial": serial or "default",
            "success": False,
            "output": str(exc),
        }


def verify_root(adb_bin: str, serial: str | None = None) -> VerifyRootResult:
    cmd = [adb_bin]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(["shell", "su", "-c", "id"])
    try:
        proc = run_command(cmd, timeout=15.0)
        out = proc.stdout.strip()
        uid: int | None = None
        gid: int | None = None
        m_uid = re.search(r"uid=(\d+)", out)
        if m_uid:
            uid = int(m_uid.group(1))
        m_gid = re.search(r"gid=(\d+)", out)
        if m_gid:
            gid = int(m_gid.group(1))
        rooted = uid == 0
        return {
            "serial": serial or "default",
            "rooted": rooted,
            "uid": uid,
            "gid": gid,
            "raw_output": out,
        }
    except Exception as exc:
        return {
            "serial": serial or "default",
            "rooted": False,
            "uid": None,
            "gid": None,
            "raw_output": str(exc),
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Android Studio KernelSU Root Automation Utility",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--download-dir",
        type=Path,
        default=get_default_download_dir(),
        help="Directory containing KernelSU images, AnyKernel3 zips, and APKs (auto-cached)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of human-readable text",
    )

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # list
    subparsers.add_parser("list", help="List SDK, system images, AVDs, and KernelSU assets")

    # download
    p_download = subparsers.add_parser(
        "download", help="Download matching KernelSU GKI kernel zip and Manager APK"
    )
    p_download.add_argument(
        "--kernel-version",
        help="Target kernel version (e.g. 6.6.66-android15 or 6.12.58-android16)",
    )
    p_download.add_argument(
        "--apk-only", action="store_true", help="Download only KernelSU Manager APK"
    )
    p_download.add_argument(
        "--kernel-only", action="store_true", help="Download only KernelSU GKI kernel zip"
    )
    # create-avd
    p_create = subparsers.add_parser("create-avd", help="Create a new AVD")
    p_create.add_argument("--name", default=DEFAULT_AVD_NAME, help="AVD name")
    p_create.add_argument(
        "--system-image",
        help="System image package id (e.g. system-images;android-36;google_apis_playstore;arm64-v8a)",
    )
    p_create.add_argument("--device", default=DEFAULT_DEVICE, help="Hardware device definition")
    p_create.add_argument(
        "--force", action="store_true", default=True, help="Overwrite existing AVD"
    )

    # patch-kernel
    p_patch = subparsers.add_parser(
        "patch-kernel", help="Replace kernel-ranchu in system image directory"
    )
    p_patch.add_argument(
        "--system-image-path",
        type=Path,
        help="Path to directory containing kernel-ranchu (auto-detected if omitted)",
    )
    p_patch.add_argument(
        "--kernel-source",
        type=Path,
        help="Path to Image file or AnyKernel3 zip (auto-detected if omitted)",
    )

    # cold-boot
    p_boot = subparsers.add_parser("cold-boot", help="Cold boot the emulator")
    p_boot.add_argument("--avd", default=DEFAULT_AVD_NAME, help="AVD name to boot")
    p_boot.add_argument("--headless", action="store_true", help="Run without UI window or audio")

    # wait-boot
    p_wait = subparsers.add_parser("wait-boot", help="Wait for emulator boot completion")
    p_wait.add_argument("--serial", help="Device serial (e.g. emulator-5554)")
    p_wait.add_argument("--timeout", type=float, default=180.0, help="Boot timeout in seconds")

    # install-apk
    p_apk = subparsers.add_parser("install-apk", help="Install KernelSU Manager APK to emulator")
    p_apk.add_argument("--apk", type=Path, help="Explicit APK path (auto-detected if omitted)")
    p_apk.add_argument("--serial", help="Device serial")

    # verify-root
    p_verify = subparsers.add_parser("verify-root", help="Verify root access via adb su")
    p_verify.add_argument("--serial", help="Device serial")

    # setup-all
    p_all = subparsers.add_parser(
        "setup-all", help="Complete end-to-end flow (create, patch, cold-boot, wait, apk, verify)"
    )
    p_all.add_argument("--avd", default=DEFAULT_AVD_NAME, help="AVD name")
    p_all.add_argument("--device", default=DEFAULT_DEVICE, help="Device definition")
    p_all.add_argument("--headless", action="store_true", help="Run emulator headless")
    p_all.add_argument("--timeout", type=float, default=180.0, help="Wait boot timeout in seconds")

    return parser


def emit_output(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    print(f"== {k} ({len(v)}) ==")
                    for item in v:
                        if isinstance(item, dict):
                            summary = ", ".join(f"{ik}={iv}" for ik, iv in item.items())
                            print(f"  - {summary}")
                        else:
                            print(f"  - {item}")
                elif isinstance(v, dict):
                    print(f"== {k} ==")
                    for subk, subv in v.items():
                        print(f"  {subk}: {subv}")
                else:
                    print(f"{k}: {v}")
        else:
            print(data)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    sdk_root = find_sdk_root()
    adb_bin = resolve_binary("adb", sdk_root)
    emulator_bin = resolve_binary("emulator", sdk_root)
    avdmanager_bin = resolve_binary("avdmanager", sdk_root)
    sdkmanager_bin = resolve_binary("sdkmanager", sdk_root)
    download_dir = args.download_dir.expanduser().resolve()

    sub = args.subcommand

    if sub == "list":
        sys_imgs = list_system_images(sdk_root)
        avds = list_avds(emulator_bin)
        assets = list_assets(download_dir)
        report: ListReport = {
            "sdk_root": str(sdk_root) if sdk_root else None,
            "avdmanager": avdmanager_bin,
            "sdkmanager": sdkmanager_bin,
            "emulator": emulator_bin,
            "adb": adb_bin,
            "system_images": sys_imgs,
            "avds": avds,
            "assets": assets,
        }
        emit_output(report, args.json)
        return 0

    if sub == "download":
        dl_apk = not args.kernel_only
        dl_kernel = not args.apk_only
        results: dict[str, Any] = {"download_dir": str(download_dir)}
        if dl_apk:
            try:
                apk_path = download_kernelsu_apk(download_dir)
                results["apk"] = str(apk_path)
            except Exception as exc:
                results["apk_error"] = str(exc)
        if dl_kernel:
            k_ver = args.kernel_version
            if not k_ver:
                def_target = get_default_system_image_path(sdk_root)
                if def_target:
                    k_ver = detect_target_kernel_version(def_target)
            if not k_ver:
                k_ver = "6.6.66-android15"
            results["kernel_version_requested"] = k_ver
            try:
                k_path = download_kernel_zip(k_ver, download_dir)
                results["kernel_zip"] = str(k_path)
            except Exception as exc:
                results["kernel_error"] = str(exc)
        has_err = "apk_error" in results or "kernel_error" in results
        emit_output(results, args.json)
        return 1 if has_err else 0

    if sub == "create-avd":
        if not avdmanager_bin:
            emit_output({"error": "avdmanager executable not found"}, args.json)
            return 1
        pkg = args.system_image
        if not pkg:
            # Pick modern default
            arch = "arm64-v8a" if platform.machine() in {"arm64", "aarch64"} else "x86_64"
            # Find an installed image first
            def_path = get_default_system_image_path(sdk_root)
            if def_path and sdk_root:
                rel = def_path.relative_to(sdk_root / "system-images")
                parts = rel.parts
                # rel is e.g. android-36/google_apis_playstore/arm64-v8a
                pkg = f"system-images;{parts[0]};{parts[1]};{parts[2]}"
            else:
                pkg = f"system-images;android-36;google_apis_playstore;{arch}"
        ok = create_avd(
            avdmanager_bin=avdmanager_bin,
            name=args.name,
            package_path=pkg,
            device=args.device,
            force=args.force,
        )
        create_res: CreateAvdResult = {
            "avd": args.name,
            "system_image_package": pkg,
            "device": args.device,
            "success": ok,
        }
        emit_output(create_res, args.json)
        return 0 if ok else 1

    if sub == "patch-kernel":
        target = args.system_image_path
        if not target:
            target = get_default_system_image_path(sdk_root)
        if not target:
            emit_output(
                {
                    "status": "error",
                    "error": "No system image directory with kernel-ranchu found",
                },
                args.json,
            )
            return 1
        result = patch_kernel(
            target_dir=target,
            download_dir=download_dir,
            explicit_source=args.kernel_source,
        )
        emit_output(result, args.json)
        return 0 if result["status"] == "patched" else 1

    if sub == "cold-boot":
        if not emulator_bin:
            emit_output({"error": "emulator executable not found"}, args.json)
            return 1
        proc = cold_boot(
            emulator_bin=emulator_bin,
            avd_name=args.avd,
            headless=args.headless,
        )
        boot_res: ColdBootResult = {
            "avd": args.avd,
            "pid": proc.pid,
            "status": "started",
            "headless": args.headless,
            "message": f"Emulator process {proc.pid} launched in background",
        }
        emit_output(boot_res, args.json)
        return 0

    if sub == "wait-boot":
        if not adb_bin:
            emit_output({"error": "adb executable not found"}, args.json)
            return 1
        wb_res = wait_boot(adb_bin, serial=args.serial, timeout=args.timeout)
        emit_output(wb_res, args.json)
        return 0 if wb_res["boot_completed"] else 1

    if sub == "install-apk":
        if not adb_bin:
            emit_output({"error": "adb executable not found"}, args.json)
            return 1
        apk = args.apk
        if not apk:
            try:
                apk = ensure_kernelsu_apk(download_dir)
            except Exception as exc:
                emit_output({"error": f"Failed to acquire KernelSU APK: {exc}"}, args.json)
                return 1
        apk_res = install_apk(adb_bin, apk, serial=args.serial)
        emit_output(apk_res, args.json)
        return 0 if apk_res["success"] else 1
    if sub == "verify-root":
        if not adb_bin:
            emit_output({"error": "adb executable not found"}, args.json)
            return 1
        v_res = verify_root(adb_bin, serial=args.serial)
        emit_output(v_res, args.json)
        return 0 if v_res["rooted"] else 1

    if sub == "setup-all":
        # Check binaries
        if not (adb_bin and emulator_bin and avdmanager_bin):
            missing = [
                k
                for k, v in [
                    ("adb", adb_bin),
                    ("emulator", emulator_bin),
                    ("avdmanager", avdmanager_bin),
                ]
                if not v
            ]
            emit_output(
                {"error": f"Missing required binaries: {', '.join(missing)}"},
                args.json,
            )
            return 1

        # 1. Patch kernel
        target = get_default_system_image_path(sdk_root)
        if not target:
            emit_output({"error": "Cannot find system image directory"}, args.json)
            return 1
        patch_res = patch_kernel(target, download_dir)
        if patch_res["status"] != "patched":
            emit_output({"step": "patch_kernel", "result": patch_res}, args.json)
            return 1

        # 2. Check if AVD exists, create if not
        if not sdk_root:
            emit_output({"error": "Cannot find Android SDK root"}, args.json)
            return 1

        existing_avds = list_avds(emulator_bin)
        avd_name = args.avd
        if avd_name not in existing_avds:
            rel = target.relative_to(sdk_root / "system-images")
            pkg = f"system-images;{rel.parts[0]};{rel.parts[1]};{rel.parts[2]}"
            create_ok = create_avd(
                avdmanager_bin=avdmanager_bin,
                name=avd_name,
                package_path=pkg,
                device=args.device,
                force=False,
            )
            if not create_ok:
                emit_output({"error": f"Failed to create AVD {avd_name}"}, args.json)
                return 1

        # 3. Cold boot
        proc = cold_boot(emulator_bin, avd_name, headless=args.headless)

        # 4. Wait boot
        wb_res = wait_boot(adb_bin, timeout=args.timeout)
        if not wb_res["boot_completed"]:
            emit_output({"step": "wait_boot", "result": wb_res}, args.json)
            return 1

        # 5. Install APK
        try:
            apk = ensure_kernelsu_apk(download_dir)
            apk_res = install_apk(adb_bin, apk, serial=wb_res["serial"])
        except Exception as exc:
            apk_res = {
                "apk": "",
                "serial": wb_res["serial"],
                "success": False,
                "output": str(exc),
            }
        # 6. Verify root
        vr_res = verify_root(adb_bin, serial=wb_res["serial"])

        final_report = {
            "patch": patch_res,
            "avd": avd_name,
            "boot": wb_res,
            "apk_install": apk_res,
            "verify_root": vr_res,
            "success": vr_res["rooted"],
        }
        emit_output(final_report, args.json)
        return 0 if vr_res["rooted"] else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
