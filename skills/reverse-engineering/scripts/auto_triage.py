#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "lief>=0.17",
#     "magika>=0.5.0",
#     "python-magic>=0.4.27",
# ]
# ///
"""
auto_triage.py - Fast signature scanner and runtime detection for binary artifacts.
Scans file headers, magic bytes, section names, and strings to identify compiler/runtime
signatures and recommend appropriate progressive disclosure references.
"""

import argparse
import collections
import hashlib
import json
import math
import mimetypes
import os
import shutil
import subprocess
import tarfile
import zipfile

import lief

# LIEF logs parse warnings to stderr; triage output must stay clean JSON.
lief.logging.disable()


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy sum(-p * log2(p)) for byte data."""
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_plain_text(data: bytes) -> bool:
    """Checks if a byte buffer looks like UTF-8 or ASCII plain text."""
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def get_magika_info(filepath: str) -> dict | None:
    """
    Returns AI/deep-learning file identification from Google Magika if available.
    """
    try:
        from magika import Magika  # type: ignore[import-not-found]
        m = Magika()
        res = m.identify_path(filepath)
        out = res.output
        return {
            "label": out.label,
            "mime_type": out.mime_type,
            "group": out.group,
            "description": out.description,
            "score": round(float(res.score), 4),
        }
    except Exception:
        return None


def get_magic_info(filepath: str) -> tuple[str | None, str | None]:
    """
    Returns (mime_type, description) using python-magic if available,
    falling back to `file -b` via subprocess.
    """
    mime_type: str | None = None
    description: str | None = None

    # Try python-magic first
    try:
        import magic  # type: ignore[import-not-found]
        try:
            mime_type = magic.from_file(filepath, mime=True)
        except Exception:
            mime_type = None
        try:
            description = magic.from_file(filepath)
        except Exception:
            description = None
    except ImportError:
        pass

    # Fallback to system `file -b` command
    if not mime_type or not description:
        file_cmd = shutil.which("file")
        if file_cmd:
            if not mime_type:
                try:
                    res = subprocess.run(
                        [file_cmd, "-b", "--mime-type", filepath],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        mime_type = res.stdout.strip().splitlines()[0].strip()
                except Exception:
                    pass

            if not description:
                try:
                    res = subprocess.run(
                        [file_cmd, "-b", filepath],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        description = res.stdout.strip().splitlines()[0].strip()
                except Exception:
                    pass

    return mime_type, description


def extract_architecture_from_description(desc: str | None) -> str | None:
    """Extracts architecture from a description string."""
    if not desc:
        return None
    d = desc.lower()
    if "x86-64" in d or "x86_64" in d or "amd64" in d or "x64" in d:
        return "x86_64"
    if "aarch64" in d or "arm64" in d:
        return "arm64"
    if "arm" in d:
        return "arm"
    if "80386" in d or "i386" in d or "x86" in d or "intel 80386" in d:
        return "x86"
    if "mips64" in d:
        return "MIPS64"
    if "mips" in d:
        return "MIPS"
    if "riscv64" in d or "risc-v 64" in d:
        return "riscv64"
    if "riscv" in d or "risc-v" in d:
        return "riscv"
    if "powerpc" in d or "ppc" in d:
        return "PowerPC"
    return None


# Architecture labels keyed by the header enums LIEF decodes.
ELF_ARCH = {
    lief.ELF.ARCH.I386: "x86",
    lief.ELF.ARCH.X86_64: "x86_64",
    lief.ELF.ARCH.ARM: "arm",
    lief.ELF.ARCH.AARCH64: "arm64",
    lief.ELF.ARCH.MIPS: "MIPS",
    lief.ELF.ARCH.RISCV: "riscv",
    lief.ELF.ARCH.PPC: "PowerPC",
    lief.ELF.ARCH.PPC64: "PowerPC64",
    lief.ELF.ARCH.SPARC: "SPARC",
}
PE_ARCH = {
    lief.PE.Header.MACHINE_TYPES.I386: "x86",
    lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
    lief.PE.Header.MACHINE_TYPES.ARM: "arm",
    lief.PE.Header.MACHINE_TYPES.ARM64: "arm64",
}
MACHO_ARCH = {
    lief.MachO.Header.CPU_TYPE.X86: "x86",
    lief.MachO.Header.CPU_TYPE.X86_64: "x86_64",
    lief.MachO.Header.CPU_TYPE.ARM: "arm",
    lief.MachO.Header.CPU_TYPE.ARM64: "arm64",
    lief.MachO.Header.CPU_TYPE.POWERPC: "PowerPC",
    lief.MachO.Header.CPU_TYPE.POWERPC64: "PowerPC64",
}


def parse_elf_architecture(filepath: str) -> str | None:
    """Reads ELF e_machine via LIEF (header and sections only; symbols, relocations, notes skipped)."""
    config = lief.ELF.ParserConfig()
    config.parse_dyn_symbols = False
    config.parse_symtab_symbols = False
    config.parse_relocations = False
    config.parse_symbol_versions = False
    config.parse_notes = False
    config.parse_overlay = False
    try:
        binary = lief.ELF.parse(filepath, config)
        if binary is None:
            return None
        return ELF_ARCH.get(binary.header.machine_type)
    except Exception:
        return None


def parse_pe_architecture(filepath: str) -> str | None:
    """Reads PE COFF Machine via LIEF (imports, exports, resources, relocations, signature skipped)."""
    config = lief.PE.ParserConfig()
    config.parse_imports = False
    config.parse_exports = False
    config.parse_rsrc = False
    config.parse_reloc = False
    config.parse_signature = False
    config.parse_exceptions = False
    try:
        binary = lief.PE.parse(filepath, config)
        if binary is None:
            return None
        return PE_ARCH.get(binary.header.machine)
    except Exception:
        return None


def parse_macho_architecture(filepath: str) -> str | None:
    """Reads Mach-O cputype via LIEF; returns "universal" for multi-slice fat binaries."""
    try:
        fat = lief.MachO.parse(filepath, lief.MachO.ParserConfig.quick)
        if fat is None or fat.size == 0:
            return None
        if fat.size > 1:
            return "universal"
        return MACHO_ARCH.get(fat.at(0).header.cpu_type)
    except Exception:
        return None


def inspect_zip_container(filepath: str, result: dict) -> bool:
    """
    Inspects ZIP archive contents (namelist, manifests) to classify:
    - Android APK
    - iOS IPA
    - Office OpenXML macro document
    - WebExtension / Browser Extension
    - Java JAR
    - Electron ASAR container
    Returns True if definitive package classification succeeded.
    """
    if not zipfile.is_zipfile(filepath):
        return False

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            names = set(zf.namelist())

            # 1. Android APK
            if "AndroidManifest.xml" in names or "classes.dex" in names:
                result["format"] = "Android APK"
                result["runtime"] = "JVM / Dalvik / Android"
                result["indicators"].append("Found AndroidManifest.xml or classes.dex inside ZIP package")
                result["recommended_reference"] = "references/01-static-architectures/managed-dotnet-jvm.md"
                result["category"] = "01-static-architectures"
                if not result.get("mime_type") or result.get("mime_type") == "application/zip":
                    result["mime_type"] = "application/vnd.android.package-archive"
                return True

            # 2. iOS IPA
            has_payload = any(n.startswith("Payload/") and n.endswith(".app/") for n in names) or any(
                n.startswith("Payload/") and "/Info.plist" in n for n in names
            )
            if has_payload or any(n.endswith(".app/Info.plist") for n in names):
                result["format"] = "iOS IPA"
                result["runtime"] = "Apple ObjC / Swift"
                result["indicators"].append("Found Payload/*.app and Info.plist inside iOS package")
                result["recommended_reference"] = "references/01-static-architectures/mobile-ios.md"
                result["category"] = "01-static-architectures"
                if not result.get("mime_type") or result.get("mime_type") == "application/zip":
                    result["mime_type"] = "application/x-ios-app"
                return True

            # 3. Office OpenXML macro document
            has_vba = (
                "vbaProject.bin" in names
                or "word/vbaProject.bin" in names
                or "xl/vbaProject.bin" in names
                or "ppt/vbaProject.bin" in names
            )
            if has_vba:
                result["format"] = "Office OpenXML (Macro-enabled)"
                result["runtime"] = "Office Document / VBA Macro"
                result["indicators"].append("Found embedded vbaProject.bin inside OpenXML package")
                result["recommended_reference"] = "references/01-static-architectures/script-nonpe-analysis.md"
                result["category"] = "01-static-architectures"
                if not result.get("mime_type") or result.get("mime_type") == "application/zip":
                    result["mime_type"] = "application/vnd.ms-office.vba"
                return True

            # 4. WebExtension / Browser Extension
            if "manifest.json" in names:
                try:
                    manifest_content = zf.read("manifest.json").decode("utf-8", errors="ignore")
                    if "manifest_version" in manifest_content:
                        result["format"] = "Browser Extension (ZIP/XPI)"
                        result["runtime"] = "Browser Extension"
                        result["indicators"].append("Found manifest.json with manifest_version in archive")
                        result["recommended_reference"] = "references/01-static-architectures/browser-extensions.md"
                        result["category"] = "01-static-architectures"
                        if not result.get("mime_type") or result.get("mime_type") == "application/zip":
                            result["mime_type"] = "application/x-web-extension"
                        return True
                except Exception:
                    pass

            # 5. Java JAR
            if "META-INF/MANIFEST.MF" in names or any(n.endswith(".class") for n in names):
                result["format"] = "Java JAR"
                result["runtime"] = "JVM / Dalvik / Android"
                result["indicators"].append("Found META-INF/MANIFEST.MF or .class files in archive")
                result["recommended_reference"] = "references/01-static-architectures/managed-dotnet-jvm.md"
                result["category"] = "01-static-architectures"
                if not result.get("mime_type") or result.get("mime_type") == "application/zip":
                    result["mime_type"] = "application/java-archive"
                return True

            # 6. Electron ASAR embedded in ZIP package
            if any(n.endswith("app.asar") or n.endswith(".asar") for n in names):
                result["format"] = "Electron Package (ASAR inside ZIP)"
                result["runtime"] = "Browser JS / WASM"
                result["indicators"].append("Found app.asar package inside archive")
                result["recommended_reference"] = "references/01-static-architectures/browser-js-wasm.md"
                result["category"] = "01-static-architectures"
                return True

    except Exception:
        return False

    return False


def inspect_tar_container(filepath: str, result: dict) -> bool:
    """Inspects TAR archive container (standard library tarfile)."""
    if not tarfile.is_tarfile(filepath):
        return False

    try:
        with tarfile.open(filepath, "r:*") as tf:
            names = tf.getnames()
            if any(n.endswith("app.asar") for n in names):
                result["format"] = "Electron Package (TAR)"
                result["runtime"] = "Browser JS / WASM"
                result["indicators"].append("Found app.asar inside tar archive")
                result["recommended_reference"] = "references/01-static-architectures/browser-js-wasm.md"
                result["category"] = "01-static-architectures"
                return True
            if any(n.endswith("AndroidManifest.xml") or n.endswith("classes.dex") for n in names):
                result["format"] = "Android Archive (TAR)"
                result["runtime"] = "JVM / Dalvik / Android"
                result["indicators"].append("Found Android components inside tar archive")
                result["recommended_reference"] = "references/01-static-architectures/managed-dotnet-jvm.md"
                result["category"] = "01-static-architectures"
                return True
            result["format"] = "TAR Archive"
            result["runtime"] = "Archive Container"
            result["indicators"].append("Recognized tar archive container")
            return True
    except Exception:
        return False


SURFACE_LIMIT = 30


def sha256_file(filepath: str) -> str:
    digest = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_surface(filepath: str) -> dict | None:
    """Bounded import/export summary for ELF, PE, and Mach-O (first slice of a fat file).

    Returns None for non-native files. A parse failure is reported, not hidden:
    Rule 1 needs either the overview or the recorded failure.
    """
    lief.logging.disable()
    try:
        if lief.is_macho(filepath):
            fat = lief.MachO.parse(filepath)
            binary = fat.at(0) if fat is not None and fat.size else None
        elif lief.is_elf(filepath) or lief.is_pe(filepath):
            binary = lief.parse(filepath)
        else:
            return None
    except Exception as exc:  # lief raises on truncated or hostile headers
        return {"error": f"lief parse failed: {exc}"}
    if binary is None:
        return {"error": "lief could not parse the headers"}

    imports = [f.name for f in binary.imported_functions if f.name]
    exports = [f.name for f in binary.exported_functions if f.name]
    if isinstance(binary, lief.PE.Binary):
        libraries = [lib.name for lib in binary.imports]
        delay = [lib.name for lib in binary.delay_imports] if binary.has_delay_imports else []
    else:
        # ELF yields names, Mach-O yields DylibCommand objects.
        libraries = [getattr(lib, "name", lib) for lib in binary.libraries]
        delay = []
    return {
        "libraries": libraries[:SURFACE_LIMIT],
        "delay_load_libraries": delay[:SURFACE_LIMIT],
        "import_count": len(imports),
        "export_count": len(exports),
        "imports_sample": imports[:SURFACE_LIMIT],
        "exports_sample": exports[:SURFACE_LIMIT],
        "truncated": len(imports) > SURFACE_LIMIT or len(exports) > SURFACE_LIMIT or len(libraries) > SURFACE_LIMIT,
    }


def triage_file(filepath: str) -> dict:
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}

    file_size = os.path.getsize(filepath)
    result = {
        "file": os.path.abspath(filepath),
        "size_bytes": file_size,
        "format": "Unknown",
        "mime_type": None,
        "description": None,
        "architecture": None,
        "confidence_score": 0.5,
        "magika": None,
        "runtime": "Unknown",
        "entropy": 0.0,
        "is_packed": False,
        "packer": None,
        "indicators": [],
        "recommended_reference": "references/01-static-architectures/native-cpp-abi.md",
        "category": "01-static-architectures",
    }

    # Fallback Layer 1: Google Magika AI/deep-learning file type detector
    # Primary detector: seeds format, mime_type, description, and confidence_score
    magika_info = get_magika_info(filepath)
    if magika_info:
        result["magika"] = magika_info
        if magika_info.get("mime_type"):
            result["mime_type"] = magika_info["mime_type"]
        if magika_info.get("description"):
            result["description"] = magika_info["description"]
        if magika_info.get("score") is not None:
            result["confidence_score"] = magika_info["score"]

        label = (magika_info.get("label") or "").lower()
        group = (magika_info.get("group") or "").lower()

        # Map Magika label/group to normalized format seed
        magika_format_map = {
            "elf": "ELF",
            "pebin": "PE",
            "macho": "Mach-O",
            "dex": "DEX",
            "apk": "Android APK",
            "jar": "Java JAR",
            "wasm": "WASM",
            "pcap": "PCAP",
            "pcapng": "PCAP",
            "gzip": "GZIP",
            "squashfs": "SquashFS",
            "crx": "CRX (Browser Extension)",
            "powershell": "PowerShell Script",
            "batch": "Windows Batch Script",
            "javascript": "Browser JS / Script",
            "typescript": "Browser JS / Script",
        }
        if label in magika_format_map:
            result["format"] = magika_format_map[label]
        elif group == "executable":
            result["format"] = "Native Executable"
        elif group == "archive":
            result["format"] = "Archive Container"

        result["indicators"].append(
            f"Magika AI classification: {magika_info.get('label')} (score: {magika_info.get('score')})"
        )

    # Fallback Layer 2: python-magic with fallback to system `file -b` via subprocess
    magic_mime, magic_desc = get_magic_info(filepath)
    if magic_mime and not result["mime_type"]:
        result["mime_type"] = magic_mime
    if magic_desc:
        if not result["description"]:
            result["description"] = magic_desc
        inferred_arch = extract_architecture_from_description(magic_desc)
        if inferred_arch:
            result["architecture"] = inferred_arch

    # Fallback Layer 3: Python standard library mimetypes (MIME type hint if still missing)
    guessed_type, _ = mimetypes.guess_type(filepath)
    if guessed_type and not result["mime_type"]:
        result["mime_type"] = guessed_type

    # Read binary samples for analysis
    try:
        with open(filepath, "rb") as f:
            header = f.read(4096)
            f.seek(0)
            head_sample = f.read(min(file_size, 1024 * 1024))
            tail_sample = b""
            if file_size > 1024 * 1024:
                f.seek(max(0, file_size - 512 * 1024))
                tail_sample = f.read(512 * 1024)
            sample_data = head_sample + tail_sample

            # Layer 5: Shannon entropy & packer detection
            result["entropy"] = calculate_entropy(sample_data)

            # Extract architecture from headers if native binary
            if header.startswith(b"\x7fELF"):
                elf_arch = parse_elf_architecture(filepath)
                if elf_arch:
                    result["architecture"] = elf_arch
            elif header.startswith(b"MZ"):
                pe_arch = parse_pe_architecture(filepath)
                if pe_arch:
                    result["architecture"] = pe_arch
            elif (
                header.startswith(b"\xca\xfe\xba\xbe")
                or header.startswith(b"\xcf\xfa\xed\xfe")
                or header.startswith(b"\xce\xfa\xed\xfe")
                or header.startswith(b"\xfe\xed\xfa\xcf")
                or header.startswith(b"\xfe\xed\xfa\xce")
            ):
                macho_arch = parse_macho_architecture(filepath)
                if macho_arch and macho_arch != "universal":
                    result["architecture"] = macho_arch
    except Exception as e:
        result["error"] = f"Failed to read file: {e}"
        return result

    # Check Electron ASAR format (magic header: 4-byte size + JSON header containing files)
    if len(header) >= 16 and header[4:12] == b"\x04\x00\x00\x00\x00\x00\x00\x00" and b'"files":{' in header:
        result["format"] = "Electron ASAR"
        result["runtime"] = "Browser JS / WASM"
        result["indicators"].append("Found Electron ASAR package header")
        result["recommended_reference"] = "references/01-static-architectures/browser-js-wasm.md"
        result["category"] = "01-static-architectures"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-asar"
        return result

    # Fallback Layer 4: Deep container inspection (zipfile & tarfile disambiguating APK, IPA, Office, JAR, Extension, ASAR)
    if inspect_zip_container(filepath, result):
        return result

    if inspect_tar_container(filepath, result):
        return result

    # Fallback Layer 5: Structural byte magic & compiler heuristics

    if header.startswith(b"\x7fELF"):
        result["format"] = "ELF"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-executable"
    elif header.startswith(b"MZ"):
        result["format"] = "PE"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-dosexec"
    elif header.startswith(b"\xca\xfe\xba\xbe"):
        # Disambiguate between Java .class and Fat Mach-O
        if len(header) >= 8:
            # Dispatch only: a Java class stores its major version where a fat
            # Mach-O stores a small big-endian slice count.
            major_ver = int.from_bytes(header[6:8], "big")
            if 45 <= major_ver <= 70:
                result["format"] = "Java Class"
                if not result["mime_type"]:
                    result["mime_type"] = "application/java-vm"
            else:
                result["format"] = "Mach-O (Fat)"
                if not result["mime_type"]:
                    result["mime_type"] = "application/x-mach-binary"
        else:
            result["format"] = "Java Class"
            if not result["mime_type"]:
                result["mime_type"] = "application/java-vm"
    elif (
        header.startswith(b"\xcf\xfa\xed\xfe")
        or header.startswith(b"\xce\xfa\xed\xfe")
        or header.startswith(b"\xfe\xed\xfa\xcf")
        or header.startswith(b"\xfe\xed\xfa\xce")
    ):
        result["format"] = "Mach-O"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-mach-binary"
    elif header.startswith(b"dex\n"):
        result["format"] = "DEX"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-dex"
    elif header.startswith(b"PK\x03\x04"):
        if filepath.lower().endswith((".docm", ".xlsm", ".pptm")):
            result["format"] = "Office OpenXML (Macro-enabled)"
            result["runtime"] = "Office Document / VBA Macro"
            result["indicators"].append("Found macro-enabled Office XML package (.docm/.xlsm/.pptm)")
            result["recommended_reference"] = "references/01-static-architectures/script-nonpe-analysis.md"
            result["category"] = "01-static-architectures"
            return result
        result["format"] = "ZIP/Package"
    elif header.startswith(b"\xd0\xcf\x11\xe0"):
        result["format"] = "OLE2 Compound Document"
        result["runtime"] = "Office Document / VBA Macro"
        result["indicators"].append("Found OLE2 compound document magic (legacy Office .doc/.xls/.ppt)")
        result["recommended_reference"] = "references/01-static-architectures/script-nonpe-analysis.md"
        result["category"] = "01-static-architectures"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-ole-storage"
        return result
    elif header.startswith(b"Cr24"):
        result["format"] = "CRX (Browser Extension)"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-chrome-extension"
    elif header.startswith(b"\x1f\x8b"):
        result["format"] = "GZIP"
        if not result["mime_type"]:
            result["mime_type"] = "application/gzip"
    elif header.startswith(b"\x00asm"):
        result["format"] = "WASM"
        if not result["mime_type"]:
            result["mime_type"] = "application/wasm"
    elif header.startswith(b"\xc6\x1f\xbc\x03"):
        result["format"] = "Hermes Bytecode"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-hermes-bytecode"
    elif header[:4] in [b"hsqs", b"sqsh", b"qshs", b"shsq"]:
        result["format"] = "SquashFS"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-squashfs-image"
    elif header.startswith(b"\x27\x05\x19\x56"):
        result["format"] = "U-Boot Image"
        if not result["mime_type"]:
            result["mime_type"] = "application/x-u-boot-image"
    elif (
        header.startswith(b"\xd4\xc3\xb2\xa1")
        or header.startswith(b"\xa1\xb2\xc3\xd4")
        or header.startswith(b"\x0a\x0d\x0d\x0a")
    ):
        result["format"] = "PCAP"
        if not result["mime_type"]:
            result["mime_type"] = "application/vnd.tcpdump.pcap"
    elif is_plain_text(head_sample):
        result["format"] = "Text/Script"
        if not result["mime_type"]:
            result["mime_type"] = "text/plain"

    # Avoid matching internal binary signatures inside plain text / source scripts (unless manifest.json)
    if result["format"] == "Text/Script":
        lower_path = filepath.lower()
        if os.path.basename(filepath) == "manifest.json" and b'"manifest_version"' in sample_data:
            result["runtime"] = "Browser Extension (Manifest)"
            result["indicators"].append("Found manifest.json with manifest_version")
            result["recommended_reference"] = "references/01-static-architectures/browser-extensions.md"
            result["category"] = "01-static-architectures"
            return result
        if lower_path.endswith(".ps1"):
            result["runtime"] = "PowerShell Script"
            result["indicators"].append("Found PowerShell script extension (.ps1)")
            result["recommended_reference"] = "references/01-static-architectures/script-nonpe-analysis.md"
            result["category"] = "01-static-architectures"
            return result
        if lower_path.endswith((".bat", ".cmd")):
            result["runtime"] = "Windows Batch Script"
            result["indicators"].append("Found Windows Batch script extension (.bat/.cmd)")
            result["recommended_reference"] = "references/01-static-architectures/script-nonpe-analysis.md"
            result["category"] = "01-static-architectures"
            return result
        if lower_path.endswith((".vbs", ".vbe", ".hta", ".wsf")):
            result["runtime"] = "Windows Script Host (VBS/HTA/WSF)"
            result["indicators"].append("Found Windows Script Host extension (.vbs/.vbe/.hta/.wsf)")
            result["recommended_reference"] = "references/01-static-architectures/script-nonpe-analysis.md"
            result["category"] = "01-static-architectures"
            return result
        if lower_path.endswith((".js", ".mjs", ".ts")):
            result["runtime"] = "Browser JS / Script"
            result["recommended_reference"] = "references/01-static-architectures/browser-js-wasm.md"
        else:
            result["runtime"] = "Plain Text / Script"
            result["recommended_reference"] = "references/01-static-architectures/native-cpp-abi.md"
        return result

    # Browser Extensions (.crx / Cr24 header)
    if result["format"] == "CRX (Browser Extension)" or filepath.endswith(".crx"):
        result["format"] = "CRX (Browser Extension)"
        result["runtime"] = "Browser Extension"
        result["indicators"].append("Found CRX package magic header or extension")
        result["recommended_reference"] = "references/01-static-architectures/browser-extensions.md"
        result["category"] = "01-static-architectures"
        return result

    # Hermes Bytecode (React Native)
    if result["format"] == "Hermes Bytecode" or filepath.endswith(".hbc"):
        result["format"] = "Hermes Bytecode"
        result["runtime"] = "React Native (Hermes Bytecode)"
        result["indicators"].append("Found Hermes bytecode magic header or .hbc extension")
        result["recommended_reference"] = "references/01-static-architectures/react-native-hermes.md"
        result["category"] = "01-static-architectures"
        return result

    # Flutter / Dart AOT check
    if (
        b"libapp.so" in sample_data
        or b"libflutter.so" in sample_data
        or b"isolate_snapshot_data" in sample_data
        or b"vm_snapshot_data" in sample_data
        or b"kDartVmSnapshotData" in sample_data
        or b"Dart VM version" in sample_data
        or os.path.basename(filepath) in ["libapp.so", "libflutter.so"]
    ):
        result["runtime"] = "Flutter / Dart AOT"
        result["indicators"].append("Found Flutter/Dart snapshot or runtime engine markers")
        result["recommended_reference"] = "references/01-static-architectures/flutter-dart.md"
        result["category"] = "01-static-architectures"
        return result

    # Binary container targets (ELF, PE, Mach-O)
    is_native_binary = result["format"] in ["ELF", "PE", "Mach-O", "Mach-O (Fat)"]

    # Layer 5: Packer and High Entropy Detection for Native Binaries
    if is_native_binary:
        packer_signatures = [
            (b"UPX0", "UPX"),
            (b"UPX1", "UPX"),
            (b"UPX2", "UPX"),
            (b"UPX!", "UPX"),
            (b".vmp0", "VMProtect"),
            (b".vmp1", "VMProtect"),
            (b".vmp2", "VMProtect"),
            (b"VMProtect", "VMProtect"),
            (b".themida", "Themida"),
            (b"Themida", "Themida"),
            (b".aspack", "ASPack"),
            (b"ASPack", "ASPack"),
            (b".enigma", "Enigma"),
            (b"Enigma", "Enigma"),
            (b".mpress1", "MPRESS"),
            (b".mpress2", "MPRESS"),
            (b"MPRESS", "MPRESS"),
            (b"Petite", "Petite"),
            (b"PECompact", "PECompact"),
            (b"MEW", "MEW"),
        ]

        for sig, name in packer_signatures:
            if sig in sample_data:
                result["is_packed"] = True
                result["packer"] = name
                result["indicators"].append(f"Found {name} packer signature/section ({sig.decode(errors='replace')})")
                break

        # Flag high entropy binaries as packed/encrypted even without explicit signature
        if result["entropy"] > 7.2:
            result["is_packed"] = True
            if not result["packer"]:
                result["packer"] = "Generic / High-Entropy Crypter"
            result["indicators"].append(f"High Shannon entropy detected ({result['entropy']} > 7.2)")

        if result["is_packed"] or result["entropy"] > 7.2:
            result["runtime"] = f"Packed / Armored ({result['packer']})"
            result["recommended_reference"] = "references/02-dynamic-instrumentation/unpacking-memory-dump.md"
            result["category"] = "02-dynamic-instrumentation"
            return result

    # Go check (restricted to native binaries or explicit Go build IDs)
    if is_native_binary and (
        b".gopclntab" in sample_data
        or b"runtime.morestack" in sample_data
        or b"Go build ID:" in sample_data
    ):
        result["runtime"] = "Go"
        result["indicators"].append("Found .gopclntab / runtime.morestack")
        result["recommended_reference"] = "references/01-static-architectures/native-golang.md"
        result["category"] = "01-static-architectures"
        return result

    # Rust check (restricted to native binaries)
    if is_native_binary and (
        b"rust_eh_personality" in sample_data
        or b"core::panicking" in sample_data
        or b"library/std/src" in sample_data
        or b".dep-v0" in sample_data
    ):
        result["runtime"] = "Rust"
        result["indicators"].append("Found rust_eh_personality / core::panicking")
        result["recommended_reference"] = "references/01-static-architectures/native-rust.md"
        result["category"] = "01-static-architectures"
        return result

    # .NET CLR check (PE binaries with CLI metadata)
    if result["format"] == "PE" and (
        b"_CorExeMain" in sample_data
        or b"_CorDllMain" in sample_data
        or b"BSJB" in sample_data
    ):
        result["runtime"] = ".NET / CLR"
        result["indicators"].append("Found .NET metadata marker BSJB / _CorExeMain")
        result["recommended_reference"] = "references/01-static-architectures/managed-dotnet-jvm.md"
        result["category"] = "01-static-architectures"
        return result

    # Dalvik DEX / Android / Java Class
    if (
        result["format"] in ["DEX", "Java Class"]
        or b"classes.dex" in sample_data
        or b"META-INF/MANIFEST.MF" in sample_data
    ):
        result["runtime"] = "JVM / Dalvik / Android"
        result["indicators"].append("Found DEX magic, Java .class, or Android package markers")
        result["recommended_reference"] = "references/01-static-architectures/managed-dotnet-jvm.md"
        result["category"] = "01-static-architectures"
        return result

    # Unity IL2CPP check
    if (
        b"Il2Cpp" in sample_data
        or b"libil2cpp.so" in sample_data
        or b"global-metadata.dat" in sample_data
        or header.startswith(b"\xaf\x1b\xb1\xfa")
        or header.startswith(b"\xaf\x1b\xb1\xea")
    ):
        result["runtime"] = "Unity IL2CPP"
        result["indicators"].append("Found Unity IL2CPP strings or global-metadata signature")
        if header.startswith(b"\xaf\x1b\xb1\xea"):
            result["indicators"].append(
                "Variant metadata magic AF 1B B1 EA. The version word still applies. "
                "A sane version with section ranges past EOF is a header permutation, "
                "not a failed magic patch. See unity-il2cpp.md section 4.5."
            )
        result["recommended_reference"] = "references/01-static-architectures/unity-il2cpp.md"
        result["category"] = "01-static-architectures"
        return result

    # WebAssembly / Browser JS
    if (
        result["format"] == "WASM"
        or b"webpackJsonp" in sample_data
        or b"sourceMappingURL=" in sample_data
        or filepath.endswith(".js")
    ):
        result["runtime"] = "Browser JS / WASM"
        result["indicators"].append("Found WASM binary or JavaScript bundle structure")
        result["recommended_reference"] = "references/01-static-architectures/browser-js-wasm.md"
        result["category"] = "01-static-architectures"
        return result

    # Firmware / IoT
    if (
        result["format"] in ["SquashFS", "U-Boot Image"]
        or b"u-boot" in sample_data.lower()
        or b"busybox" in sample_data.lower()
    ):
        result["runtime"] = "Firmware / Embedded Linux"
        result["indicators"].append("Found embedded bootloader or SquashFS markers")
        result["recommended_reference"] = "references/01-static-architectures/firmware-iot.md"
        result["category"] = "01-static-architectures"
        return result

    # Apple iOS / Mach-O with ObjC/Swift (strictly require Apple runtime markers or .ipa)
    if (
        b"__objc_classlist" in sample_data
        or b"_swift_release" in sample_data
        or filepath.endswith(".ipa")
        or b"/System/Library/Frameworks" in sample_data
    ):
        result["runtime"] = "Apple ObjC / Swift"
        result["indicators"].append("Found Objective-C / Swift runtime markers")
        result["recommended_reference"] = "references/01-static-architectures/mobile-ios.md"
        result["category"] = "01-static-architectures"
        return result

    # Network PCAP
    if (
        result["format"] == "PCAP"
        or filepath.endswith(".pcap")
        or filepath.endswith(".pcapng")
    ):
        result["runtime"] = "Network Capture"
        result["indicators"].append("Found PCAP network packet capture header")
        result["recommended_reference"] = "references/03-objectives/protocol-recovery.md"
        result["category"] = "03-objectives"
        return result

    # Standard C / C++ Default (ELF, PE, Mach-O)
    # Heavily obfuscated / OLLVM flattened binaries
    if is_native_binary and (
        b"ollvm" in sample_data.lower()
        or b"hikari" in sample_data.lower()
        or b"goron" in sample_data.lower()
        or b"armariris" in sample_data.lower()
        or b"obfuscator" in sample_data.lower()
        or b"flattening" in sample_data.lower()
    ):
        result["runtime"] = "Obfuscated / OLLVM Flattened Native"
        result["indicators"].append("Found OLLVM/Hikari obfuscation signatures or symbols")
        result["recommended_reference"] = "references/01-static-architectures/deobfuscation-anti-analysis.md"
        result["category"] = "01-static-architectures"
        return result

    if is_native_binary:
        result["runtime"] = "Native C/C++"
        result["indicators"].append("Native compiled binary (x86/ARM/MIPS)")
        result["recommended_reference"] = "references/01-static-architectures/native-cpp-abi.md"
        result["category"] = "01-static-architectures"

    return result


def main():
    parser = argparse.ArgumentParser(description="Classify an artifact and name the matching reference. Prints JSON.")
    parser.add_argument("artifact", help="binary, package, firmware image, or archive to triage")
    parser.add_argument("--json", action="store_true", help="accepted for compatibility; output is always JSON")
    args = parser.parse_args()
    res = triage_file(args.artifact)
    if "error" not in res:
        res["sha256"] = sha256_file(args.artifact)
        surface = binary_surface(args.artifact)
        if surface is not None:
            res["surface"] = surface
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
