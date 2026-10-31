#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pyelftools>=0.31",
# ]
# ///
"""Deterministic, read-only ELF reconnaissance for static analysis.

Never executes, loads, emulates, or debugs the target and never contacts
anything it contains. Reads file bytes only; headers, sections, segments, and
symbols are parsed with pyelftools.

Usage:
  uv run scripts/elf_triage.py target.bin
  uv run scripts/elf_triage.py target.bin --find '^(main|decrypt_payload|key)$'
  uv run scripts/elf_triage.py target.bin --dump encrypted_payload,key
  uv run scripts/elf_triage.py target.bin --xor encrypted_payload --key key
  uv run scripts/elf_triage.py target.bin --xor encrypted_payload --key-hex deadbeef...

Exit codes: 0 success, 2 unreadable/not ELF/missing object.
"""

import argparse
import collections
import io
import math
import re
import sys

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

# pyelftools decodes enum fields to names ("ET_EXEC", "PT_LOAD", ...) and
# leaves values it does not know as plain ints.
ET = {"ET_REL": "REL", "ET_EXEC": "EXEC (non-PIE)", "ET_DYN": "DYN (PIE/shared)", "ET_CORE": "CORE"}
MACH = {
    "EM_386": "i386",
    "EM_ARM": "ARM",
    "EM_X86_64": "x86-64",
    "EM_AARCH64": "AArch64",
    "EM_MIPS": "MIPS",
    "EM_PPC": "PowerPC",
    "EM_PPC64": "PowerPC64",
    "EM_RISCV": "RISC-V",
}


def short(value, prefix):
    """Display name for a decoded enum: drop the prefix, hex for unknown ints."""
    if isinstance(value, str):
        return value[len(prefix) :] if value.startswith(prefix) else value
    return hex(value)


def die(msg):
    sys.stderr.write("elf_triage: %s\n" % msg)
    sys.exit(2)


class Elf:
    def __init__(self, path):
        try:
            self.data = open(path, "rb").read()
        except OSError as exc:
            die("cannot read %s: %s" % (path, exc))
        if self.data[:4] != b"\x7fELF":
            die("%s is not an ELF file" % path)
        self.path = path
        try:
            elf = ELFFile(io.BytesIO(self.data))
            self.bits = elf.elfclass
            self.little_endian = elf.little_endian
            self.e_type = elf.header["e_type"]
            self.e_machine = elf.header["e_machine"]
            self.entry = elf.header["e_entry"]
            self.sections = self._sections(elf)
            self.phdrs = self._phdrs(elf)
            self.symtab = self._symbols(elf)
        except ELFError as exc:
            die("%s is not a valid ELF file: %s" % (path, exc))
        self.shnum = len(self.sections)
        self.phnum = len(self.phdrs)

    def _sections(self, elf):
        out = []
        for sec in elf.iter_sections():
            h = sec.header
            out.append(
                {
                    "sname": sec.name,
                    "type": h["sh_type"],
                    "flags": h["sh_flags"],
                    "addr": h["sh_addr"],
                    "offset": h["sh_offset"],
                    "size": h["sh_size"],
                }
            )
        return out

    def _phdrs(self, elf):
        out = []
        for seg in elf.iter_segments():
            h = seg.header
            out.append(
                {
                    "type": h["p_type"],
                    "flags": h["p_flags"],
                    "offset": h["p_offset"],
                    "vaddr": h["p_vaddr"],
                    "filesz": h["p_filesz"],
                    "memsz": h["p_memsz"],
                }
            )
        return out

    def _symbols(self, elf):
        symtab = next(
            (
                s
                for s in elf.iter_sections()
                if s["sh_type"] == "SHT_SYMTAB" and isinstance(s, SymbolTableSection)
            ),
            None,
        )
        if not symtab or not symtab["sh_entsize"]:
            return []
        out = []
        for sym in symtab.iter_symbols():
            out.append(
                {
                    "name": sym.name,
                    "type": sym["st_info"]["type"],
                    "bind": sym["st_info"]["bind"],
                    # Special indexes (SHN_UNDEF/ABS/COMMON) decode to names.
                    "shndx": sym["st_shndx"],
                    "value": sym["st_value"],
                    "size": sym["st_size"],
                }
            )
        return out

    def section_for(self, sym):
        if not self.file_backed(sym):
            die("symbol %r is not in a file-backed section" % sym["name"])
        return self.sections[sym["shndx"]]

    def symbol_bytes(self, sym):
        sec = self.section_for(sym)
        start = sec["offset"] + (sym["value"] - sec["addr"])
        if start < 0 or start + sym["size"] > len(self.data):
            die("symbol %r bytes fall outside the file" % sym["name"])
        return self.data[start : start + sym["size"]], start

    def file_backed(self, sym):
        idx = sym["shndx"]
        # SHN_ABS, SHN_COMMON, and SHN_UNDEF are not section indexes.
        return isinstance(idx, int) and 0 < idx < len(self.sections)

    def find(self, name=None, rx=None):
        out = []
        for sym in self.symtab:
            if not self.file_backed(sym):
                continue
            if name is not None and sym["name"] != name:
                continue
            if rx is not None and not rx.search(sym["name"]):
                continue
            out.append(sym)
        return out


def projection(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def printable_ratio(b):
    return sum(1 for x in b if 32 <= x < 127) / len(b) if b else 0.0


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(b).values())


def report(elf):
    d = elf.data
    print("== %s ==" % elf.path)
    print(
        "format      ELF%d %s %s, %s"
        % (
            elf.bits,
            "LE" if elf.little_endian else "BE",
            MACH.get(elf.e_machine, short(elf.e_machine, "")),
            ET.get(elf.e_type, str(elf.e_type)),
        )
    )
    print("file size   0x%x bytes" % len(d))
    print(
        "entry       0x%x   sections=%d  phdrs=%d  symbols=%d"
        % (elf.entry, elf.shnum, elf.phnum, len(elf.symtab))
    )

    loads = [p for p in elf.phdrs if p["type"] == "PT_LOAD"]
    if loads:
        deltas = sorted({p["vaddr"] - p["offset"] for p in loads})
        print("LOAD deltas %s" % ", ".join("0x%x" % x for x in deltas))
        if len(deltas) > 1:
            print(
                "  NOTE: more than one delta: translate per section with "
                "file_offset = sh_offset + (vma - sh_addr)"
            )
        for sec in elf.sections:
            if (
                sec["sname"] in (".text", ".rodata", ".data", ".data.rel.ro", ".init_array")
                and sec["size"]
            ):
                print(
                    "  %-12s VMA 0x%-8x file 0x%-7x delta 0x%x"
                    % (sec["sname"], sec["addr"], sec["offset"], sec["addr"] - sec["offset"])
                )

    for p in elf.phdrs:
        print(
            "  PH %-10s off=0x%-7x vaddr=0x%-8x filesz=0x%-7x flags=%d"
            % (short(p["type"], "PT_"), p["offset"], p["vaddr"], p["filesz"], p["flags"])
        )
    stack = next((p for p in elf.phdrs if p["type"] == "PT_GNU_STACK"), None)
    if stack:
        print(
            "  GNU_STACK flags=%d%s"
            % (stack["flags"], " (RWX/executable stack)" if stack["flags"] == 7 else "")
        )

    print("\n-- sections (name addr off size type) --")
    for sec in elf.sections:
        if sec["sname"] in (
            ".text",
            ".rodata",
            ".data",
            ".bss",
            ".init_array",
            ".fini_array",
            ".data.rel.ro",
            ".got",
            ".plt",
        ):
            print(
                "  %-12s addr=0x%-8x off=0x%-7x size=0x%-7x %s"
                % (
                    sec["sname"],
                    sec["addr"],
                    sec["offset"],
                    sec["size"],
                    short(sec["type"], "SHT_"),
                )
            )

    print("\n-- selected symbols --")
    seen = False
    for name in ("_start", "main", "__libc_start_main"):
        for sym in elf.find(name=name):
            print(
                "  %-24s %-8s value=0x%-8x size=0x%x"
                % (sym["name"], short(sym["type"], "STT_"), sym["value"], sym["size"])
            )
            seen = True
    if not seen:
        print("  (none matched; use --find REGEX)")
    print(
        "  use --find REGEX for application symbols; globals are not "
        "grouped under the source-file stt_file entry"
    )


def report_find(elf, pattern):
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        die("bad --find regex: %s" % exc)
    hits = elf.find(rx=rx)
    print("-- symbols matching %r (%d) --" % (pattern, len(hits)))
    for sym in hits:
        sec = elf.section_for(sym)
        print(
            "  %-36s %-8s %-10s value=0x%-8x size=0x%-4x file=0x%x"
            % (
                sym["name"],
                short(sym["type"], "STT_"),
                sec["sname"],
                sym["value"],
                sym["size"],
                sec["offset"] + (sym["value"] - sec["addr"]),
            )
        )


def report_dump(elf, names):
    print("-- named OBJECT bytes --")
    for name in names:
        syms = [s for s in elf.find(name=name) if s["type"] == "STT_OBJECT"]
        if not syms:
            print("  %-28s MISSING (not an OBJECT symbol)" % name)
            continue
        sym = syms[0]
        raw, foff = elf.symbol_bytes(sym)
        shown = raw if len(raw) <= 128 else raw[:128]
        print(
            "  %-28s addr=0x%-8x off=0x%-7x size=0x%-4x %s%s"
            % (
                sym["name"],
                sym["value"],
                foff,
                sym["size"],
                shown.hex(),
                "..." if len(raw) > 128 else "",
            )
        )


def report_xor(elf, blob_name, key_name, key_hex):
    blobs = [s for s in elf.find(name=blob_name) if s["type"] == "STT_OBJECT"]
    if not blobs:
        die("no OBJECT symbol named %r" % blob_name)
    blob = blobs[0]
    raw, foff = elf.symbol_bytes(blob)
    if key_hex:
        try:
            key = bytes.fromhex(key_hex.replace(" ", ""))
        except ValueError as exc:
            die("bad --key-hex: %s" % exc)
        key_src = "--key-hex"
    else:
        keys = [s for s in elf.find(name=key_name or "") if s["type"] == "STT_OBJECT"]
        if not keys:
            die("no OBJECT symbol named %r (pass --key-hex)" % key_name)
        key, key_off = elf.symbol_bytes(keys[0])
        key_src = "%s @0x%x" % (key_name, key_off)
    if not key:
        die("empty key")
    dec = bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw)))
    print(
        "blob        %s addr=0x%x file_off=0x%x size=%d"
        % (blob_name, blob["value"], foff, len(raw))
    )
    print("key         %s (%d bytes): %s" % (key_src, len(key), key.hex()))
    print("cipher_hex  %s" % raw.hex())
    print("decoded_hex %s" % dec.hex())
    print("decoded_asc %s" % projection(dec))
    print("printable   %.2f   entropy %.2f" % (printable_ratio(dec), entropy(dec)))
    print(
        "syscall?    0f=%s  0f05=%s  cd80=%s"
        % (b"\x0f" in dec, b"\x0f\x05" in dec, b"\xcd\x80" in dec)
    )
    if len(raw) % len(key) == 0 and len(raw) >= 2 * len(key):
        b0 = raw[: len(key)]
        for blk in range(1, len(raw) // len(key)):
            cb = raw[blk * len(key) : (blk + 1) * len(key)]
            deltas = {a ^ b for a, b in zip(cb, b0)}
            print(
                "block%d^block0 %s"
                % (blk, "constant 0x%02x" % deltas.pop() if len(deltas) == 1 else "varies")
            )
    print(
        "classification aid: printable high + no syscall bytes -> text; "
        "syscall bytes + plausible flow -> code; neither -> data blob"
    )


def main():
    ap = argparse.ArgumentParser(description="read-only ELF triage")
    ap.add_argument("path")
    ap.add_argument("--find", metavar="REGEX")
    ap.add_argument("--dump", metavar="NAME[,NAME]")
    ap.add_argument("--xor", metavar="BLOB")
    ap.add_argument("--key", metavar="KEY")
    ap.add_argument("--key-hex")
    args = ap.parse_args()
    elf = Elf(args.path)
    if args.xor:
        report_xor(elf, args.xor, args.key, args.key_hex)
    elif args.dump:
        report_dump(elf, [n.strip() for n in args.dump.split(",") if n.strip()])
    elif args.find:
        report_find(elf, args.find)
    else:
        report(elf)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
