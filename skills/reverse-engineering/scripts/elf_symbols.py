#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pyelftools>=0.31",
# ]
# ///
"""Read-only ELF symbol span and file-symbol report.

Prints every FUNC/OBJECT in an address window and every STT_FILE name that is
not a .o runtime object. Never executes or loads the target. Sections and
symbols are parsed with pyelftools.

Usage:
  uv run scripts/elf_symbols.py target.bin
  uv run scripts/elf_symbols.py target.bin --span 0x401100 0x401800

Exit codes: 0 success, 2 unreadable/not ELF/bad span.
"""

import argparse
import sys

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def die(msg):
    sys.stderr.write("elf_symbols: %s\n" % msg)
    sys.exit(2)


def parse_int(text):
    try:
        return int(text, 0)
    except ValueError:
        die("bad address %r" % text)


def load(path):
    try:
        f = open(path, "rb")
    except OSError as exc:
        die("cannot read %s: %s" % (path, exc))
    with f:
        if f.read(4) != b"\x7fELF":
            die("%s is not an ELF file" % path)
        try:
            elf = ELFFile(f)
            if not elf.num_sections():
                die("%s has no section headers" % path)
            sections = [
                {"addr": sec["sh_addr"], "offset": sec["sh_offset"]} for sec in elf.iter_sections()
            ]
            return sections, symbols(elf)
        except ELFError as exc:
            die("%s is not a valid ELF file: %s" % (path, exc))


def symbols(elf):
    symtab = next(
        (
            s
            for s in elf.iter_sections()
            if s["sh_type"] == "SHT_SYMTAB" and isinstance(s, SymbolTableSection)
        ),
        None,
    )
    if not symtab or not symtab["sh_entsize"]:
        die("no symbol table")
    out = []
    for sym in symtab.iter_symbols():
        out.append(
            {
                "name": sym.name,
                "type": sym["st_info"]["type"],
                # Special indexes (SHN_UNDEF/ABS/COMMON) decode to names.
                "shndx": sym["st_shndx"],
                "value": sym["st_value"],
                "size": sym["st_size"],
            }
        )
    return out


STT = {"STT_OBJECT": "OBJECT", "STT_FUNC": "FUNC", "STT_FILE": "FILE"}


def file_backed(sym, sections):
    idx = sym["shndx"]
    return isinstance(idx, int) and 0 < idx < len(sections)


def main():
    ap = argparse.ArgumentParser(description="read-only ELF symbol span")
    ap.add_argument("path")
    ap.add_argument("--span", nargs=2, metavar=("START", "END"))
    args = ap.parse_args()
    sections, syms = load(args.path)
    print("-- STT_FILE outside runtime objects --")
    for sym in syms:
        if sym["type"] == "STT_FILE" and sym["name"] and not sym["name"].endswith(".o"):
            print("  %s" % sym["name"])
    start, end = (0, 1 << 64)
    if args.span:
        start, end = parse_int(args.span[0]), parse_int(args.span[1])
        if end < start:
            die("span end before start")
    print("-- FUNC/OBJECT in [0x%x, 0x%x) --" % (start, end))
    shown = 0
    for sym in sorted(syms, key=lambda s: (s["value"], s["name"])):
        if sym["type"] not in ("STT_OBJECT", "STT_FUNC") or not file_backed(sym, sections):
            continue
        if not (start <= sym["value"] < end):
            continue
        sec = sections[sym["shndx"]]
        foff = sec["offset"] + (sym["value"] - sec["addr"])
        print(
            "  0x%-10x %-8s size=0x%-6x file=0x%-8x %s"
            % (sym["value"], STT.get(sym["type"], "?"), sym["size"], foff, sym["name"])
        )
        shown += 1
    if not shown:
        print("  (none)")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
