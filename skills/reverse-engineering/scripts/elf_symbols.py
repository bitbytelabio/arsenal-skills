#!/usr/bin/env python3
"""Read-only ELF symbol span and file-symbol report.

Prints every FUNC/OBJECT in an address window and every STT_FILE name that is
not a .o runtime object. Never executes or loads the target. Standard library only.

Usage:
  python3 elf_symbols.py target.bin
  python3 elf_symbols.py target.bin --span 0x401100 0x401800

Exit codes: 0 success, 2 unreadable/not ELF/bad span.
"""

import argparse
import struct
import sys


def die(msg):
    sys.stderr.write("elf_symbols: %s\n" % msg)
    sys.exit(2)


def parse_int(text):
    try:
        return int(text, 0)
    except ValueError:
        die("bad address %r" % text)


def cstr(data, start):
    if start < 0 or start >= len(data):
        return "?"
    end = data.find(b"\x00", start)
    if end < 0:
        end = len(data)
    return data[start:end].decode("utf-8", "replace")


def load(path):
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        die("cannot read %s: %s" % (path, exc))
    if len(data) < 52 or data[:4] != b"\x7fELF":
        die("%s is not an ELF file" % path)
    if data[4] not in (1, 2) or data[5] != 1:
        die("%s is not little-endian ELF32/ELF64" % path)
    bits = 64 if data[4] == 2 else 32
    if bits == 64:
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        e_shentsize = struct.unpack_from("<H", data, 58)[0]
        e_shnum = struct.unpack_from("<H", data, 60)[0]
        e_shstrndx = struct.unpack_from("<H", data, 62)[0]
    else:
        e_shoff = struct.unpack_from("<I", data, 32)[0]
        e_shentsize = struct.unpack_from("<H", data, 46)[0]
        e_shnum = struct.unpack_from("<H", data, 48)[0]
        e_shstrndx = struct.unpack_from("<H", data, 50)[0]
    if not e_shoff or not e_shnum:
        die("%s has no section headers" % path)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if bits == 64:
            name, typ, _flags, addr, offset, size, link, _info, _align, entsize = struct.unpack_from(
                "<IIQQQQIIQQ", data, off
            )
        else:
            name, typ, _flags, addr, offset, size, link, _info, _align, entsize = struct.unpack_from(
                "<IIIIIIIIII", data, off
            )
        sections.append(
            {
                "name": name,
                "type": typ,
                "addr": addr,
                "offset": offset,
                "size": size,
                "link": link,
                "entsize": entsize,
            }
        )
    shstr = sections[e_shstrndx] if 0 <= e_shstrndx < len(sections) else None
    for sec in sections:
        sec["sname"] = cstr(data, shstr["offset"] + sec["name"]) if shstr else "?"
    return data, sections


def symbols(data, sections):
    symtab = next((s for s in sections if s["type"] == 2), None)
    if not symtab or not symtab["entsize"]:
        die("no symbol table")
    strtab = sections[symtab["link"]]
    bits = 64 if data[4] == 2 else 32
    count = symtab["size"] // symtab["entsize"]
    out = []
    for i in range(count):
        off = symtab["offset"] + i * symtab["entsize"]
        if bits == 64:
            name, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, off)
        else:
            name, value, size, info, _other, shndx = struct.unpack_from("<IIIBBH", data, off)
        out.append(
            {
                "name": cstr(data, strtab["offset"] + name),
                "type": info & 0xF,
                "shndx": shndx,
                "value": value,
                "size": size,
            }
        )
    return out


STT = {1: "OBJECT", 2: "FUNC", 4: "FILE"}


def file_backed(sym, sections):
    idx = sym["shndx"]
    return 0 < idx < len(sections)


def main():
    ap = argparse.ArgumentParser(description="read-only ELF symbol span")
    ap.add_argument("path")
    ap.add_argument("--span", nargs=2, metavar=("START", "END"))
    args = ap.parse_args()
    data, sections = load(args.path)
    syms = symbols(data, sections)
    print("-- STT_FILE outside runtime objects --")
    for sym in syms:
        if sym["type"] == 4 and sym["name"] and not sym["name"].endswith(".o"):
            print("  %s" % sym["name"])
    start, end = (0, 1 << 64)
    if args.span:
        start, end = parse_int(args.span[0]), parse_int(args.span[1])
        if end < start:
            die("span end before start")
    print("-- FUNC/OBJECT in [0x%x, 0x%x) --" % (start, end))
    shown = 0
    for sym in sorted(syms, key=lambda s: (s["value"], s["name"])):
        if sym["type"] not in (1, 2) or not file_backed(sym, sections):
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
