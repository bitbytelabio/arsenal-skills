#!/usr/bin/env python3
"""Deterministic, read-only ELF reconnaissance for static analysis.

Never executes, loads, emulates, or debugs the target and never contacts
anything it contains. Reads file bytes only. Standard library only.

Usage:
  python3 elf_triage.py target.bin
  python3 elf_triage.py target.bin --find '^(main|decrypt_payload|key)$'
  python3 elf_triage.py target.bin --dump encrypted_payload,key
  python3 elf_triage.py target.bin --xor encrypted_payload --key key
  python3 elf_triage.py target.bin --xor encrypted_payload --key-hex deadbeef...

Exit codes: 0 success, 2 unreadable/not ELF/missing object.
"""

import argparse
import collections
import math
import re
import struct
import sys

ET = {1: "REL", 2: "EXEC (non-PIE)", 3: "DYN (PIE/shared)", 4: "CORE"}
MACH = {0x03: "i386", 0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64"}
PT = {
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    6: "PHDR",
    7: "TLS",
    0x6474E550: "GNU_EH_FRAME",
    0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO",
}
SHT = {
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    8: "NOBITS",
    9: "REL",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
}
STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 6: "TLS"}


def die(msg):
    sys.stderr.write("elf_triage: %s\n" % msg)
    sys.exit(2)


class Elf:
    def __init__(self, path):
        try:
            self.data = open(path, "rb").read()
        except OSError as exc:
            die("cannot read %s: %s" % (path, exc))
        d = self.data
        if len(d) < 52 or d[:4] != b"\x7fELF":
            die("%s is not an ELF file" % path)
        if d[4] not in (1, 2) or d[5] not in (1, 2):
            die("%s has an unsupported ELF class/encoding" % path)
        self.bits = 64 if d[4] == 2 else 32
        self.endian = "<" if d[5] == 1 else ">"
        self.path = path
        e = self.endian
        if self.bits == 64:
            (
                self.e_type,
                self.e_machine,
                _,
                self.entry,
                self.phoff,
                self.shoff,
                _,
                _,
                self.phentsize,
                self.phnum,
                self.shentsize,
                self.shnum,
                self.shstrndx,
            ) = struct.unpack_from(e + "HHIQQQIHHHHHH", d, 16)
        else:
            (
                self.e_type,
                self.e_machine,
                _,
                self.entry,
                self.phoff,
                self.shoff,
                _,
                _,
                self.phentsize,
                self.phnum,
                self.shentsize,
                self.shnum,
                self.shstrndx,
            ) = struct.unpack_from(e + "HHIIIIIHHHHHH", d, 16)
        self.sections = self._sections()
        self.phdrs = self._phdrs()
        self.symtab = self._symbols()

    def _cstr(self, sec, rel):
        if not sec:
            return "?"
        start = sec["offset"] + rel
        if start < 0 or start >= len(self.data):
            return "?"
        end = self.data.find(b"\x00", start)
        if end < 0:
            end = len(self.data)
        return self.data[start:end].decode("utf-8", "replace")

    def _sections(self):
        out = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            if self.bits == 64:
                vals = struct.unpack_from(self.endian + "IIQQQQIIQQ", self.data, off)
            else:
                vals = struct.unpack_from(self.endian + "IIIIIIIIII", self.data, off)
            name, typ, flags, addr, offset, size, link, info, align, entsize = vals
            out.append(
                {
                    "name": name,
                    "type": typ,
                    "flags": flags,
                    "addr": addr,
                    "offset": offset,
                    "size": size,
                    "link": link,
                    "info": info,
                    "align": align,
                    "entsize": entsize,
                }
            )
        shstr = out[self.shstrndx] if 0 <= self.shstrndx < len(out) else None
        for sec in out:
            sec["sname"] = self._cstr(shstr, sec["name"])
        return out

    def _phdrs(self):
        out = []
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            if self.bits == 64:
                typ, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
                    self.endian + "IIQQQQQQ", self.data, off
                )
            else:
                typ, offset, vaddr, paddr, filesz, memsz, flags, align = struct.unpack_from(
                    self.endian + "IIIIIIII", self.data, off
                )
            out.append(
                {
                    "type": typ,
                    "flags": flags,
                    "offset": offset,
                    "vaddr": vaddr,
                    "filesz": filesz,
                    "memsz": memsz,
                }
            )
        return out

    def _symbols(self):
        symtab = next((s for s in self.sections if s["type"] == 2), None)
        if not symtab or not symtab["entsize"]:
            return []
        strtab = self.sections[symtab["link"]] if symtab["link"] < len(self.sections) else None
        count = symtab["size"] // symtab["entsize"]
        out = []
        for i in range(count):
            off = symtab["offset"] + i * symtab["entsize"]
            if self.bits == 64:
                name, info, other, shndx, value, size = struct.unpack_from(
                    self.endian + "IBBHQQ", self.data, off
                )
            else:
                name, value, size, info, other, shndx = struct.unpack_from(
                    self.endian + "IIIBBH", self.data, off
                )
            out.append(
                {
                    "name": self._cstr(strtab, name),
                    "type": info & 0xF,
                    "bind": info >> 4,
                    "shndx": shndx,
                    "value": value,
                    "size": size,
                }
            )
        return out

    def section_for(self, sym):
        idx = sym["shndx"]
        if not (0 < idx < len(self.sections)):
            die("symbol %r is not in a file-backed section" % sym["name"])
        return self.sections[idx]

    def symbol_bytes(self, sym):
        sec = self.section_for(sym)
        start = sec["offset"] + (sym["value"] - sec["addr"])
        if start < 0 or start + sym["size"] > len(self.data):
            die("symbol %r bytes fall outside the file" % sym["name"])
        return self.data[start : start + sym["size"]], start

    def file_backed(self, sym):
        idx = sym["shndx"]
        # SHN_ABS, SHN_COMMON, and SHN_UNDEF are not section indexes.
        return 0 < idx < len(self.sections)

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
            "LE" if elf.endian == "<" else "BE",
            MACH.get(elf.e_machine, hex(elf.e_machine)),
            ET.get(elf.e_type, str(elf.e_type)),
        )
    )
    print("file size   0x%x bytes" % len(d))
    print(
        "entry       0x%x   sections=%d  phdrs=%d  symbols=%d"
        % (elf.entry, elf.shnum, elf.phnum, len(elf.symtab))
    )

    loads = [p for p in elf.phdrs if p["type"] == 1]
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
            % (PT.get(p["type"], hex(p["type"])), p["offset"], p["vaddr"], p["filesz"], p["flags"])
        )
    stack = next((p for p in elf.phdrs if p["type"] == 0x6474E551), None)
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
                    SHT.get(sec["type"], str(sec["type"])),
                )
            )

    print("\n-- selected symbols --")
    seen = False
    for name in ("_start", "main", "__libc_start_main"):
        for sym in elf.find(name=name):
            print(
                "  %-24s %-8s value=0x%-8x size=0x%x"
                % (sym["name"], STT.get(sym["type"], "?"), sym["value"], sym["size"])
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
                STT.get(sym["type"], "?"),
                sec["sname"],
                sym["value"],
                sym["size"],
                sec["offset"] + (sym["value"] - sec["addr"]),
            )
        )


def report_dump(elf, names):
    print("-- named OBJECT bytes --")
    for name in names:
        syms = [s for s in elf.find(name=name) if s["type"] == 1]
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
    blobs = [s for s in elf.find(name=blob_name) if s["type"] == 1]
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
        keys = [s for s in elf.find(name=key_name or "") if s["type"] == 1]
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
