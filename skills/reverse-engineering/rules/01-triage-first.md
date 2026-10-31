# Rule 1: Mandatory Triage-First Gate

## Mandate
It is **STRICTLY FORBIDDEN** to invoke any decompiler (IDA Pro, Ghidra, Binary Ninja), disassembler, or dynamic debugger on an artifact before a triage manifest exists. The manifest is the JSON printed by `uv run scripts/auto_triage.py "$ARTIFACT"`, plus format-specific output from `file`, `rabin2 -I`, `readelf -h -l`, or `uv run scripts/elf_triage.py`, saved under `triage` in `re_state.json`.

## Rationale
Jumping directly to decompile an uncharacterized entry point or `main` without establishing foundational binary attributes violates core reverse engineering principles:
1. **Toolchain Mismatch**: Invoking standard C decompilation models on Golang, Rust, or C++ binaries produces hallucinated control flow and unreadable abstractions without appropriate runtime and symbol support.
2. **Packer and Armor Hazards**: Decompiling packed, encrypted, or virtualized sections wastes CPU cycles and context space on stub loaders or decryption loops.
3. **Format Blindness**: Operating without architecture (x86_64, AArch64, MIPS, ARM Thumb), endianness, and binary format specifics leads to incorrect calling conventions and register assignments.

## Enforcement
- **Pre-Hook Validation**: Before any disassembler or decompiler call (ida-mcp `open_database`, `idat`, `analyzeHeadless`, `r2 -A`, `objdump -d`), check that `re_state.json` has a `triage` block for this exact SHA-256.
- **Immediate Rejection**: Any instruction or sub-task directing decompilation prior to artifact characterization must be rejected immediately, pivoting back to triage execution:
  ```bash
  uv run scripts/auto_triage.py "$ARTIFACT"
  ```
- **Manifest Requirements**: The triage manifest must confirm the items below. The `auto_triage.py` field that supplies each one is in brackets; add the rest by hand.
  - Sample identity: SHA-256 [`sha256`], path [`file`], format [`format`].
  - Target architecture and bitness [`architecture`]. For a fat Mach-O, name the slice you will analyze.
  - Toolchain and runtime markers [`runtime`, `indicators`]: Go, Rust, MSVC, GCC/Clang, .NET, JVM, Unity, Flutter, Hermes. Add the version by hand when a marker gives it (Go buildinfo, Rust `rustc` path, Dart snapshot hash). NativeAOT is native code, not a dnSpy/IL target.
  - Entropy and packer indicators [`entropy`, `is_packed`, `packer`]. The script reports whole-file entropy. Per-section entropy comes from `rabin2 -S` with `binwalk -E`, or from LIEF.
  - Import/export overview [`surface`: libraries, delay-load libraries, counts, and the first 30 names], or the recorded parse failure [`surface.error`].

## Thin Surface
An empty ASCII string list or a tiny import table is not the end of triage. Before calling the surface empty, record which of these were checked:

- **Wide and decoded strings**: UTF-16LE strings (GNU `strings -el`; macOS `strings` has no `-e`, so use `floss`, `rabin2 -zz`, or a Python scan) and a decoded-string pass (`floss`) when ASCII strings are absent.
- **Packing structure**: a section with raw size near 0 and a large virtual size; a section that is writable and executable; an entry point outside the first section; a TLS directory.
- **Trailing and embedded payloads**: file size larger than the sum of raw section sizes (overlay); a high-entropy resource such as `RT_RCDATA`.
- **Late binding**: delay-load imports, or a proxy DLL whose exports mirror a system DLL while the sample loads the real DLL beside it.

A miss on one of these is an observation. Skipping them and then claiming "no strings" or "no payload" is not.
