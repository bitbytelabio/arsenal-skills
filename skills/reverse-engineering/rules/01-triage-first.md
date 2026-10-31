# Rule 1: Mandatory Triage-First Gate

## Mandate
It is **STRICTLY FORBIDDEN** to invoke any decompiler (IDA Pro, Ghidra, Binary Ninja), disassembler, or dynamic debugger on an artifact before obtaining or generating a valid `<target_triage_manifest>` via `scripts/auto_triage.py` (or format-specific pre-triage tools such as `file`, `rabin2 -I`, `readelf`, `dumpbin`).

## Rationale
Jumping directly to decompile an uncharacterized entry point or `main` without establishing foundational binary attributes violates core reverse engineering principles:
1. **Toolchain Mismatch**: Invoking standard C decompilation models on Golang, Rust, or C++ binaries produces hallucinated control flow and unreadable abstractions without appropriate runtime and symbol support.
2. **Packer and Armor Hazards**: Decompiling packed, encrypted, or virtualized sections wastes CPU cycles and context space on stub loaders or decryption loops.
3. **Format Blindness**: Operating without architecture (x86_64, AArch64, MIPS, ARM Thumb), endianness, and binary format specifics leads to incorrect calling conventions and register assignments.

## Enforcement
- **Pre-Hook Validation**: Before executing any disassembler/decompiler command (`ida64`, `ghidra`, `cutter`, `objdump`, `radare2`), the agent must check for the presence of a triage manifest in `re_state.json` or as raw execution output from `auto_triage.py`.
- **Immediate Rejection**: Any instruction or sub-task directing decompilation prior to artifact characterization must be rejected immediately, pivoting back to triage execution:
  ```bash
  uv run scripts/auto_triage.py <target_path>
  ```
- **Manifest Requirements**: The triage manifest must confirm:
  - Sample identity: SHA-256, path, format (`ELF`, `PE`, `Mach-O`, `DEX`, `WASM`, `Firmware`).
  - Target architecture and bitness (`x86_64`, `aarch64`, etc.).
  - Toolchain and runtime markers (`Go`, `Rust`, `MSVC`, `GCC/Clang`, `.NET`, `JVM`). NativeAOT is native code, not a dnSpy/IL target.
  - Section entropy and packer indicators (UPX, Themida, VMProtect, custom stub).
  - High-level import/export overview, or the recorded failure to parse them.

## Thin Surface
An empty ASCII string list or a tiny import table is not the end of triage. Before calling the surface empty, record which of these were checked:

- **Wide and decoded strings**: UTF-16 (`strings -el` or the decompiler's Unicode view) and a decoded-string pass (`floss` or equivalent) when ASCII strings are absent.
- **Packing structure**: a section with raw size near 0 and a large virtual size; a section that is writable and executable; an entry point outside the first section; a TLS directory.
- **Trailing and embedded payloads**: file size larger than the sum of raw section sizes (overlay); a high-entropy resource such as `RT_RCDATA`.
- **Late binding**: delay-load imports, or a proxy DLL whose exports mirror a system DLL while the sample loads the real DLL beside it.

A miss on one of these is an observation. Skipping them and then claiming "no strings" or "no payload" is not.
