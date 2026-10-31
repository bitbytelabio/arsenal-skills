# Embedded Firmware & IoT Binary Reverse Engineering

## 1. Title & Overview
- **Domain**: Embedded systems, IoT devices, home routers, industrial controllers, and bare-metal microcontrollers across MIPS, ARM, RISC-V, and PowerPC architectures.
- **Scope**: Identifying flash dump and firmware container formats (uImage, SquashFS, TRX, JFFS2, UBIFS), recursive extraction with `binwalk` and `unblob`, calculating base load addresses for bare-metal binaries, and analyzing architecture-specific instruction quirks (MIPS branch delay slots, ARM/Thumb interworking mode switches).

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing raw flash chips, firmware update images, or bare-metal dumps:

### Binary Signatures & Container Headers
- **U-Boot Legacy Image (uImage)**:
  - Magic bytes (first 4 bytes): `\x27\x05\x19\x56` (`0x27051956`).
  - Followed by 32-bit big-endian fields: header checksum, timestamp, data size, load address (`ih_load`), entry point (`ih_ep`).
- **SquashFS File System**:
  - Magic bytes:
    - Little-endian: `sqsh` (`0x68737173`) or `hsqs` (`0x73717368`)
    - Big-endian: `shsq` or `qshs`
    - Non-standard vendor headers: `sqlz`, `qslz`
- **TRX Container (Broadcom router firmware)**:
  - Magic bytes: `HDR0` (`\x48\x44\x52\x30` / `0x30524448`).
  - Structure: 4-byte magic, 4-byte total length, 4-byte CRC32, flags, partition offsets.
- **JFFS2 File System**:
  - Magic bytes: `\x85\x19` (`0x1985` in little-endian or `0x8519` in big-endian).
- **Bare-Metal & RTOS Images**:
  - FreeRTOS, VxWorks, eCos, ThreadX.
  - Absence of standard ELF/PE headers; contiguous binary data starting with vector tables.

---

## 3. Tooling & CLI/MCP Actions
- **Firmware Carvers & Extractors**:
  - `unblob`: Modern container and filesystem extraction engine with sandbox protection.
    ```bash
    unblob -e ./extracted_firmware firmware.bin
    ```
  - `binwalk`: Signature scanner and entropy analyzer.
    ```bash
    # Scan signatures without extracting
    binwalk firmware.bin
    # Recursive extraction
    binwalk -eM firmware.bin
    # Entropy analysis (detect encryption or compression boundaries)
    binwalk -E firmware.bin
    ```
  - Filesystem specific tools:
    - `sasquatch`: Extracts non-standard vendor SquashFS images.
    - `ubireader_extract_files`: Extracts UBI/UBIFS flash volumes.
- **Decompilers & Disassemblers**:
  - Headless IDA Pro MCP / Ghidra: Multi-architecture analysis for MIPS32/64, ARM/Thumb, and PowerPC.
  - Emulation: `qemu-mips-static` or `qemu-arm-static` for executing isolated Linux binaries under chroot.

---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 Flash Dump Container Triage & Extraction Pipeline
A standard IoT flash layout packs bootloaders, kernel images, and root filesystems together:

```text
Flash Memory Map:
0x00000000 ┌────────────────────────────────────────┐
           │ Bootloader (U-Boot / RedBoot / CFE)    │
0x00040000 ├────────────────────────────────────────┤
           │ NVRAM / U-Boot Environment Variables  │
0x00060000 ├────────────────────────────────────────┤
           │ Linux Kernel (uImage: zImage / lzma)   │
0x00260000 ├────────────────────────────────────────┤
           │ Root Filesystem (SquashFS / JFFS2)     │
           │  ├── /bin/busybox                      │
           │  ├── /etc/init.d/rcS                   │
           │  └── /www/ (Web Management Interface)  │
0x01000000 └────────────────────────────────────────┘
```

#### Extraction Workflow:
One failed extractor is not encryption. Walk the chain before calling the image encrypted.

1. **Header and entropy, before extract.**
   - `file`, `binwalk` (signatures only), and `binwalk -E`.
   - Vendor headers that are not uImage or SquashFS: TP-Link CHK (`2A 23 24 5E`), D-Link DLOB (`4D 5A 4F 41`).
   - Entropy bands: about `0.0–0.3` padding, `0.3–0.7` code or strings, `0.7–0.95` compression, `0.95–1.0` encryption or a dense compressor. A flat `~0.99` with no magic is the encryption hypothesis. A step up to `~0.9` under a uImage or SquashFS magic is compression.
2. **Carve in this order.** `binwalk -eM`, then `unblob` if the layout is incomplete, then the format tool: `jefferson` for JFFS2, `ubireader_extract_files` for UBI, `unsquashfs` when the offset is known, `sasquatch` for vendor SquashFS (`sqlz`, `qslz`, old Realtek LZMA).
3. **Filesystem orientation.**
   - Inspect `/etc/init.d/` and `/etc/inittab` to locate startup daemons.
   - Inspect `/www` or `/htdocs` for web management scripts, CGI executables, and API endpoints.
   - Hash the extracted tree. An automated CVE report is a lead until the version string and the binary match.

#### Endianness And Emulation
MediaTek images are usually little-endian (`qemu-mipsel-static`). Broadcom images are usually big-endian (`qemu-mips-static`). The wrong qemu user binary is not a broken target. If a userspace daemon dies immediately inside qemu, the usual cause is `nvram_get` with an empty store, a wrong network interface name, or a missing `/dev` node. Preload an NVRAM shim before treating the crash as a bug in the daemon.

#### Encrypted Images
When the entropy hypothesis holds, the key is usually in the bootloader that runs before `bootm`, not in the ciphertext. Recover that routine from a UART boot log or a SPI read of the same flash, then decrypt offline and return to the carve chain. A locked secure-boot fuse is a stop, not an invitation to glitch the chip.

#### Debug Ports (Read Only)
Authorized hardware access is read-only until a dump exists.

- Photograph test points. Silkscreen `TX RX GND VCC` is UART. `TDI TDO TCK TMS` is JTAG. SWD is `SWDIO SWCLK`.
- Measure voltage before connecting. `1.8 V`, `3.3 V`, and `5 V` are not interchangeable.
- UART first, common rates `115200` and `57600`. Log the boot text. Do not `saveenv`.
- JTAG: read IDCODE and record whether the chain is locked. Do not write flash.
- `flashrom` or an equivalent SPI read produces the image. Record SHA-256 before any extract. Hand the image back to the carve chain above.

---

### 4.2 Bare-Metal Firmware Load Base Address Calculation
Raw microcontroller firmware (e.g., STM32, ESP32, nRF52, PIC32) lacks ELF headers containing virtual memory base addresses (`VMA`). If loaded at address `0x0`, pointers to strings and function tables will point to invalid memory.

#### Base Address Calculation Workflow:
1. **Vector Table Inspection (ARM Cortex-M Example)**:
   - The first 4 bytes at offset `0x00` contain the initial Stack Pointer (`SP`). This value points to top-of-RAM (e.g., `0x20008000`).
   - The second 4 bytes at offset `0x04` contain the Reset Vector (address of entry function).
   - In Thumb mode, the Reset Vector address has its Least Significant Bit (LSB) set to `1`:
     - If bytes at `0x04` are `\x01\x04\x08\x08` (`0x08080401`), the actual code address is `0x08080400`.
     - Because offset in file is `0x00`, the base address is `0x08080000` (typical STM32 flash base).
2. **String Cross-Reference Delta Matching**:
   - Search for a readable ASCII string in the binary (e.g., `"System Initialized"` at file offset `0x3210`).
   - Search the code for 32-bit pointer values that point to `"System Initialized"`.
   - If a table or literal pool contains `0x80043210`:
     $$\text{Base Address} = \text{Pointer Value} - \text{File Offset} = 0x80043210 - 0x00003210 = 0x80040000$$
3. Rebase the binary in the disassembler to `0x80040000`. Pointers and cross-references will immediately align.

---

### 4.3 Architecture-Specific Peculiarities: MIPS & ARM

#### A. MIPS Instruction Peculiarities
1. **Branch Delay Slots**:
   - In MIPS, the instruction immediately following a branch or jump (`J`, `JAL`, `BEQ`, `BNE`) is executed **before** the branch takes effect:
     ```nasm
     jal     target_function     ; Call target_function
     addiu   $a0, $zero, 1       ; DELAY SLOT: Argument 1 is set to 1 BEFORE the call executes!
     ```
   - *Reversing Action*: Never analyze a MIPS call instruction without reading the instruction immediately below it; the delay slot frequently loads arguments or cleans up frames.
2. **Position Independent Code (PIC) Register Conventions**:
   - In MIPS PIC code, functions load their target address into `$t9` before calling:
     ```nasm
     lw      $t9, -0x7fd0($gp)
     jalr    $t9
     nop                         ; Delay slot
     ```

#### B. ARM Instruction Peculiarities: ARM32 vs Thumb Interworking
ARM processors switch dynamically between 32-bit ARM mode and 16/32-bit Thumb mode:
- **LSB State Indicator**:
  - Any branch to an odd address (`address | 1`) switches processor execution into Thumb mode (`BX`, `BLX`).
  - The actual instruction is fetched from `address & ~1`.
- **Disassembler Alignment (`$a` vs `$t`)**:
  - In IDA Pro and Ghidra, if Thumb code is disassembled as ARM, it will decode as illegal or nonsense instructions.
  - In IDA: Press `Alt+G` on the function start and toggle `T` register:
    - `T = 0`: Disassemble as ARM32.
    - `T = 1`: Disassemble as Thumb / Thumb-2.

---

## 5. Concrete Code & Script Examples

### Python Base Address Brute-Forcer for Bare-Metal Firmware
```python
import struct
import sys

def find_candidate_base_addresses(bin_data, word_size=4):
    """Find prospective base addresses by matching string references with pointers."""
    data_len = len(bin_data)
    # Collect candidate ASCII strings (length >= 8)
    strings_offsets = []
    curr_start = None

    for i in range(data_len):
        b = bin_data[i]
        if 0x20 <= b <= 0x7E:
            if curr_start is None:
                curr_start = i
        else:
            if curr_start is not None:
                s_len = i - curr_start
                if s_len >= 8:
                    strings_offsets.append(curr_start)
                curr_start = None

    print(f"[+] Found {len(strings_offsets)} candidate string literals.")

    # Scan for 32-bit little-endian pointers pointing to string offsets + Base
    # Typical flash bases: 0x00000000, 0x08000000, 0x80000000, 0x1fc00000, 0x40000000
    candidate_bases = {}

    for i in range(0, data_len - 4, 4):
        val = struct.unpack_from("<I", bin_data, i)[0]
        # Skip small values or obvious non-pointers
        if val < 0x00010000 or val > 0xFFFE0000:
            continue

        for s_off in strings_offsets:
            # If val = Base + s_off
            potential_base = val - s_off
            # Align to 64KB boundary
            if (potential_base & 0xFFFF) == 0:
                candidate_bases[potential_base] = candidate_bases.get(potential_base, 0) + 1

    # Sort candidates by frequency of matching string references
    sorted_bases = sorted(candidate_bases.items(), key=lambda x: x[1], reverse=True)

    print("[+] Top candidate base addresses:")
    for base, score in sorted_bases[:5]:
        print(f"    Base Address: 0x{base:08X} (Matched references: {score})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 find_base.py <firmware.bin>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        find_candidate_base_addresses(f.read())
```

---

## 6. Boundaries & Anti-Patterns
- **Do not execute embedded binaries on the host workstation directly**: IoT binaries target foreign CPU architectures (MIPS, ARM, PPC) or rely on specialized NVRAM libraries (`libnvram.so`). Running them directly will fail or produce architecture faults. Use `qemu-user-static` with NVRAM pre-load wrappers.
- **Do not ignore MIPS delay slots during flow analysis**: An instruction immediately following a jump or branch is not part of the sequential fall-through block; it executes in the delay slot of the jump.
- **Do not misidentify Thumb mode as ARM**: Disassembling Thumb-2 instructions as ARM32 produces completely wrong opcode sequences. Always verify the vector table LSB bit or set the `T` selector in IDA/Ghidra.
- **Do not confuse SPI flash dumps with OTA update files**: Raw SPI dumps include bootloaders, partition tables, and calibration data; OTA packages often contain only an encrypted file or a single SquashFS partition.
- **Do not call an image encrypted because one carver returned nothing**: Run the extractor chain in section 4.1 before that claim. A high-entropy compressor and AES look alike until the header and a second tool have been checked.
- **Do not write a debug port or U-Boot environment during acquisition**: The first hardware session records voltage, pins, and a hashed flash image.
