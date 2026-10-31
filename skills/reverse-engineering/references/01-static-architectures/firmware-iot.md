# Embedded Firmware & IoT Reverse Engineering

## When To Open
Open this file for a vendor update image, a raw SPI/NAND/eMMC dump, a bare-metal MCU blob, or an extracted embedded Linux root filesystem (MIPS, ARM, AArch64, RISC-V, PowerPC). Userspace ELF binaries found inside the rootfs continue in [native-cpp-abi.md](native-cpp-abi.md) and [deobfuscation-anti-analysis.md](deobfuscation-anti-analysis.md). Fuzzing an extracted service is [fuzzing-for-reversing.md](../02-dynamic-instrumentation/fuzzing-for-reversing.md).

## Order Of Work
1. **Hash and record.** SHA-256 of the original file, file size, source (vendor URL, OTA capture, chip dump with chip part number).
2. **Identify by magic, not by extension.** Table below. `file`, `xxd -l 256`, and a signature scan.
3. **Plot entropy.** Decide: plain, compressed, encrypted, or XOR-obfuscated. See "Entropy".
4. **Carve.** `binwalk -eM`, then `unblob`, then the format tool. One failed extractor is not encryption.
5. **Orient in the filesystem.** Init scripts, web server, CGI, update handler, `/etc/shadow`, certificates, keys.
6. **Raw blob without a filesystem.** Recover architecture and load address, then load into the disassembler at that base.
7. **Emulate only after the static map exists.** qemu-user for one daemon; FirmAE for the whole system.
8. **Hardware last.** Read-only acquisition through UART, SPI, JTAG/SWD.

## Identification By Magic
Verified against binwalk 3.1.0 signature sources unless noted.

| Bytes (at offset 0 of the object) | Format | Notes |
| :--- | :--- | :--- |
| `27 05 19 56` | U-Boot legacy uImage | 64-byte big-endian header: magic, hcrc, time, size, `ih_load`, `ih_ep`, dcrc, os, arch, type, comp, name[32]. `mkimage -l` / `dumpimage -l` decode it. |
| `D0 0D FE ED` | Flattened device tree (DTB), also FIT image (`.itb`) | FIT has an `/images` node. `dumpimage -l fit.itb`; extract with `dumpimage -T flat_dt -p 0 -o kernel.bin fit.itb`. `dtc -I dtb -O dts -o out.dts blob.dtb`. |
| `68 73 71 73` (`hsqs`) | SquashFS little-endian | `sqsh` = big-endian. Vendor variants: `sqlz`, `qshs`, `tqsh`, `hsqt`, `shsq`. Use `sasquatch` for those. |
| `85 19` (LE) / `19 85` (BE), then node type `01 E0`/`02 E0`/`03 20` | JFFS2 | Endianness follows the CPU. |
| `55 42 49 23` (`UBI#`) | UBI erase-block header | Volume table header `UBI!`. UBIFS node magic `31 18 10 06`. |
| `45 3D CD 28`, `Compressed ROMFS` at +16 | CramFS | |
| `-rom1fs-` | RomFS | |
| `03 00 00 00 01 00 00 00 FF FF` (LE) | YAFFS2 object header | No superblock; NAND OOB layout matters. |
| `48 44 52 30` (`HDR0`) | Broadcom TRX | LE: magic, len, crc32, flags/version, partition offsets (3 in v1, 4 in v2). |
| `2A 23 24 5E` (`*#$^`) | Netgear CHK header | |
| `5E A3 A4 17` | SEAMA / D-Link DLOB | |
| `01 00 00 00` + `TP-LINK Technologies` | TP-Link firmware header | |
| `RTK0`, `--PaCkImGs--` | Realtek RTK, PackImg headers | |
| `SHRS` | D-Link encrypted image (AES-CBC) | Not in binwalk; decrypted by `imgdecrypt` from an older rootfs. |
| `Salted__` | `openssl enc` output | Key plus `-md` (md5 for old OpenSSL, sha256 for 1.1+) needed. |
| `1F 8B 08`, `5D 00 00`, `FD 37 7A 58 5A 00`, `28 B5 2F FD`, `04 22 4D 18`, `89 4C 5A 4F` | gzip, LZMA (raw `lzma_alone`), xz, zstd, lz4 frame, lzop | |
| `ARMd` at 0x38 | Linux ARM64 `Image` | |
| `18 28 6F 01` at 0x24 | Linux ARM `zImage` (magic `0x016F2818` LE) | |
| `Linux version ` string | Kernel | `vmlinux-to-elf` rebuilds an ELF with kallsyms symbols. |
| `WIND version ` | VxWorks kernel | Symbol table search below. |
| `ANDROID!`, `3A FF 26 ED` | Android boot image, Android sparse image | `simg2img` for sparse. |
| `7F 45 4C 46` | ELF | `e_machine` and `EI_DATA` give arch and endianness. |

## Tools And Verified Syntax

```bash
# binwalk v3 (Rust rewrite). Install: cargo install binwalk  (3.1.0 built and tested).
binwalk "$FW"                              # signature scan
binwalk -e -C ./bw "$FW"                   # extract into ./bw/<file>.extracted/<HEX_OFFSET>/
binwalk -eM -C ./bw "$FW"                  # recursive (matryoshka)
binwalk -E "$FW"                           # writes <file>.png in CWD; fails if that PNG already exists
binwalk -E -l entropy.json "$FW"           # per-block Shannon entropy, 0-8 bits/byte, as JSON
binwalk "$FW" -y squashfs,uimage           # only these; -x excludes. File name first: -y/-x swallow later args
binwalk -L                                 # signatures and which external extractor each needs
```

binwalk v2 options that are gone in v3: `-A` (opcode scan), `-R` (raw string), `-B`, `--dd`, `-W` (hexdiff), `-Y` (cpu-arch via capstone). v3 delegates many formats to external tools (`sasquatch`, `jefferson`, `ubireader_*`, `7z`, `tsk_recover`, `vmlinux-to-elf`); missing tools fail silently per format. Check `binwalk -L` against what is installed.

```bash
# unblob 26.x (Linux first; uses Landlock). Extract and keep a JSON report of every chunk.
uvx unblob --show-external-dependencies
uvx unblob -e ./ub --report ub.json "$FW"   # chunks named <start>-<end>.<type>; unknown chunks kept as .unknown
uvx jefferson -d ./jffs2_out "$JFFS2_IMG"
uvx --from ubi_reader ubireader_display_info "$UBI_IMG"
uvx --from ubi_reader ubireader_extract_files -o ./ubifs_out "$UBI_IMG"     # -K master key for fscrypt
uvx --from ubi_reader ubireader_extract_images -o ./ubi_vols "$UBI_IMG"
unsquashfs -d ./sq_out -o "$OFFSET" "$FW"  # squashfs-tools 4.4+; -o skips to the superblock
sasquatch -d ./sq_out "$SQ_IMG"            # onekey-sec/sasquatch release packages; vendor LZMA variants
uvx vmlinux-to-elf "$KERNEL" kernel.elf    # 1.4.0; also kallsyms-finder
```

unblob is better at bounding unknown regions and reporting their randomness. binwalk is faster for a first look. Run both when the first result does not account for the whole file. `unblob` reported tar, gzip, padding, and an `unknown` random chunk on a test image where binwalk reported the uImage and the tar.

Whole-image analyzers. EMBA (`sudo ./emba -l ./log -f "$FW" -p ./scan-profiles/default-scan.emba`) and FACT_core run extraction, SBOM, CVE matching, and checks in one pass. Treat their CVE lists as leads until the binary version is confirmed. firmware-mod-kit is unmaintained; do not use it for extraction.

## Entropy
binwalk v3 reports 0–8 bits per byte (v2 normalized to 0–1; divide v3 values by 8 to compare).

| Bits/byte | Typical content |
| :--- | :--- |
| < 1 | `FF`/`00` padding, erased flash |
| 4.5–6.5 | Code, strings, tables |
| 7.0–7.9 with dips | Compressed streams with headers between them |
| > 7.95, flat, no magic, no dips | Encryption, or one large compressed stream without a recognized header |
| 5–7 with no magic, repeating period | XOR or byte-substitution obfuscation |

Separating compression from encryption. A compressed stream starts with a known header and decompresses with the right tool. Encrypted data has no header and a chi-square close to uniform; unblob's report gives both. XOR with a short key leaves the key visible wherever plaintext was `00` padding: look at the bytes where erased flash should be.

## Encrypted Images
The image is encrypted in transit far more often than in flash. Work these in order:

1. **Older or transitional firmware.** Vendors that add encryption ship one unencrypted image that contains the decryptor. Extract it, find the decrypt binary or script (`imgdecrypt`, `/usr/sbin/*decrypt*`, `openssl enc -d` in the upgrade script), and its key or key file.
2. **Upgrade path in the current rootfs.** Grep the web/CGI handler for the upload path: `rg -n "openssl|aes|decrypt|firmware|upgrade|mtd write|sysupgrade" ./rootfs`. Keys sit in `/etc`, in a shared library, or derived from a device string.
3. **Flash dump.** If the device stores the decrypted rootfs, an SPI read gives plaintext. Compare entropy of the OTA image and the dump.
4. **Bootloader.** When the rootfs is encrypted on flash, the bootloader or kernel holds the key or calls a hardware engine. U-Boot `bootcmd` names the decrypt step.
5. **Hardware root of trust.** eFuse/OTP keys, TrustZone, secure-boot fuses: stop and report. Fault injection is out of scope unless the task says so.

## Bootloader, Environment, Partitions
- **U-Boot environment.** `u32 crc32` + (redundant env: 1 flag byte) + `key=value\0` pairs ending in `\0\0`. Find it with `rg -a -b "bootcmd=" "$FW"` or `strings -t x`. Key fields: `bootargs` (`console=`, `root=`, `mtdparts=`), `bootcmd` (load address, `sf read`/`nand read`, decrypt or verify steps), `ipaddr`/`serverip`, `ethaddr`.
- **`mtdparts=`** gives the partition map: `mtdparts=spi0.0:256k(u-boot)ro,64k(u-boot-env),64k(factory),1536k(kernel),-(rootfs)`. Cut the dump with `dd` at those offsets before carving.
- **Calibration and identity.** `factory`, `art`, `nvram` partitions hold MAC, Wi-Fi calibration, serials, and sometimes credentials. They are data, not code.
- **Device tree.** Gives SoC, peripherals and their MMIO base addresses, flash controller, partitions, and GPIOs. Base addresses become segment names in a raw-blob disassembly.
- **Other bootloaders.** CFE (Broadcom), RedBoot, Barebox, vendor ROM loaders. Strings near offset 0 name them.

## Filesystem Orientation
- Startup: `/etc/inittab`, `/etc/init.d/rcS`, `/etc/rc.d/`, `/etc/preinit`, procd `/etc/init.d/*` (OpenWrt), systemd units.
- Network services: `httpd`, `lighttpd`, `uhttpd`, `boa`, `goahead`, `mini_httpd`, `dropbear`, `telnetd`, `miniupnpd`, vendor daemons listening on TCP/UDP.
- Web: `/www`, `/htdocs`, `/web`; CGI binaries under `cgi-bin`; Lua (`/usr/lib/lua/luci`), PHP, or a single monolithic `httpd` with handlers keyed by URL string.
- Configuration store: `nvram_get`/`nvram_set` (`libnvram.so`), `uci` (`/etc/config`), `cfg_get`, XML/JSON blobs in a config partition.
- Secrets to record: `/etc/shadow`, `/etc/passwd`, `*.pem`, `*.key`, hard-coded tokens, cloud endpoints, default Wi-Fi key derivation.
- Version facts: `/etc/version`, `/etc/openwrt_release`, busybox banner (`strings busybox | rg "BusyBox v"`), kernel `Linux version`, library SONAMEs. These anchor CVE claims.

## Static Triage Of The Rootfs
Run these from the extraction root. They produce leads for the decompiler, not findings.

```bash
ROOT=./rootfs
# Which binaries are network-facing: listed in init scripts and holding socket/bind imports.
rg -n --no-heading -e 'httpd|lighttpd|uhttpd|boa|goahead|telnetd|dropbear|miniupnpd|dnsmasq' "$ROOT/etc"
find "$ROOT" -type f -exec sh -c 'for f; do [ "$(head -c 4 "$f" | od -An -tx1 | tr -d " \n")" = 7f454c46 ] && echo "$f"; done' _ {} + > elfs.txt
# Command-injection sinks reached from web handlers (MIPS/ARM vendor wrappers included).
while read -r f; do rg -l -a -e 'system|popen|execve|doSystem|twsystem|CsteSystem|_eval' "$f"; done < elfs.txt | sort -u
# Hard-coded secrets and keys.
rg -n -a -e 'BEGIN (RSA |EC |)PRIVATE KEY' -e 'password\s*=' -e 'api[_-]?key' "$ROOT" | head -50
# Backdoor-style listeners and debug switches.
rg -n -a -e 'telnetd -l' -e 'debug_mode' -e 'factory_mode' -e 'mfg' "$ROOT/etc" "$ROOT/www" 2>/dev/null | head
```

In the decompiler, the usual chain is `websGetVar`/`getenv("QUERY_STRING")`/`nvram_get` into `sprintf`/`snprintf` into `system`/`popen`/`doSystem`. Name the source, the format string, and the sink with addresses. A sink with a constant format string and no caller-controlled argument is not a finding.

## Raw Blobs: Architecture And Load Address
1. **Architecture.** Look for prologue patterns: Thumb `push {r4-r7, lr}` = `F0 B5`, `bx lr` = `70 47`; ARM `e92d4xxx`; MIPS `27 BD FF xx` (BE `addiu sp,sp,-N`) / `xx FF BD 27` (LE), `jr ra` = `03 E0 00 08` (BE); AArch64 `ret` = `C0 03 5F D6`; RISC-V `ret` = `82 80` (compressed). Count hits per candidate in a hex search; the dominant one wins.
2. **Cortex-M vector table.** Word 0 is the initial SP (inside RAM, typically `0x2000_0000`–`0x2004_0000`). Words 1–15 are handlers with bit 0 set (Thumb). Every handler must point inside the image, which bounds the base: `max(handler) - size <= base <= min(handler)`. SVCall (11), PendSV (14), SysTick (15) point into the RTOS port.
3. **Typical flash bases.** STM32 `0x0800_0000` (bootloader offset images at `0x0800_4000`/`0x0800_8000`), nRF52 `0x0000_0000` (after SoftDevice: app at its end), ESP32 images are segment-mapped (use `esptool image-info`), MIPS SoC Linux kernels `0x8000_0000`+ (KSEG0), MIPS boot ROM `0xBFC0_0000`, Broadcom/Qualcomm ARM vary: read `ih_load` from the uImage.
4. **String-pointer intersection.** Pointers in literal pools and tables point at strings. The base that makes the most pointer values land on string starts is the load address. Same idea as `rbasefind` (`rbasefind -m 10 "$FW"`, `-b` for big-endian).
5. **VxWorks symbol table.** binwalk finds it (`vxworks_symtab`) and `-e` writes `symtab.json`. Entries are 16 bytes: `name_ptr, value, type (0x500 function, 0x700 data, 0x900 bss), group`. Name pointers minus string file offsets give the base directly; the table then names every function.

Base finder. Verified on a synthetic Cortex-M image at `0x0800_4000` (ranked first with all 6 string references; vector bounds printed correctly).

```python
# find_base.py: uv run find_base.py fw.bin [--be] [--align 0x1000] [--minstr 8]
import argparse, collections, re, struct

ap = argparse.ArgumentParser()
ap.add_argument("blob"); ap.add_argument("--be", action="store_true")
ap.add_argument("--align", type=lambda x: int(x, 0), default=0x1000)
ap.add_argument("--minstr", type=int, default=8)
a = ap.parse_args()
data = open(a.blob, "rb").read()
fmt, A, n = (">I" if a.be else "<I"), a.align, len(data)

# Cortex-M vector table: [0]=initial SP in RAM, [1..15]=handlers with the Thumb bit set.
sp, *vec = struct.unpack_from(fmt[0] + "16I", data, 0)
h = [v for v in vec if v and v != 0xFFFFFFFF]
if 0x20000000 <= sp < 0x40000000 and h and all(v & 1 for v in h):
    lo, hi = -(-(max(h) - n) // A) * A, min(h) // A * A
    print(f"[vector] SP={sp:#x} reset={vec[0]:#x}  base in [{max(lo, 0):#x}, {hi:#x}] step {A:#x}")

# String/pointer intersection, grouped by residue mod align so it stays fast on MB-sized blobs.
strs = [m.start() for m in re.finditer(rb"[\x20-\x7e]{%d,}\x00" % a.minstr, data)]
ptrs = set(struct.unpack_from(fmt, data, i)[0] for i in range(0, n - 3, 4))
by_res = collections.defaultdict(list)
for s in strs: by_res[s % A].append(s)
score = collections.Counter()
for p in ptrs:
    for s in by_res.get(p % A, ()):
        if p >= s: score[p - s] += 1
print(f"[strings] {len(strs)} strings, {len(ptrs)} distinct words")
for base, hits in score.most_common(5):
    print(f"  base {base:#010x}  string refs {hits}")
```

A winner needs a clear margin (dozens of hits against single digits). A tie means the wrong endianness, the wrong alignment, or a blob that is several images concatenated: split it at padding first.

## RTOS Recognition

| RTOS | Evidence | First targets |
| :--- | :--- | :--- |
| FreeRTOS | Task names `IDLE`, `Tmr Svc`; assert paths `tasks.c`, `queue.c`, `port.c`; `pvPortMalloc` heap; PendSV handler saves `r4-r11` and loads `pxCurrentTCB` | `xTaskCreate` callers give every task entry function and name |
| Zephyr | `*** Booting Zephyr OS build`; `z_`/`k_` prefixed asserts; `CONFIG_` strings; MCUboot header `3D B8 F3 96` in front of the app | `k_thread_create` callers; device structs with driver API tables |
| VxWorks | `WIND version x.y`, `VxWorks`, `usrRoot`, `tShell` | Embedded symbol table (above); `usrAppInit` |
| ThreadX / Azure RTOS | `ThreadX`, `_tx_thread_create`, `tx_` names | Thread create calls |
| eCos, Nucleus, uC/OS, RT-Thread | `eCos`, `Nucleus PLUS`, `uC/OS-II`, `RT-Thread` strings | Task create API |
| ESP-IDF | `esp_image` header byte `E9`, `app_main`, `ESP-IDF v` | `esptool image-info` segments; `app_main` |

## Calling Conventions And ISA Traps

| ISA | Args | Return | Callee-saved | Notes |
| :--- | :--- | :--- | :--- | :--- |
| MIPS O32 | `$a0-$a3`, then stack (caller reserves 16 bytes) | `$v0`, `$v1` | `$s0-$s8`, `$gp` (PIC), `$sp` | Branch delay slot. PIC calls `lw $t9, off($gp)`; `jalr $t9`. `$gp` set from `$t9` in prologue (`lui gp,%hi(_gp_disp)`). |
| MIPS N32/N64 | `$a0-$a7` | `$v0` | `$s0-$s8` | 64-bit Octeon/Cavium routers |
| ARM AAPCS | `r0-r3` | `r0`(`r1`) | `r4-r11` | `lr` return; odd target = Thumb; `bx`/`blx` switch modes |
| AArch64 | `x0-x7` | `x0` | `x19-x28` | `x8` indirect result; `x30` link |
| RISC-V | `a0-a7` | `a0`, `a1` | `s0-s11` | `ra` link; compressed 16-bit instructions mixed in |
| PowerPC 32 | `r3-r10` | `r3` | `r14-r31` | `lr` link; `r1` stack; `r2`/`r13` small-data base |

- **MIPS delay slot.** The instruction after `jal`/`jalr`/`b*` executes before the target. It often loads `$a0`. Read it as part of the call.
- **Thumb vs ARM.** Wrong mode decodes into junk. In IDA set the `T` segment register (`Alt+G`, `T=1`) at the function start; in Ghidra set the `TMode` context register. Vector-table and function-pointer LSBs tell the mode.
- **Endianness.** Read it from each ELF (`file busybox`: `MSB` = big-endian, `LSB` = little-endian). Vendor is not a reliable predictor: Broadcom BCM63xx is big-endian MIPS, while BCM47xx/53xx is little-endian MIPS.

## Emulation (When Execution Is Allowed)
qemu-user runs one binary against the extracted rootfs. Debian/Ubuntu: `apt install qemu-user-static binfmt-support`.

```bash
ROOT=./rootfs; BIN=/usr/sbin/httpd
file "$ROOT/bin/busybox"                                   # pick qemu-mips (MSB) vs qemu-mipsel (LSB), qemu-arm, qemu-aarch64
qemu-mipsel-static -L "$ROOT" "$ROOT$BIN" --help           # -L: dynamic loader and libs from the rootfs
qemu-mipsel-static -strace -L "$ROOT" "$ROOT$BIN"          # syscall trace: missing /dev, /var, nvram, ifaces
qemu-mipsel-static -g 1234 -L "$ROOT" "$ROOT$BIN"          # gdb-multiarch: set arch mips; target remote :1234
qemu-mipsel-static -E LD_PRELOAD=/lib/libnvram.so -L "$ROOT" "$ROOT$BIN"   # NVRAM shim built for the target arch
qemu-mipsel-static -cpu 74Kf -L "$ROOT" "$ROOT$BIN"        # when an instruction is unsupported by the default CPU
# chroot form: needed when the binary uses absolute paths heavily
sudo cp "$(command -v qemu-mipsel-static)" "$ROOT/usr/bin/"
sudo mount --bind /proc "$ROOT/proc"; sudo mount --bind /dev "$ROOT/dev"
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/sh
```

With binfmt registered with the `F` flag (`update-binfmts --display qemu-mipsel`), `chroot "$ROOT" /bin/sh` works without copying qemu in.

Common early exits and fixes:

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Exits right after `nvram_get` | Empty NVRAM store | `libnvram` shim (firmadyne/FirmAE fork) with defaults from the device's `nvram` partition |
| `ioctl` on `/dev/...` fails | Missing device node or kernel module | Create the node, or patch the check (record the patch) |
| Binds to `br0`/`eth0.2` fails | Interface does not exist | Create a dummy interface in the lab netns, or patch the name |
| Waits forever on a PID file or socket | Missing sibling daemon | Start the dependency, or stub it |
| `Illegal instruction` | CPU model | `-cpu` with the SoC's core |

Full-system emulation: FirmAE (`./init.sh`, then `sudo ./run.sh -c <brand> "$FW"` to check, `-a` analyze, `-r` run, `-d` user-level debug shell, `-b` kernel boot debug). FirmAE improves on firmadyne's success rate with arbitration heuristics. A firmware that does not boot there needs a custom kernel and machine model in qemu-system, which is a project, not a step.

## Hardware Debug Ports (Read Only)
Authorized hardware access is read-only until a hashed dump exists. Never write flash, `saveenv`, or mass-erase during acquisition.

UART:
- Find 3–4 pins near the SoC. GND has continuity to the shield. VCC is steady. TX fluctuates during boot. RX is usually pulled high.
- Measure the voltage first: 1.8 V, 3.3 V, and 5 V adapters are not interchangeable. Connect TX, RX, GND only; never VCC.
- Baud: try 115200, then 57600, 38400, 9600. A logic analyzer gives it exactly: baud = 1 / shortest bit width.
- Log everything: `picocom -b 115200 -g boot.log /dev/ttyUSB0` (or `screen -L`).
- U-Boot read-only commands after interrupting autoboot: `version`, `printenv`, `bdinfo`, `mtdparts`, `sf probe`, `md.b <addr> <len>`. `sf read ${loadaddr} 0 <size>` copies flash to RAM only.

SPI flash (preferred acquisition):
```bash
flashrom -p ch341a_spi -r dump1.bin && flashrom -p ch341a_spi -r dump2.bin && cmp dump1.bin dump2.bin && sha256sum dump1.bin
# several chip matches: add -c "<CHIP_NAME>" from flashrom's list
```
In-circuit reads can fail when the SoC drives the bus. Hold the SoC in reset or lift the chip. Two identical reads are the minimum before trusting a dump.

ESP32/ESP8266 over the ROM bootloader: `uvx esptool --port "$PORT" read-flash 0 0x400000 flash.bin` (esptool 5.6.0; size is an integer, match the chip size). Flash encryption makes this ciphertext.

JTAG / SWD with OpenOCD (xPack OpenOCD 0.12.0 config names verified):
```bash
# Unknown JTAG chain: no target config, OpenOCD auto-probes TAPs and prints IDCODEs.
openocd -f interface/jlink.cfg -c "transport select jtag" -c "adapter speed 1000" -c init -c scan_chain -c shutdown
# STM32F1 over ST-Link (SWD): read the whole flash bank and 20 KiB of SRAM, read-only.
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg \
  -c init -c "reset halt" -c "flash read_bank 0 flash.bin" -c "dump_image sram.bin 0x20000000 0x5000" -c shutdown
# Generic CMSIS-DAP SWD probe against an STM32F4.
openocd -f interface/cmsis-dap.cfg -c "transport select swd" -f target/stm32f4x.cfg \
  -c init -c "reset halt" -c "dump_image flash.bin 0x08000000 0x100000" -c shutdown
```
- IDCODE layout: bit 0 = 1, bits 11:1 JEP106 manufacturer, 27:12 part, 31:28 version. `0x?BA00477` is an ARM CoreSight debug port (manufacturer `0x23B`, ARM Ltd).
- FT2232H/FT232H adapters use `interface/ftdi/*.cfg` (for example `ftdi/tigard.cfg`, `ftdi/ft232h-module-swd.cfg`). Raspberry Pi GPIO uses `interface/raspberrypi-native.cfg`.
- Readout protection: STM32 RDP level 1, nRF52 `APPROTECT`, ESP32 flash encryption/secure boot, locked JTAG (IDCODE reads, memory reads fail). Record and stop. Removing RDP mass-erases flash.

## Evidence To Record
- Original image SHA-256, source, size, and the carve map: offset, length, type, tool, tool version for every region, including unknown ones.
- Architecture, endianness, ABI, and how each was established (ELF header, vector table, prologue counts).
- Load address and its proof (vector bounds, pointer-intersection score, `ih_load`, symbol table).
- For each claim about a binary: path in the rootfs, SHA-256, function address, and the decompiler that produced it.
- Every patch made for emulation, and whether the claim depends on emulated behavior.

## Pitfalls
- A raw SPI dump includes bootloader, env, calibration, and possibly two firmware banks (A/B). An OTA file often holds only the kernel and rootfs. Do not compare offsets between them.
- NAND dumps include OOB/spare bytes per page (for example 2048+64). Strip OOB and handle bad blocks before UBI/YAFFS tools.
- binwalk's absence of a result is not proof of encryption. Check entropy, unblob, and a manual magic search.
- A SquashFS that `unsquashfs` rejects is usually a vendor variant: try `sasquatch` before assuming corruption.
- Emulated success is not device behavior. Peripherals, NVRAM, and timing differ. Confirm a finding statically in the binary.
- An automated CVE match is a lead. The version string and the vulnerable function in the binary must both match.
- Do not run target binaries on the host directly. Use qemu in the lab VM.
