# Unpacking, OEP Finding, and Memory Dumping

## When To Open
Open this file when the bytes on disk are not the code that runs: high-entropy sections, a tiny import table, `UPX0`/`.vmp0`/`.themida` sections, a `PT_LOAD` whose memory size dwarfs its file size, or a stub that allocates memory and jumps into it. The goal is a static artifact you can analyze (a dumped image with usable imports) or, when that fails, runtime evidence of what the unpacked code does. Every step that executes the sample runs in the lab from [malware-sandbox-isolation.md](malware-sandbox-isolation.md). Debugger syntax is in [debugger-workflows.md](debugger-workflows.md). Devirtualization strategy is in [deobfuscation-anti-analysis.md](../01-static-architectures/deobfuscation-anti-analysis.md).

## Is It Packed?
Static signals, cheapest first. Run these on the host; they only read bytes.

```bash
SAMPLE=./sample.bin
uv run scripts/auto_triage.py "$SAMPLE"          # whole-file entropy, packer strings, next reference
diec "$SAMPLE"                                   # Detect It Easy: packer/protector/compiler signatures
r2 -qc 'iS entropy' "$SAMPLE"                    # per-section entropy column (radare2)
readelf -lW "$SAMPLE"                            # ELF: compare FileSiz and MemSiz per PT_LOAD
```

| Signal | Reading |
|---|---|
| Section entropy > 7.2 on code | Compressed or encrypted |
| Whole-file entropy | Plain compiled code ≈ 5.5–6.5. UPX-packed ELF measured 7.83 vs 5.92 unpacked |
| PE: `VirtualSize` ≫ `SizeOfRawData` on the first section | Space reserved for unpacked code (UPX0 has raw size 0) |
| ELF: no section headers, first `PT_LOAD` `MemSiz` ≫ `FileSiz` | Measured on UPX 4.2 AArch64: `FileSiz 0x1000`, `MemSiz 0x96d80` |
| Imports limited to `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect` | Runtime import resolution |
| Section names `UPX0/UPX1`, `.vmp0/.vmp1`, `.themida`, `.aspack`, `.MPRESS1`, `.petite`, `.enigma1` | Known packer, possibly renamed |
| Entry point outside the first code section, or in the last section | Stub runs first |
| TLS callbacks present on a small binary | Early anti-debug or decryption |

A clean signal is not proof of no packing. Renamed sections and low-entropy XOR stubs pass these checks. A tiny import table on a native binary is a dynamic-resolution suspect regardless of entropy.

## Pick The Approach

| Situation | First move | Fallback |
|---|---|---|
| Stock UPX (`upx -t` says OK) | `upx -d -o unpacked "$SAMPLE"` on the host; it does not execute the sample | — |
| UPX with modified magic or names | Restore `UPX!` magics and `UPX0/UPX1` names in a copy, then `upx -d` | Dynamic dump |
| Known simple 32-bit PE packer (ASPack, FSG, MEW, MPRESS, PEtite, UPX, Yoda) | `unipacker` (emulation) in an x86-64 Linux container | x64dbg + Scylla |
| Custom crypter / loader | x64dbg: break on `VirtualAlloc`/`VirtualProtect`, find the transfer, dump with pe-sieve or Scylla | `hollows_hunter` across all processes |
| Process injection / hollowing | `pe-sieve` / `hollows_hunter` on the target process | Volatility `windows.malfind`, `windows.hollowprocesses` |
| Themida / VMProtect / Enigma | Dump after OEP for strings and unvirtualized code; treat VM handlers as black boxes | Trace I/O behavior, see deobfuscation reference |
| Linux ELF packer | Run to the transfer under gdb, or let it run and dump `/proc/PID/mem` | `gcore`, then analyze the core |
| Android packer / DEX protector | `frida-dexdump` or hook ART's DEX loading | Volatility on an emulator memory image |
| Shellcode stager | `speakeasy --raw` or `qiling` emulation; dump the next stage from the report | Debugger with a breakpoint on the final `jmp`/`call` into new memory |

## UPX And Why `upx -d` Fails
`upx -d` reads the packer's own metadata (`l_info`, `p_info`, `PackHeader`, all tagged with the `UPX!` magic) to reverse the compression. It is a static operation. It fails when a malware author edits that metadata, which costs them nothing and keeps the stub working.

Verified on UPX 4.2.2 with a static AArch64 ELF:
- `upx -t packed` → `[OK]`. `upx -l` shows ratio and format.
- Replacing the three `UPX!` occurrences with `XYZ!` made `upx -d` report `Unpacked 0 files`. The packed program still ran.
- Writing `UPX!` back produced a file that `upx -d` unpacked byte-for-byte equal to the original.

```bash
# 1. Inspect: the PackHeader sits in the last 0x24 bytes; l_info follows the stub's program headers.
python3 -I -c 'import sys; d=open(sys.argv[1],"rb").read(); print("UPX!:", d.count(b"UPX!")); print(d[-0x40:].hex(" "))' "$SAMPLE"
# 2. Restore a replaced 4-byte tag in a copy, then unpack the copy.
TAG='XYZ!'                     # the 4 bytes the author put where UPX! belongs
python3 -I -c 'import sys; d=open(sys.argv[1],"rb").read(); t=sys.argv[3].encode(); print("replaced", d.count(t)); open(sys.argv[2],"wb").write(d.replace(t, b"UPX!"))' "$SAMPLE" restored.bin "$TAG"
upx -t restored.bin && upx -d -o unpacked.bin restored.bin
```

Look for the tag the author used in the last 0x40 bytes (PackHeader) and near the start of the stub (`l_info`). Restore it with the same length. Also restore section names `UPX0`/`UPX1`/`UPX2` on PE. If `upx -d` then fails with a checksum or format error, the author changed more than tags. Switch to dynamic unpacking; do not patch further blindly.

## Windows: Finding The OEP
Run in the Windows VM with x64dbg. Enable TLS callback and entry breakpoints first (x64dbg `init` sets both), and ScyllaHide if the stub checks for a debugger.

### ESP / pushad trick (classic compressors, mostly 32-bit)
1. At the entry point the stub saves registers: `pushad` (x86) or a run of `push` instructions (x64).
2. Step over it. Set a hardware access breakpoint on the saved-register slot: `bph esp, r, 4` (x86) or `bph rsp, r, 8` (x64).
3. `run`. The breakpoint fires at the matching `popad`/`pop` sequence after decompression.
4. Step to the tail jump (`jmp` to a far address, often into the first section). The jump target is the OEP.

This works because the stub restores the original register state just before transferring control. It fails on stubs that never save registers, or that use the stack for decompression.

### Section hop (execute in the original section)
1. Memory Map: find the first section of the main image (UPX0, or the section containing the original code).
2. `bpm SECTION_VA, 0, x` sets a one-shot guard-page execute breakpoint on that whole region.
3. `run`. The first instruction executed in that region is usually the OEP. Writes by the decompressor do not trigger an `x` breakpoint.

### Write-then-execute (crypters, loaders, shellcode stages)
1. `bp VirtualAlloc`, `bp VirtualProtect`, `bp NtProtectVirtualMemory` (catches direct callers of the native API), and on Windows 10+ `bp VirtualAlloc2`.
2. On `VirtualAlloc` return (`rtr`), note `rax` (the region). On `VirtualProtect`, read `rcx` (address), `rdx` (size), `r8` (new protection). `0x10/0x20/0x40/0x80` are the `PAGE_EXECUTE*` values.
3. Set `bpm REGION, 0, x` on a region that was just written and made executable. Continue.
4. When it fires, you are at the first instruction of the next stage. Dump it before it is freed.
5. A stage that is a full PE (look for `MZ` at the region start, or a PE header written into it) can be dumped with pe-sieve or `savedata`. Shellcode stays a raw blob with a recorded base address.

### Exception-driven and other transfers
- Stubs that transfer through `RtlRestoreContext`, `NtContinue`, an SEH/VEH handler, or `SetThreadContext` on a new thread: break on those APIs and read the new instruction pointer from the `CONTEXT` argument (`Rip` at offset `0xF8` on x64).
- `CreateThread` / `NtCreateThreadEx` with a start address in a new region: the start address is the next stage.
- `ResumeThread` on a suspended child after `WriteProcessMemory` is process hollowing. Dump the child, not the parent.

### What OEP code looks like

| Toolchain | First instructions at OEP |
|---|---|
| MSVC x86 | `call __security_init_cookie` then `jmp __scrt_common_main_seh` |
| MSVC x64 | `sub rsp, 28h`; `call __security_init_cookie`; `add rsp, 28h`; `jmp __scrt_common_main_seh` |
| MinGW | `sub rsp, 28h`; set `__mingw_app_type`; `call __tmainCRTStartup` |
| Delphi | `push ebp; mov ebp, esp; add esp, -10h; mov eax, ...; call @InitExe` |
| Go | `jmp _rt0_amd64` into the runtime |
| .NET | No native OEP; the CLR loads metadata. Dump the module and use dnSpy/ILSpy |

## Windows: Dumping And Rebuilding Imports

### pe-sieve and hollows_hunter
Flags below are the parameter names defined in pe-sieve's and hollows_hunter's `params.h` (2025 sources). Values are numeric indexes into each option's list.

```cmd
:: One process. Realigned dump, rebuild imports from IATs, detect shellcode, JSON report.
pe-sieve64.exe /pid 1234 /dmode 3 /imp 3 /shellc 3 /data 3 /dir C:\lab\pesieve /json /jlvl 1

:: Every process, or by name. Unique output dir per run. Suspend suspicious processes instead of killing.
hollows_hunter64.exe /pname sample.exe /dmode 3 /imp 1 /shellc 3 /dir C:\lab\hh /uniqd /suspend
hollows_hunter64.exe /dir C:\lab\hh /uniqd /hooks /threads
```

| Flag | Values |
|---|---|
| `/dmode` | `0` auto, `1` virtual (as in memory), `2` unmapped (raw by section headers), `3` realigned (raw aligned to virtual) |
| `/imp` | `0` none, `1` auto, `2` unerase existing table, `3` rebuild from IATs (terminated blocks), `4` rebuild (terminated or multi-thunk), `5` rebuild (all blocks) |
| `/shellc` | `0` none, `1` patterns, `2` statistics, `3` patterns or stats, `4` patterns and stats |
| `/data` | `0` none … `3` always scan non-executable memory, `4`/`5` include inaccessible pages |
| `/iat` | Scan for IAT hooks: `0` none, `1`–`3` filter levels |
| `/threads` | Scan thread start addresses and stacks for shellcode |
| `/minidmp` | Also write a minidump (`/minidump` is not a flag) |
| `/refl` | Reflection: scan a clone of the process, not the live one |
| `/quiet`, `/json`, `/jlvl 0-2`, `/dir PATH` | Output control |

Read `scan_report.json` (and `dump_report.json`) first: it lists which modules were implanted, replaced (hollowed), or patched, with addresses. Dumped files are named by base address, for example `400000.sample.exe`, and shellcode regions as `.shc`.

### Scylla (x64dbg plugin or standalone)
Scylla works on x86 and x64. Use the 32-bit Scylla (or x32dbg) for 32-bit targets. ImportREC is x86-only; never use it on a 64-bit image.

1. Stop at the OEP in x64dbg. Open Plugins → Scylla. It attaches to the debuggee.
2. `OEP` field: the VA of the current instruction (Scylla fills it from `cip`).
3. `IAT Autosearch`. Check the found `VA` and `Size` against what you see in the dump view: a table of pointers into system DLLs.
4. `Get Imports`. Expand the tree. Invalid entries are red.
5. For invalid entries: right-click → `Trace`/`Disassemble`. A packer often redirects through a thunk (`push api; ret`, `jmp [api]`, or an encrypted pointer). Resolve the real API, edit the entry, or `Cut thunk` if it is junk.
6. `Dump` → `sample_dump.exe`. Then `Fix Dump` on that file → `sample_dump_SCY.exe` with a new `.SCY` section holding the rebuilt import directory.
7. Load `_SCY.exe` in IDA or Ghidra. Check that imports resolve and that calls through the IAT show API names.

Iron rules (also in `SKILL.md`):
- If Scylla cannot resolve the IAT, or the fixed dump fails to parse, stop. Record `E-iat-repair-fail` with the tool, PID, and error. Switch to runtime evidence: breakpoints or Frida hooks on the APIs you need, in the VM. Do not loop on manual IAT edits.
- If the fixed dump crashes when run, it may check its own file size, checksum, or path. Record `E-self-check-crash`. Find the check with breakpoints on `CreateFileW`, `GetFileSize(Ex)`, `ReadFile`, `GetModuleFileNameW` and hash routines. Do not keep patching headers.
- A dump that does not run is still a valid static artifact. Say which you hold.

### Exit-time dump
When the stub detects analysis and exits, the unpacked code is often still mapped at the moment of exit.

```text
bp kernel32.ExitProcess
bp ntdll.NtTerminateProcess
erun
// on hit, before continuing:
minidump "C:\lab\exit.dmp"
```

Then run `pe-sieve64.exe /pid PID /dmode 3 /imp 1 /dir C:\lab\exit` while the process is still paused at the breakpoint. `uv run scripts/dump_memory.py` does not support Windows; it prints a pointer to procdump/WinDbg and exits. `procdump64.exe -ma PID C:\lab\full.dmp` and WinDbg `.dump /ma C:\lab\full.dmp` are the alternatives. Record `E-mem-dump-exitprocess`.

## Linux ELF Unpacking
Run in the Linux lab container or VM. Verified on Ubuntu 24.04 AArch64 with a UPX-packed static binary.

After the stub runs, the unpacked image is an **anonymous** mapping at the original load address. The packed file maps only a small region:

```text
00400000-0047b000 r-xp 00000000 00:00 0           <- unpacked code, no backing file
0048c000-00490000 r--p 00000000 00:00 0
00490000-00497000 rw-p 00000000 00:00 0
ffff9f8a0000-ffff9f8a1000 r--p ... /tmp/packed    <- the stub's own file mapping
```

Dump options, in the guest:

```bash
PID="$(pgrep -n sample)"
uv run scripts/dump_memory.py "$PID" -o dump_x -p x       # executable regions only (default filter is 'w')
uv run scripts/dump_memory.py "$PID" -o dump_all -p all   # everything up to 256 MB per region
uv run scripts/dump_memory.py "$PID" -o dump_core --gdb   # gcore via gdb
gdb -q -nx -batch -p "$PID" -ex "gcore /tmp/sample.core"  # same, directly
```

`dump_memory.py` filters by permission characters. The default `-p w` dumps only writable regions and misses unpacked code that the stub re-protected as `r-x`. Use `-p x` or `-p all` for unpacking. Files are named `mem_<start>_<end>_<perms>_<path>.bin`; an anonymous region is `anon`. The script needs read access to `/proc/PID/mem`: same UID and a permissive Yama `ptrace_scope`, or root.

Stopping at the transfer instead of after the fact:
- gdb: `catch syscall mprotect` and `catch syscall munmap`. The UPX stub `munmap`s itself just before jumping to the original entry. At the last `munmap` return, `stepi` until the PC lands in the anonymous region. Read the original entry point from the restored ELF header at the region start (`x/gx 0x400018` on a non-PIE x86-64 or AArch64 binary is `e_entry`).
- Packers that `memfd_create` + `execve` the payload: `catch syscall memfd_create execve execveat`. The payload is `/proc/PID/fd/N`; copy it before `execve`.
- Packers that decrypt into `mmap(PROT_READ|PROT_WRITE)` then `mprotect(PROT_EXEC)`: at the `mprotect` catchpoint the region is complete.

Analyze the result:
- A core file (`gcore`) is an ELF with one `PT_LOAD` per mapping. IDA and Ghidra load it with all segments at their runtime addresses.
- A raw region dump has no headers of its own unless the stub restored them. Load it in the disassembler as a binary at the region's start address. For a non-PIE image whose first page holds the restored ELF header, `readelf -h` on the dump works.
- `uv run scripts/elf_triage.py dump.bin` and `uv run scripts/elf_symbols.py dump.bin` work on a dump that still has valid headers.

## Android DEX And Native Unpacking
On a rooted lab device or emulator (pre-flight gate in [frida.md](../04-tool-usage/frida.md)):

```bash
PACKAGE_ID="$(apkanalyzer manifest application-id target.apk)"
uv run --with frida-dexdump frida-dexdump -U -f "$PACKAGE_ID" -d -o "./dex_$PACKAGE_ID"
```

`frida-dexdump` scans process memory for `dex\n0` headers, and with `-d` also for headerless DEX by structure. Spawn mode (`-f`) waits `--sleep` seconds (default 5) before scanning, so the packer has time to decrypt. Packers that decrypt per method (instruction-level protection) leave stub methods in the dump; those methods' code arrives only when invoked.

Hook points when you need the exact moment of loading:
- `dalvik.system.InMemoryDexClassLoader.$init` and `dalvik.system.DexClassLoader.$init` (Java).
- `libart.so` `art::DexFileLoader::OpenCommon` / `art::DexFile::DexFile` (native, name varies by Android version; resolve with `ApiResolver('module').enumerateMatches('exports:libart.so!*Dex*Open*')`).
- `android_dlopen_ext` for native payloads written to app storage and loaded.

Native `.so` unpacking on Android follows the Linux procedure. `/proc/PID/maps` and `/proc/PID/mem` are readable with root.

## Emulation-Based Unpackers
Emulators run the stub without a real OS. They still execute sample-controlled logic in your process, so run them in the lab container, not on the host.

| Tool | Command | Scope |
|---|---|---|
| unipacker | `unipacker sample.exe -d out/` (`-p` partitions output by packer, `-i` interactive) | 32-bit PE: ASPack, FSG, MEW, MPRESS, PEtite, UPX, Yoda's; generic unpacking for others. Its pinned `unicorn` fork failed to build on macOS arm64; use an x86-64 Linux container |
| speakeasy | `speakeasy -t sample.exe -o report.json --no-mp --timeout 60`; shellcode: `speakeasy -t sc.bin --raw --arch amd64 -o report.json` (`--arch` is `x86` or `amd64`) | Windows PE, drivers, shellcode. Report lists API calls, dropped files (`--dropped-files-path`), and memory activity |
| qiling | `qltool run -f sample --rootfs ROOTFS --timeout 60000000 -c cov.drcov`; shellcode: `qltool code --os linux --arch x8664 --format bin -f sc.bin` | Linux, Windows, macOS, firmware ISAs. Needs a rootfs with the target's libraries. `--timeout` is in microseconds |

Emulator results are evidence of behavior under that emulator. A stub that checks for missing APIs or timing may take a different path. Confirm the dumped stage against a VM run before concluding.

## Physical Memory And Volatility 3
Use a full memory image when the code hides from user-mode tools (rootkits, injection into other processes, DKOM), or when the VM is about to be reverted. A process dump is faster when one process is enough.

| Need | Tool |
|---|---|
| One process, user mode | pe-sieve, procdump, `dump_memory.py`, `gcore` |
| Whole Linux guest | AVML in the guest, or the hypervisor's memory snapshot |
| Whole Windows guest | WinPmem in the guest, or the hypervisor's memory snapshot |
| No in-guest tool allowed | QEMU `dump-guest-memory -z` from the monitor, or a VMware `.vmem` from a suspended VM |

Acquisition, inside the guest:

```bash
sudo ./avml acquire mem.lime                     # current AVML (subcommands)
sudo ./avml mem.lime                             # older releases (no subcommands)
sudo ./avml acquire --compress mem.lime.compressed
./avml convert mem.lime.compressed mem.lime      # decompress before Volatility unless your vol has AVML support
```

```cmd
:: WinPmem mini (current Velocidex release). Default on x64 is PTE remapping (-2).
winpmem_mini_x64_rc2.exe C:\lab\physmem.raw
winpmem_mini_x64_rc2.exe -1 C:\lab\physmem.raw      :: \Device\PhysicalMemory method
```

The older WinPmem options `--mode`, `-m 3`, and `--volume_mode` belong to retired builds. Check `winpmem_mini_x64_rc2.exe -h` on the build you have.

Volatility 3 (`vol` from `pip install volatility3`; `vol.py` from a git checkout). Plugin names below were checked against the installed volatility3 plugin list. Global options such as `-f`, `-o` (output directory), `-r` (renderer: `pretty`, `csv`, `json`, `jsonl`), and `-q` go before the plugin name.

```bash
IMG=physmem.raw
OUT=vol_out && mkdir -p "$OUT"
vol -f "$IMG" windows.info
vol -f "$IMG" -r csv windows.pstree > "$OUT/pstree.csv"
vol -f "$IMG" windows.psscan                         # pool scan; finds unlinked processes
vol -f "$IMG" windows.psxview                         # cross-view hidden-process check
vol -f "$IMG" windows.cmdline
vol -f "$IMG" windows.malfind --pid 1234
vol -f "$IMG" -o "$OUT" windows.malfind --pid 1234 --dump
vol -f "$IMG" windows.hollowprocesses
vol -f "$IMG" windows.ldrmodules --pid 1234           # modules missing from loader lists
vol -f "$IMG" windows.vadinfo --pid 1234
vol -f "$IMG" -o "$OUT" windows.pslist --pid 1234 --dump
vol -f "$IMG" -o "$OUT" windows.dlllist --pid 1234 --dump
vol -f "$IMG" -o "$OUT" windows.pedump --pid 1234 --base 0x7ff6a0000000
vol -f "$IMG" windows.netscan
vol -f "$IMG" windows.ssdt
vol -f "$IMG" windows.callbacks
vol -f "$IMG" windows.driverscan
```

```bash
IMG=mem.lime
vol -f "$IMG" linux.pslist
vol -f "$IMG" linux.psscan
vol -f "$IMG" linux.pstree
vol -f "$IMG" linux.malfind
vol -f "$IMG" -o "$OUT" linux.proc.Maps --pid 1234 --dump
vol -f "$IMG" -o "$OUT" linux.elfs --pid 1234 --dump
vol -f "$IMG" linux.check_syscall.Check_syscall
vol -f "$IMG" linux.hidden_modules
vol -f "$IMG" linux.lsmod
vol -f "$IMG" linux.sockstat
vol -f "$IMG" linux.bash
```

- Short names (`windows.pslist`) resolve to the full class (`windows.pslist.PsList`) when unique. Class names are case-sensitive: `linux.check_syscall.Check_syscall`, not `Check_Syscall`.
- Newer releases also list malware plugins under `windows.malware.*` and `linux.malware.*`. The old names still resolve.
- Windows symbols: Volatility downloads PDB-derived symbol tables from Microsoft on first use. In an `offline` lab, pre-populate the symbol cache or the run fails with an unsatisfied requirement.
- Linux symbols: you need an ISF JSON for the exact kernel build, made with `dwarf2json linux --elf vmlinux-with-debuginfo`, placed in the `symbols/linux/` directory (or passed with `-s`). No matching ISF, no Linux plugin output.
- A `malfind` hit is a candidate: private, executable, often `PAGE_EXECUTE_READWRITE` memory. JIT engines (.NET, browsers) produce benign hits. Confirm with the dumped bytes.

## Devirtualization Boundary
Dumping after OEP removes the outer packer. It does not remove a code virtualizer. VMProtect and Themida leave selected functions as bytecode run by a handler loop. Signs: a function body that pushes context and jumps into a dispatcher with an indirect `jmp reg` over a handler table.

- Treat each virtualized function as a black box. Record its inputs and outputs from a trace or a hook.
- Lifting (Triton, Miasm, VTIL-based tools, NoVmp for some VMProtect 3 builds) is version-specific. A lift is validated only when it reproduces the observed input/output pairs.
- The staged procedure for recovering logic from black boxes is in [fuzzing-for-reversing.md](fuzzing-for-reversing.md) and [deobfuscation-anti-analysis.md](../01-static-architectures/deobfuscation-anti-analysis.md).

## Verification
- An unpacked artifact is accepted when: the disassembler shows code at the claimed OEP, imports resolve to API names, and strings that were absent in the packed file are present.
- Record the OEP as an RVA, the method used to find it, the dump tool and mode, and the import repair result.
- Compare a behavior from the dump (a string, a config field, an API sequence) with the live run. They must agree.
- For memory images, record the acquisition tool and version, the image hash, the Volatility version, and the symbol source.

## Boundaries
- Static unpackers (`upx -d`) can run on the host because they do not execute the sample. Everything else runs in the lab.
- Do not run a dumped or fixed binary outside the lab. It is still the sample.
- Do not paste multi-megabyte dumps into the conversation. Keep paths, hashes, and the relevant offsets.
- A dump that will not run is still a valid static artifact. Do not spend the session making it run.
