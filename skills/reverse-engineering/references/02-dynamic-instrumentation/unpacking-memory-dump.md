# Dynamic Unpacking, OEP Detection & Memory Dumping

## Title & Overview
- **Domain**: Packed executables, runtime crypters, dynamic loaders, and self-modifying code (PE, ELF, Mach-O).
- **Scope**: Detecting runtime packing (UPX, Themida, VMProtect, custom crypters), entropy profiling, Original Entry Point (OEP) identification via tail jump and `pushad`/`popad` patterns, devirtualization of VM-protected dispatchers, memory dumping via `dump_memory.py`, and Import Address Table (IAT) reconstruction with Scylla.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Static analysis reveals packed sections (e.g. `UPX0`, `UPX1`, `.vmp0`, `.themida`, `.packer`, or high Shannon entropy > 7.2 across executable sections).
- Executable imports are minimal: only `LoadLibraryA` + `GetProcAddress` on Windows, or `dlopen` + `dlsym` on Linux.
- Binary exhibits structural anomalies: Raw Size ≈ 0 while Virtual Size is large, or section flags marked both Writable and Executable (`RWX`).
- Control flow jumps into dynamically allocated heap/stack regions or anonymous mapped memory.
- Execution reaches a complex fetch-decode-dispatch loop executing custom virtual bytecode rather than compiler-generated instructions.

---

## Tooling & CLI/MCP Actions

- **Triage & Identification**:
  - `diec` (Detect It Easy command line) or `rabin2 -S <binary>`.
  - Entropy profiler: `binwalk -E <binary>`.
- **Process-Level Memory Dumpers**:
  - `uv run scripts/dump_memory.py <pid> -o <dump_dir>`.
  - PE-sieve / HollowsHunter: `pe-sieve /pid <pid> /dmode 3`.
  - Windows Sysinternals ProcDump: `procdump.exe -ma <pid> target_process.dmp`.
- **Physical Memory Acquisition Frameworks**:
  - Linux: Microsoft AVML (`avml --compress /tmp/mem.lime`).
  - Windows: Velocidex WinPmem (`winpmem.exe -o mem.raw --mode 1`).
- **Debugger & Unpacking Engines**:
  - Windows PE: `x64dbg` with Scylla (built-in IAT recovery) and ScyllaHide (anti-anti-debug).
  - Linux ELF: GDB (`pwndbg` / `gef`), `gcore <pid>`, `/proc/<pid>/maps` + `/proc/<pid>/mem`.
  - Deobfuscation & Devirtualization: Triton, Miasm, VTIL, NoVmp.
- **Volatile Memory Analysis & Forensics**:
  - Volatility 3 (`vol` / `vol.py`) for Windows and Linux kernel memory triage.
  - Rekall Forensic Framework.

## Core Methodologies & Step-by-Step Technical Workflow

### 1. Detecting Runtime Packing & Entropy Screening

#### Entropy Profiling
- **Shannon Entropy Range**:
  - `0.0 - 5.5`: Plain text, sparse tables, uncompressed code.
  - `5.5 - 6.8`: Standard compiled native code and CRT runtime.
  - `7.0 - 8.0`: Compressed archives, encrypted payload buffers, packed stubs.
- Run CLI triage:
  ```bash
  # Check file with Detect It Easy
  diec target.exe
  # Check section entropy and characteristics
  rabin2 -S target.exe
  # Search for packer strings in raw binary
  grep -E -a "UPX|Themida|VMProtect|ASPack|MPRESS|Enigma" target.exe
  ```

#### TLS Callbacks & Early Execution
Packed executables frequently place anti-debugging and decryption stubs in Thread Local Storage (TLS) callbacks:
- TLS callbacks execute **before** the PE Entry Point is reached.
- In `x64dbg`: Configure `Options -> Events` and check **TLS Callbacks** and **System Breakpoint**.
- In GDB/pwndbg: Set hardware breakpoint on the TLS callback address obtained from the PE header directory (`IMAGE_DIRECTORY_ENTRY_TLS`).

### 2. Original Entry Point (OEP) Detection Methodologies

#### Method A: The Pushad / Popad & Tail Jump Pattern (Standard Crypters / UPX)
1. At entry point, the packer saves register state:
   ```assembly
   pushad          ; Save EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
   ```
2. Set a hardware breakpoint on the stack pointer immediately after `pushad`:
   - In x64dbg: Step over `pushad`, look at `ESP`, right-click in dump -> `Breakpoint -> Hardware, Access -> Dword`.
3. Run execution (`F9`). When the packer finishes unpacking, it executes:
   ```assembly
   popad           ; Restore registers
   jmp 0x00401500  ; Long tail jump to OEP outside packer stub section
   ```
4. Stepping across this long jump lands execution directly at the real compiler CRT entry point (`OEP`).

#### Method B: Memory Protection Page Breakpoints (Write-Then-Execute)
1. Inspect the memory map of the process in `x64dbg` or GDB.
2. Locate the main `.text` or executable section of the primary binary module (currently holding encrypted data or zeros).
3. Set a memory page breakpoint or hardware execute breakpoint on the target `.text` section:
   - In x64dbg: In Memory Map tab, right-click `.text` -> `Set Memory Breakpoint -> Break on Execute`.
4. Run execution. The unpacker unpacks and writes data into memory, then eventually transfers execution into the newly written `.text` section.
5. The memory breakpoint triggers on the first instruction executed in the unpacked section: this instruction is the OEP.

#### Method C: Compiler Runtime Entry Signatures
Standard compilers produce recognizable initialization sequences at OEP:
- **MSVC (Visual C++)**:
  ```assembly
  call sub_4011A0       ; __security_init_cookie
  jmp  sub_401200       ; __scrt_common_main_seh
  ```
- **GCC / MinGW**:
  ```assembly
  push rbp
  mov  rbp, rsp
  and  rsp, -16
  call sub_401080       ; __main
  ```

### 3. Memory Dumping via `dump_memory.py` and Debugger APIs

Once halted at OEP, dump the unpacked memory pages before the program terminates or clears memory:

```bash
# Using project dump script against running process
uv run scripts/dump_memory.py <target_pid> -o /tmp/unpacked_dump/

# Command output extracts all writable / executable regions:
# /tmp/unpacked_dump/mem_00400000_00450000_r-x_target.exe.bin
# /tmp/unpacked_dump/mem_00450000_00470000_rw-_target.exe.bin
```

In GDB:
```text
(gdb) info proc mappings
(gdb) dump binary memory /tmp/unpacked_elf.bin 0x00400000 0x00480000
```

In Windows using `pe-sieve`:
```cmd
pe-sieve.exe /pid <pid> /dmode 3 /minidump
```

### 4. Import Address Table (IAT) Reconstruction & The IAT Repair Iron Rules

Packers destroy the original Import Table, resolving external DLL APIs dynamically via `LoadLibraryA` and `GetProcAddress`. A raw memory dump has unmapped import pointers.

#### The IAT Repair Iron Rules (MANDATORY)
1. **Tool Selection Constraint**:
   - **x86 (32-bit PE)**: Use **ImportREC** (or Scylla).
   - **x64 (64-bit PE)**: Use **Scylla** (or x64dbg built-in Scylla plugin). NEVER attempt to use 32-bit ImportREC on 64-bit PE binaries.
2. **Fast-Failure Boundary**:
   - Attempt automated/semi-automated reconstruction (`IAT Autosearch` -> `Get Imports` -> `Fix Dump`).
   - If the auto-repair tool throws errors, generates corrupt pointers, or the resulting output binary fails to parse:
     - **STOP STATIC IAT REPAIR IMMEDIATELY**. Do not get trapped in an endless loop modifying static import structures.
     - Record the failure in Evidence as `E-iat-repair-fail` (capturing tool name, target PID, and failure details).
     - **TRANSITION TO DYNAMIC API BREAKPOINTS**: Switch directly to dynamic debugging in memory. Set hardware breakpoints on critical functional APIs (`CreateFile`, `InternetOpen`, `RegSetValue`, `VirtualAlloc`) to intercept and resolve dynamic API pointers at runtime. This fulfills the import analysis contract via dynamic evidence.
3. **Self-Check Crash Bypass (`E-self-check-crash`)**:
   - If the unpacked and patched binary crashes immediately upon launch (e.g. instant crash, silent exit, or exception):
     - The binary likely implements runtime self-integrity checks (PE file size verification, PE header CRC32, or hash checks against disk bytes).
     - **STOP FILE PATCHING IMMEDIATELY**. Continuing to patch disk headers will only continue triggering the integrity check.
     - Record `E-self-check-crash` in Evidence.
     - In the dynamic debugger, set hardware execution breakpoints on file-read and integrity-checking APIs: `CreateFileA/W`, `GetFileSize`, `GetFileSizeEx`, `ReadFile`, and hashing routines (MD5/CRC32). Trace where the file is read from disk and patch the comparison branch or force the check return value in memory.

#### Scylla Step-by-Step Workflow
1. **Attach Scylla**:
   - In `x64dbg`, open the built-in Scylla plugin (or launch `Scylla.exe` standalone and attach to `<pid>`).
2. **Configure OEP**:
   - In the `OEP` field, enter the Virtual Address (or Relative Virtual Address) of the identified OEP.
3. **IAT Autosearch**:
   - Click `IAT Autosearch`. Scylla searches memory for arrays of API pointers pointing into loaded DLLs (`kernel32.dll`, `user32.dll`, `ntdll.dll`).
4. **Get Imports**:
   - Click `Get Imports`. Scylla maps every pointer to DLL exports and displays the resolved imports tree.
5. **Handle Unresolved Imports**:
   - If red entries appear (unresolved pointers), this indicates API redirection (thunks created by the packer to disguise API calls).
   - Trace the unresolving pointer to determine if it forwards to a standard DLL export. Right-click the item and select `Disassemble / Trace`.
6. **Dump and Fix**:
   - Click `Dump` to write the memory image to `dump.exe`.
   - Click `Fix Dump` and select `dump.exe`. Scylla creates a new section (`.scy`) containing the valid rebuilt Import Directory, IAT, and recalculated section headers.
   - The resulting `dump_SCY.exe` can now be analyzed in IDA Pro or Ghidra with full cross-references and symbol recognition.

### 5. ExitProcess Memory Dumping Pattern
When dynamic unpacking is thwarted by anti-debugging countermeasures that force a process exit:
- Pre-set a fallback breakpoint on `kernel32.ExitProcess` and `ntdll.NtTerminateProcess`.
- When the breakpoint triggers on process exit:
  - **DO NOT TERMINATE OR RESTART THE PROCESS**.
  - The process address space is frozen in its fully decrypted memory state.
  - Immediately invoke `dump_memory.py`:
    ```bash
    uv run scripts/dump_memory.py <pid> -o /tmp/exitprocess_dump/
    ```
  - Recover unpacked executable sections and strings directly from the dumped memory snapshot.
  - Document artifact in Evidence as `E-mem-dump-exitprocess`.

### 6. Devirtualization of VM-Protected Dispatchers (VMProtect / Themida)

When unpacking a virtualized binary, outer packing stubs are removed, but the core routines remain converted into custom bytecode:

```text
Target Code  --> [ VM Entry Stub ]
                      | Saves Native Registers (Context Structure)
                      v
                 [ VM Dispatcher Loop ] <----------------+
                      | Fetches Next Virtual Opcode      |
                      | Decodes Opcode via Table/Math    |
                      | Computes Handler Address         |
                      v                                  |
                 [ Virtual Handler Routine ] ------------+
                      | Executes Micro-Operation (e.g. VADD, VXOR)
                      | Updates Virtual Context
                      v (When done)
                 [ VM Exit Stub ]
                      | Restores Native Registers
                      v
                 Target Native Continuation
```

#### Step-by-Step Devirtualization Workflow
1. **Identify the Dispatcher Loop**:
   - Look for an indirect jump instruction: `jmp rax` or `jmp [rbx + rsi*8]`.
   - The dispatcher fetches bytecode bytes, decrypts them with a rolling key (e.g., `xor dl, al; ror dl, 3`), and indexes into a jump table.
2. **Map Handler Semantics via Symbolic Execution**:
   - Do not reverse every handler by hand. Isolate individual handler basic blocks and lift them using Triton or Miasm.
   - Symbolic execution strips out obfuscation noise (MBA expressions, dead stores, junk instructions), yielding the pure mathematical operation (e.g., `rax = rax + rbx`).
3. **Trace Virtual Instruction Stream**:
   - Set a breakpoint on the VM dispatcher loop.
   - Log the virtual instruction pointer and executed handler address on each loop iteration.
4. **Lift to Intermediate Representation (VTIL)**:
   - Lift the extracted opcode stream into VTIL (Virtual Translation Intermediate Language).
   - Execute optimization pipelines: Dead-Code Elimination (DCE), Constant Folding, and Peephole Optimization.
   - Reconstruct clean native control flow graphs from simplified VTIL blocks.

---

### 7. Process-Level Dumping vs. Full Physical Memory Acquisition

Memory acquisition sits on a duality between rapid process-scoped carving and comprehensive host-level physical memory triage. Selecting the proper acquisition tier dictates whether ephemeral forensic indicators survive analysis.

#### Acquisition Strategy Matrix

| Capability / Dimension | Process-Level Memory Dump | System Physical Memory Capture |
|---|---|---|
| **Primary Tools** | `dump_memory.py`, PE-sieve, HollowsHunter, ProcDump, `gcore` | Microsoft AVML (Linux), Velocidex WinPmem (Windows) |
| **Execution Scope** | Single user-mode process address space (`VAD` tree / page tables) | Entire physical RAM (Kernel space, all processes, hardware buffers) |
| **Primary Objective** | Rapid payload carving, unpacked code recovery, heap string inspection | Rootkits, DKOM, hidden processes, injected DLLs, kernel hooks |
| **Artifacts Recovered** | Decrypted PE/ELF headers, injected shellcode, config buffers | Unlinked `EPROCESS` blocks, active network sockets, driver objects, SSDT/IDT hooks |
| **Kernel Hook Detection**| No (blind to kernel-level tampering and rootkit masking) | Yes (direct inspection of kernel paging structures and driver objects) |
| **Acquisition Overhead**| Milliseconds; minimal disk footprint | Seconds to minutes; output matches physical RAM allocation size |
| **Trigger Window** | At OEP arrival or before `ExitProcess` / termination | Immediately prior to guest VM shutdown or snapshot rollback |

#### Triage Decision Workflow
1. **Use Process-Level Dumping when**:
   - Target is a user-mode dropper, crypter, or standard ransomware strain.
   - Objective is extracting the clean unpacked payload binary, dumping decrypted C2 configuration blocks, or recovering encryption keys from heap memory.
   - Low overhead and fast turnaround inside automated triage pipelines are required.
2. **Use Full Physical Memory Capture when**:
   - Target drops or interacts with kernel drivers (`.sys`, `.ko`), rootkits, or bootkits.
   - Direct Kernel Object Manipulation (DKOM) is suspected (e.g., process unlinked from `ActiveProcessLinks` or hidden from task managers).
   - Analyzing advanced code injection across arbitrary system processes (AtomBombing, Process Doppelgänging, Process Ghosting).
   - Extracting volatile system-wide network sockets, active TCP connections, credential artifacts (`lsass.exe`), or bash shell history.

---

### 8. Microsoft AVML (Acquire Volatile Memory for Linux)

Microsoft AVML is a portable, memory-safe volatile memory acquisition tool for Linux written in Rust.

#### Architecture & Mechanism
- **Zero Compilation Overhead**: Built as a fully static, standalone Rust binary. Does not require target kernel headers, GCC, or dynamic kernel module compilation (unlike classic LiME kernel module builds).
- **Kernel Access Sources**:
  - `/dev/crash`: Red Hat / CentOS memory crash driver.
  - `/dev/fmem`: Direct physical memory driver when present.
  - `/proc/kcore`: Fallback mechanism reading ELF core format of kernel memory space. AVML parses the kernel page table mappings to extract raw physical pages.
- **Compression & Streaming**:
  - Employs inline multi-threaded LZ4 compression (`--compress`).
  - Direct streaming to remote storage via Azure Blob SAS URLs (`--url`), bypassing local disk writes on compromised hosts.

#### CLI Invocations
```bash
# Standard acquisition with inline LZ4 compression (LiME format)
sudo ./avml --compress /tmp/mem.lime

# Uncompressed acquisition to raw memory image
sudo ./avml /tmp/mem.raw

# Force specific memory source (/proc/kcore)
sudo ./avml --source /proc/kcore /tmp/mem.raw

# Direct cloud upload without storing full image on target filesystem
sudo ./avml --compress --url "https://myaccount.blob.core.windows.net/evidence/mem.lime?st=...&sig=..."
```

#### Post-Acquisition Volatility 3 Analysis
Analyze captured Linux memory images (`mem.lime` or `mem.raw`) using Volatility 3:
```bash
# Enumerate running processes (including memory maps)
vol -f /tmp/mem.lime linux.pslist.PsList

# Detect hidden processes unlinked from kernel lists
vol -f /tmp/mem.lime linux.psaux.PsAux

# Detect hidden or injected executable code pages
vol -f /tmp/mem.lime linux.malfind.Malfind

# Recover bash command history from memory
vol -f /tmp/mem.lime linux.bash.Bash

# Verify system call table integrity against rootkit hooks
vol -f /tmp/mem.lime linux.check_syscall.Check_Syscall

# Scan active network connections and sockets
vol -f /tmp/mem.lime linux.sockstat.Sockstat

# List loaded kernel modules (LKM rootkit detection)
vol -f /tmp/mem.lime linux.lsmod.Lsmod
```

---

### 9. Velocidex WinPmem (Physical Memory Acquisition for Windows)

Velocidex WinPmem is an open-source, high-performance physical memory acquisition tool for Windows operating systems.

#### Architecture & Driver Mechanisms
- **Kernel Driver Integration**: Deploys a signed 32-bit or 64-bit kernel driver (`winpmem.sys`) dynamically into the kernel space to establish raw hardware page mapping.
- **Acquisition Modes (`-m` / `--mode`)**:
  - **Mode 1 (`MmMapIoSpace`)**: Maps physical memory into kernel virtual address space via the standard NT kernel executive API `MmMapIoSpace`. Reliable on older Windows releases.
  - **Mode 2 (`\\.\PhysicalMemory`)**: Directly opens and reads the hardware physical memory section object `\Device\PhysicalMemory`. Requires high privilege and is frequently restricted on modern Windows kernels.
  - **Mode 3 (PTE Remapping)**: Maps physical memory pages directly by editing Page Table Entries (PTEs) in the kernel page table. Completely bypasses kernel restrictions and `MmMapIoSpace` limits on Windows 10, Windows 11, and Windows Server 2019/2022.
- **Output Formats**:
  - **Raw Memory Image**: Flat contiguous byte stream of physical RAM blocks.
  - **Microsoft Crash Dump format (`.dmp`)**: Formatted as a kernel crash dump (`--volume_mode 2`), making it directly loadable into WinDbg for live kernel debugging symbols.

#### CLI Invocations
```cmd
:: Dump physical memory using Mode 1 (standard MmMapIoSpace)
winpmem.exe -o mem.raw --mode 1

:: High-performance acquisition using Mode 3 (PTE remapping bypass)
winpmem.exe -o mem.raw -m 3

:: Generate a Microsoft Crash Dump image compatible with WinDbg
winpmem.exe -o crash.dmp -m 3 --volume_mode 2

:: Extract driver only (for scripted or manual deployment)
winpmem.exe -e winpmem.sys
```

#### Post-Acquisition Volatility 3 Analysis
Process the captured Windows physical memory image with Volatility 3 plugins:
```bash
# Process enumeration (standard active process tree)
vol.py -f mem.raw windows.pslist

# Detect hidden processes via DKOM (comparing PsActiveProcessHead vs thread scanning)
vol.py -f mem.raw windows.psscan

# Identify process tree hierarchy
vol.py -f mem.raw windows.pstree

# Detect injected code, shellcode, and unmapped executable memory segments
vol.py -f mem.raw windows.malfind

# Enumerate active and closed network connections / sockets
vol.py -f mem.raw windows.netscan

# Enumerate loaded DLLs for a suspicious process PID
vol.py -f mem.raw windows.dlllist --pid <target_pid>

# Scan for injected or unlinked kernel drivers
vol.py -f mem.raw windows.driverscan

# Dump memory segment containing injected payload
vol.py -f mem.raw windows.malfind --pid <target_pid> --dump
```


## Boundaries & Anti-Patterns
- **Do not run unknown packed binaries on bare-metal workstations**: Execute unpacking and dynamic observation only within disposable research VMs.
- **Do not attempt to execute raw memory dumps directly**: Memory dumps require header reconstruction, section alignment adjustment, and IAT rebuilds before they can run; they are intended for static decompiler analysis.
- **Do not confuse Virtual Size with Raw Size**: Memory dumps reflect Virtual Size (aligned to page boundaries, e.g. `0x1000`). Disk binaries reflect Raw Size (aligned to file boundaries, e.g. `0x200`). Adjust headers accordingly.
