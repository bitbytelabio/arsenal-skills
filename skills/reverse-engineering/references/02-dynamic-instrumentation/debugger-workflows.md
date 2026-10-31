# Debugger Workflows & Instruction-Level Tracing

## Title & Overview
- **Domain**: Native and managed runtime debuggers (GDB with pwndbg/gef, LLDB, WinDbg, x64dbg).
- **Scope**: Controlled execution, hardware vs software breakpoints, memory watchpoints, register/memory inspection, stack frame reconstruction, remote `gdbserver` inside guest VMs, and anti-debugging evasion handling inside isolated virtual machines.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Static analysis is insufficient to determine runtime state, dynamic function pointers, computed jumps, or unpack obfuscated payloads.
- Authorized environment: Debugging is performed strictly inside an isolated guest VM (UTM, QEMU, research sandbox).
- Need to trace dynamic register values, inspect heap allocations, verify decryptor loops, or examine runtime state transitions at machine code level.
- Binary emits anti-debugging symptoms: unexpected premature exits, `SIGTRAP` handling, calls to `ptrace(PTRACE_TRACEME)`, PEB `BeingDebugged` checks, or timing checks via `rdtsc`.

---

## Tooling & CLI/MCP Actions

### Primary Debugger Engines
- **Linux ELF**:
  - `gdb` augmented with `pwndbg` (exploit & heap state) or `gef` (architecture support and multi-architecture emulation).
  - Remote stub: `gdbserver` running inside target Linux VM/container.
- **macOS / iOS Mach-O**:
  - `lldb` (CLI or connected to remote `debugserver`).
- **Windows PE / Drivers**:
  - `windbg` / `cdb` (command-line, kernel-mode, and modern JavaScript scripting via `dx`).
  - `x64dbg` (interactive user-mode debugging, Scylla integration, ScyllaHide anti-anti-debugging plugin).

### VM Automation & Remote Connectivity
- **Remote GDB Server Invocation**:
  ```bash
  # Inside Guest VM (attach to PID or spawn new process)
  gdbserver 0.0.0.0:1234 /path/to/target_binary arg1 arg2
  gdbserver --attach 0.0.0.0:1234 <pid>
  
  # On Host / Analysis Machine
  gdb -q -ex "set architecture i386:x86-64" \
         -ex "target remote <vm_ip>:1234" \
         -ex "set sysroot /tmp/guest_root" \
         target_binary
  ```

---

## Core Methodologies & Step-by-Step Technical Workflow

### 1. VM Isolation & Session Initialization
1. Ensure execution occurs inside an isolated VM snapshot using UTM or QEMU disposable mode.
2. Disable Address Space Layout Randomization (ASLR) when deterministic address correlation with static disassemblers is required:
   ```bash
   # Linux GDB
   gdb -q -ex "set disable-randomization on" ./target
   # System-wide in guest (optional)
   sudo sysctl -w kernel.randomize_va_space=0
   
   # Windows WinDbg / x64dbg
   # ASLR is bound to binary headers unless modified or relocated, or run under image execution flags:
   # _IMAGE_OPTIONAL_HEADER.DllCharacteristics (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE bit stripped)
   ```
3. Set the initial breakpoint before control flow executes untrusted code:
   - For standard binaries: Break on `main` or Entry Point (`_start`).
   - For Windows binaries with TLS callbacks: Break on TLS callbacks before entry point (`break *0x...` or x64dbg `Events -> Break on TLS`).

### 2. Breakpoint Strategies: Hardware vs Software & Memory Watchpoints

| Breakpoint Type | Underlying Mechanism | Modification to Memory | Limit per Core | Primary Use Case |
|---|---|---|---|---|
| **Software Breakpoint** | Replaces instruction opcode byte with `0xCC` (`INT 3` on x86/x64) or `0xD4200000` (`BRK #0` on ARM64) | Modifies target memory page; trips checksums/hash self-checks | Unlimited | General execution control flow |
| **Hardware Execution Breakpoint** | CPU Debug Registers (`DR0`-`DR3` on x86, `HW_BREAKPOINT` on ARM) | Zero memory modification; completely transparent to memory integrity scans | 4 on x86/x64, 2–16 on ARM | Self-modifying code, packed stubs, anti-debug hooks checking code hashes |
| **Memory Watchpoint (Hardware Data)** | CPU Debug Registers (`DR0`-`DR3` configured for Write `1` or Read/Write `3`) | Zero memory modification | 4 registers | Detecting when a decryption key is written, monitoring stack/heap variable changes |
| **Page Guard / Memory Access Breakpoint** | Changes page protection to `PAGE_GUARD` or removes read/write permissions via `mprotect` | Modifies OS memory descriptor flags | Virtual memory pages | Detecting execution transition into decrypted memory sections |

#### Command Syntax Comparison Across Debuggers

```text
Operation                       GDB (pwndbg/gef)              LLDB                          WinDbg / cdb                  x64dbg
--------------------------------------------------------------------------------------------------------------------------------
Set Software Breakpoint         b *0x00401122                 b -a 0x00401122               bp 0x00401122                 bp 0x00401122
Set Hardware Breakpoint (Exec)  hb *0x00401122                b set -a 0x00401122 -H        ba e 1 0x00401122             bph 0x00401122, x
Set Memory Watchpoint (Write)   watch *(int*)0x00602000       watchpoint set expression ... ba w 4 0x00602000             bph 0x00602000, w, 4
Set Memory Watchpoint (R/W)     awatch *(int*)0x00602000      watchpoint set expr -w r/w    ba r 4 0x00602000             bph 0x00602000, rw, 4
Conditional Breakpoint          b *0x401000 if $rdi == 0x20   b -a 0x401000 -c '$rdi==0x20' bp 0x401000 ".if (@rdi=0x20) {} .else {gc}"  bp 0x401000, rdi == 0x20
List Breakpoints                info breakpoints              breakpoint list               bl                            bplist
Delete Breakpoint               delete 1                      breakpoint delete 1           bc 0                          bc 0
```

### 3. Execution Control & Instruction Stepping
- **Step-Over (`nexti` / `ni` in GDB, `ni` in LLDB, `p` in WinDbg/x64dbg)**:
  - Advances execution by one instruction. If the instruction is a `CALL`, execution runs without pausing inside the subroutine, halting at the instruction immediately following the call.
  - *Best Practice*: Step over standard library routines (`libc`, `ntdll`, `kernel32`, `MSVCRT`) to avoid losing focus in boilerplate runtime code.
- **Step-Into (`stepi` / `si` in GDB, `si` in LLDB, `t` in WinDbg/x64dbg)**:
  - Follows control flow directly into called procedures, subroutines, or interrupt handlers.
  - *Best Practice*: Step into unknown indirect calls (`call rax`, `call [rbx + 0x18]`) to uncover dynamically computed dispatch targets and virtual call handlers.
- **Step-Out / Return (`finish` in GDB, `thread step-out` in LLDB, `pt` in WinDbg/x64dbg)**:
  - Resumes execution until the current stack frame returns to its caller, stopping immediately at the return site.

### 4. Register State & Memory Inspection

#### Register Inspection
- **x86-64 System V AMD64 ABI** (Linux/macOS):
  - Arguments passed in: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`.
  - Return value stored in: `RAX`.
- **x86-64 Microsoft x64 ABI** (Windows):
  - Arguments passed in: `RCX`, `RDX`, `R8`, `R9` (with 32-byte shadow space allocated on stack).
  - Return value stored in: `RAX`.
- **ARM64 (AArch64)**:
  - Arguments passed in: `X0` - `X7`.
  - Return value stored in: `X0`.

#### Memory Dump & Inspection Commands
```bash
# GDB
# Inspect 16 quadwords from stack
x/16gx $rsp
# Inspect null-terminated ASCII/UTF-8 string
x/s 0x00404080
# Display instruction context (5 instructions at RIP)
x/5i $rip
# Dump memory range to file
dump binary memory /tmp/unpacked_payload.bin 0x00400000 0x00450000

# LLDB
memory read --format x --size 8 --count 16 $rsp
memory read --format s 0x00404080
memory read --outfile /tmp/payload.bin --binary 0x00400000 0x00450000

# WinDbg
# Display 16 pointer-sized values at RSP
dp @rsp L10
# Display ASCII / Unicode string
da 0x00404080
du 0x00404080
# Write memory range to file
.writemem C:\dump\payload.bin 0x00400000 L?0x50000
```

### 5. Scripting Automated Debugging Sessions

#### GDB Python Automation Script (`trace_decryption.py`)
```python
import gdb

class DecryptTracer(gdb.Breakpoint):
    def __init__(self, location, key_buffer_reg):
        super(DecryptTracer, self).__init__(location, gdb.BP_HARDWARE)
        self.key_buffer_reg = key_buffer_reg
        self.hit_count = 0

    def stop(self):
        self.hit_count += 1
        buf_addr = int(gdb.parse_and_eval(f"${self.key_buffer_reg}"))
        inferior = gdb.selected_inferior()
        data = inferior.read_memory(buf_addr, 32)
        hex_dump = " ".join(f"{b:02x}" for b in data)
        print(f"[*] Decrypt Loop Hit {self.hit_count} | Addr: 0x{buf_addr:x} | Data: {hex_dump}")
        # Return False to continue execution without stopping the debugger
        return False

# Register breakpoint in GDB session:
# (gdb) source trace_decryption.py
# (gdb) python DecryptTracer("*0x401560", "rsi")
```

#### WinDbg JavaScript Engine Automation (`dx` Script)
```javascript
"use strict";

function logCryptoCalls() {
    var ctl = host.namespace.Debugger.Utility.Control;
    var bp = ctl.ExecuteCommand("bp bcrypt!BCryptDecrypt \"dx @$curprocess.Io.Print('BCryptDecrypt invoked\\n'); gc\"");
    host.diagnostics.debugLog("[+] BCryptDecrypt hook armed.\n");
}
```

### 6. Anti-Debugging Evasion Strategies

#### Linux Anti-Debugging
- **`ptrace(PTRACE_TRACEME, 0, 1, 0)`**:
  - Detection: Returns `-1` (errno `EPERM`) if already traced.
  - Evasion: Hook or patch `ptrace` call return value to `0`:
    ```text
    (gdb) catch syscall ptrace
    (gdb) commands
      silent
      set $rax = 0
      continue
    end
    ```
- **`/proc/self/status` `TracerPid`**:
  - Detection: Binary reads `/proc/self/status` and verifies if `TracerPid: 0`.
  - Evasion: Intercept `read` or `openat` via LD_PRELOAD or redirect file path to a forged `/tmp/status` file reporting `TracerPid: 0`.

#### Windows Anti-Debugging
- **PEB Flags (`BeingDebugged`, `NtGlobalFlag`)**:
  - `PEB.BeingDebugged` at `fs:[0x30] + 0x02` (x86) or `gs:[0x60] + 0x02` (x64).
  - `PEB.NtGlobalFlag` at `+0x68` (x86) or `+0xbc` (x64) set to `0x70` (`FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS`).
  - Evasion in WinDbg:
    ```text
    kd> !peb
    # Clear BeingDebugged
    eb (@@masm(@$peb+0x2)) 0
    # Clear NtGlobalFlag
    ed (@@masm(@$peb+0xbc)) 0
    ```
  - Evasion in x64dbg: Enable ScyllaHide plugin (`Hook PEB`, `NtQueryInformationProcess`, `SetInformationThread`).
- **`CheckRemoteDebuggerPresent()` and `NtQueryInformationProcess(ProcessDebugPort)`**:
  - Detection: Queries `ProcessDebugPort` (class `7`), returning non-zero if attached.
  - Evasion: Hook `NtQueryInformationProcess` to overwrite the return buffer with `0`.
- **Timing Checks (`RDTSC` / `QueryPerformanceCounter`)**:
  - Detection: Measures delta between instructions. Step-over causes millions of CPU cycles delta.
  - Evasion: Trace execution uninterrupted using hardware watchpoints instead of manual single-stepping.

---

## Boundaries & Anti-Patterns
- **Do not execute target binaries on bare-metal host workstations**: Always execute inside disposable VMs with snapshot rollback capabilities.
- **Do not rely on software breakpoints in self-checksumming or self-modifying code**: Software breakpoints write `0xCC` which corrupts CRCs and hash verifications; always use hardware breakpoints (`hbreak` / `ba e`).
- **Do not step blindly into foreign standard runtime loops**: Always place targeted breakpoints at return points or high-level boundaries rather than holding down single-step.
