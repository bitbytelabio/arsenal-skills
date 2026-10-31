# Debugger Workflows

## When To Open
Open this file when static analysis cannot answer a runtime question: the value of a computed pointer, the target of `call rax`, the plaintext after a decrypt loop, the branch a check actually takes, or the moment a packer hands over control. Open it before you attach anything to an untrusted sample. The sample runs only inside the lab described in [malware-sandbox-isolation.md](malware-sandbox-isolation.md). The host runs the debugger client, never the sample.

Related references:
- IDA as the debugger front end, driven by an agent: [ida-mcp-remote-debugging.md](../04-tool-usage/ida-mcp-remote-debugging.md). Server binaries, ports, and lab VMs: [ida-remote-debugging.md](../05-environment/ida-remote-debugging.md).
- Hooking without stopping the process: [frida-hooking.md](frida-hooking.md).
- OEP finding and dumping: [unpacking-memory-dump.md](unpacking-memory-dump.md).

## Pick The Debugger

| Target | First choice | Batch / scripted mode | Notes |
|---|---|---|---|
| Linux ELF (x86-64, AArch64, ARM) | `gdb` + pwndbg or GEF | `gdb -q -nx -batch -x script.gdb`, Python API | `gdbserver` in the guest, client on the host. |
| Linux ELF, foreign ISA | `qemu-<arch> -g PORT` + `gdb-multiarch` | same | `qemu-user` is emulation, not containment. Run it inside the container. |
| macOS / iOS Mach-O | `lldb` | `lldb --batch -s cmds.lldb`, Python API | `debugserver` in the guest. Hardened-runtime binaries refuse attach without `get-task-allow`. |
| Windows user mode | x64dbg (interactive), `cdb` / WinDbg (scripted) | `cdb -c "...; q"`, WinDbg JavaScript, x64dbg script `.txt` | ScyllaHide for anti-debug. TitanHide is a kernel driver: lab VM only. |
| Windows kernel / drivers | WinDbg over KDNET to the guest | `kd -k net:...` | Never on the host kernel. |
| Any, agent-driven through IDA | IDA debugger + `ida/re_dbg.py` | bounded `execute_python` calls | See [ida-mcp-remote-debugging.md](../04-tool-usage/ida-mcp-remote-debugging.md). |
| Hot loop, thousands of hits | Not a debugger | Frida `Interceptor`/`Stalker`, or a trace breakpoint | A stop per hit costs a context switch. Use [frida-hooking.md](frida-hooking.md). |

## Remote Topologies
The sample and the debug stub live in the guest. The client lives on the host. Forward one TCP port, or reach the guest's host-only address.

| Stub (in the guest) | Command | Host client |
|---|---|---|
| `gdbserver`, spawn once | `gdbserver --once 0.0.0.0:2345 ./sample arg1` | `gdb -q -ex "target remote GUEST:2345" ./sample` |
| `gdbserver`, attach | `gdbserver --attach 0.0.0.0:2345 "$PID"` | same |
| `gdbserver`, multi-process | `gdbserver --multi 0.0.0.0:2345` | `target extended-remote GUEST:2345`, `set remote exec-file /guest/path`, `run` |
| `lldb-server` (Linux guest) | `lldb-server gdbserver 0.0.0.0:2345 -- ./sample` | `lldb -o "gdb-remote GUEST:2345"` |
| `lldb-server` platform mode | `lldb-server platform --server --listen "*:2345"` | `platform select remote-linux`, `platform connect connect://GUEST:2345` |
| `debugserver` (macOS guest) | `debugserver 0.0.0.0:2345 ./sample` or `--attach=$PID` | `lldb -o "gdb-remote GUEST:2345"` |
| IDA debug server | `linux_server`, `linux_server32`, `armlinux_server`, `armlinux_server32`, `win64_remote.exe`, `win32_remote32.exe`, `mac_server`, `mac_server_arm`, `mac_server_arme`, `android_server`, `android_server32`, `android_x64_server`, `android_x86_server`, each with `-p23946 -P"$PASS"` | IDA, or `ida/re_dbg.py` |
| WinDbg process server | `dbgsrv -t tcp:port=5005` | `windbg -premote tcp:server=GUEST,port=5005` |
| WinDbg session sharing | in a running session: `.server tcp:port=5005` | `windbg -remote tcp:server=GUEST,port=5005` |
| QEMU user mode | `qemu-aarch64 -g 1234 ./sample` | `gdb-multiarch -ex "target remote :1234" ./sample` |
| QEMU system mode | `qemu-system-x86_64 -s -S ...` (gdbstub on 1234, CPU halted) | `gdb -ex "target remote :1234"` |

IDA 9.x ships exactly these server names in `dbgsrv/`. There is no `linux_server64`, `android_server64`, or `mac_server64`. Pick the server by the target's ISA, not the host's.

Rules for every topology:
- Bind to the host-only interface, or to `127.0.0.1` and forward with `ssh -L 2345:127.0.0.1:2345 analyst@GUEST`. A stub on `0.0.0.0` with no password executes arbitrary code for anyone who reaches the port.
- `gdbserver` has no authentication. Treat the port as a shell.
- Paths given to `run`, `exec-file`, and IDA's `Application` field are guest paths.
- Copy the exact guest binary and its libraries to the host for symbols: `set sysroot /path/to/guest-root` in gdb, `settings set target.exec-search-paths` in lldb.

Verified in an Ubuntu 24.04 AArch64 container: `--once`, `--attach`, and `--multi` with `set remote exec-file` all reached breakpoints. A root container with default capabilities could attach to a same-UID process without `--cap-add=SYS_PTRACE`. Attaching to another UID, or with Yama `ptrace_scope` above 1, needs the capability.

## Hard Timeouts And Batch Mode
An agent must never wait on a debugger without a bound. A process blocked on a socket or `stdin` blocks the batch run forever. Wrap every batch invocation in `timeout` (`gtimeout` on macOS from coreutils).

### gdb
```bash
SAMPLE=./sample
timeout 60 gdb -q -nx -batch -x trace.gdb --args "$SAMPLE" arg1 </dev/null >gdb.log 2>&1
echo "exit=$?"   # 124 means the timeout fired
```

```text
# trace.gdb
set pagination off
set confirm off
break check_key if $rsi == 12
commands
  silent
  printf "check_key len=%d s=%s\n", $rsi, (char*)$rdi
  continue
end
dprintf xor_buf,"xor_buf len=%d\n", $rdx
run
info breakpoints
```

The script uses x86-64 registers (`$rdi`, `$rsi`, `$rdx`). On AArch64 use `$x0`, `$x1`, `$x2`; that variant was run. Facts checked on gdb 15 (Ubuntu 24.04):
- `-batch` exits after the script. A failing line in a `-x` script aborts the rest of that script. One bad `set` early in the file silently disables every breakpoint after it. Prefer separate `-ex` lines for fragile commands, or test the script on a benign binary first.
- `-nx` skips `~/.gdbinit`, so pwndbg/GEF do not load. Batch output stays parseable. Load them explicitly only when needed.
- `set disassembly-flavor intel` is x86-only and fails on AArch64.
- In a container with the default seccomp profile, gdb and gdbserver print `Error disabling address space randomization: Operation not permitted` and run with ASLR. Addresses then differ per run. Either accept it and compute `base + RVA`, or run that lab container with `--security-opt seccomp=unconfined`.
- `dprintf` is a logging breakpoint that never stops. It is the cheapest way to log a hot function.
- `commands ... continue ... end` turns any breakpoint into a logging breakpoint.

### lldb
```bash
timeout 60 lldb --batch -s trace.lldb -k "bt" -k "register read" -- ./sample arg1 >lldb.log 2>&1
```

```text
# trace.lldb
settings set target.disable-aslr true
breakpoint set -n check_key -N ck -c '$x1 == 12'
breakpoint command add ck
register read x0 x1
memory read -f s $x0
continue
DONE
breakpoint set -n xor_buf --auto-continue true -N xb
process launch -o /tmp/sample.stdout
```

Facts checked on Apple lldb (Xcode command-line tools, 2026):
- `-k CMD` runs only if the process stops on a crash. Use it for `bt` and `register read`.
- `breakpoint command add -o A -o B -o C` keeps only the last `-o`. Multi-line command lists need a sourced file ending in `DONE`, or a Python one-liner: `breakpoint command add -s python xb -o 'print(frame.FindRegister("x2").GetValueAsUnsigned()); return False'`. Returning `False` auto-continues.
- `b` is the `_regexp-break` alias. `b set -a ...` is wrong. Use `breakpoint set -a ADDR`.
- `memory read` refuses more than 1024 bytes unless you add `--force`: `memory read --force --binary --outfile dump.bin START END`.
- `process launch -s` stops at the entry point. `-m` stops at `main`. `-X false` keeps ASLR on.
- On macOS with Developer Mode disabled, `process launch` and `process attach` wait for an authorization prompt. In an unattended run that is a hang, so the `timeout` wrapper is mandatory. `DevToolsSecurity -status` tells you in advance.

### cdb / WinDbg
```cmd
cdb -logo C:\lab\cdb.log -G -c "bp kernel32!VirtualProtect \"r rcx, rdx, r8; k 3; gc\"; g; q" C:\lab\sample.exe
```
- The `-c` string runs once, at the first prompt: the initial loader breakpoint. Do not add `-g` (skip that breakpoint) here, or the commands never run. `-G` skips the final breakpoint so `g` returns at process exit and `q` runs.
- Any later stop without `gc` (an exception, `sxe ld:...`, a plain `bp`) waits for input. In a batch run that is a hang; every breakpoint command ends in `gc`.
- `-o` debugs child processes too. `.childdbg 1` does the same inside a session.
- There is no built-in wall-clock limit. Run `cdb` from a PowerShell job with `Wait-Job -Timeout` or kill it from the orchestrator.
- `-cf script.txt` loads a command file. `$$>< script.txt` runs one from inside a session.

WinDbg JavaScript, loaded with `.scriptload C:\lab\log.js` and run with `dx @$scriptContents.armLogging()`:

```javascript
"use strict";
function armLogging() {
    const ctl = host.namespace.Debugger.Utility.Control;
    ctl.ExecuteCommand('bp bcrypt!BCryptDecrypt "dx @$curthread.Stack.Frames[1]; gc"');
    ctl.ExecuteCommand('bp /w "@rdx >= 0x10000" kernel32!VirtualAlloc');
    host.diagnostics.debugLog("armed\n");
}
```

`bp /w "<C++ expression>"` is the modern conditional breakpoint. It stops only when the expression is true and needs no `.if`/`gc` trick.

### x64dbg
x64dbg has no headless mode. Scripts run inside the GUI in the Windows VM. Load one from the command bar with `scriptload "C:\lab\trace.txt"`, then run it from the Script tab (Space runs, Tab steps). Each line is an ordinary x64dbg command.

```text
// trace.txt — x64dbg script; every command below is in the x64dbg command reference
init "C:\lab\sample.exe"
bp VirtualProtect
bpcnd VirtualProtect, 0
bplog VirtualProtect, "VirtualProtect addr={p:rcx} size={x:rdx} prot={x:r8} hit={d:$breakpointcounter}"
bph kernel32.IsDebuggerPresent, x, 1
bpm 0x401000, 0, x
erun
log "stopped at {p:cip}"
savedata "C:\lab\region.bin", rcx, rdx
minidump "C:\lab\sample.dmp"
```

- Short forms: `bpcnd` = `SetBreakpointCondition`, `bplog` = `SetBreakpointLog`, `bph` = `SetHardwareBreakpoint` (types `x`, `w`, `r` = read **or** write; sizes 1/2/4/8, address aligned), `bpm` = `SetMemoryBPX` (guard page over the whole region; types `a`, `r`, `w`, `x`; second arg `0` = one-shot).
- A condition of `0` plus a log makes a tracepoint: it logs every hit and never stops. Do not also set fast resume; fast resume skips the log.
- `$breakpointcounter` is the hit count inside conditions, for example `bpcnd addr, "$breakpointcounter == 100"`.
- `erun` passes first-chance exceptions to the program. Packers that use exceptions for control flow need it.
- `minidump` writes a full-memory `.dmp` from the debuggee. `savedata` writes one range. `:memdump:` as the file name writes into the x64dbg folder.
- `x64dbgpy` adds Python. It tracks specific x64dbg builds. Check that the plugin loads before you build automation on it.

## Breakpoint Types

| Type | Mechanism | Memory changed | Limit | Use for |
|---|---|---|---|---|
| Software | `int3` (`0xCC`) on x86, `brk #0` (`0xd4200000`) on AArch64 | Yes, one instruction | Unlimited | Normal control flow |
| Hardware execute | DR0–DR3 on x86 (DR7 enables), `DBGBVR/DBGBCR` on ARM | No | 4 on x86/x64; 2–16 on ARM (often 6) | Self-checksumming code, code not yet written, `0xCC` scanners |
| Hardware data (watchpoint) | DR0–DR3 with R/W bits, ARM `DBGWVR/DBGWCR` | No | Shares the 4 x86 slots; sizes 1/2/4/8, aligned | Who writes the key, who reads the flag |
| Memory / page | `PAGE_GUARD` or removed permission, then catch the fault | Page protections | Page granularity | "First execute in this section" (OEP), large ranges |
| Software watchpoint | Single-step and compare | No | Unlimited, very slow | Avoid. gdb falls back to it silently when hardware slots run out |

Commands that were checked or are taken from each tool's own help:

| Operation | gdb | lldb | WinDbg / cdb | x64dbg |
|---|---|---|---|---|
| Software bp | `break *0x401122` | `breakpoint set -a 0x401122` | `bp 0x401122` | `bp 0x401122` |
| Hardware exec | `hbreak *0x401122` | `breakpoint set -a 0x401122 -H` | `ba e1 0x401122` | `bph 0x401122, x, 1` |
| Write watch | `watch -l *(int*)0x602000` | `watchpoint set expression -w write -s 4 -- 0x602000` | `ba w4 0x602000` | `bph 0x602000, w, 4` |
| Read watch | `rwatch -l ...` | `-w read` | `ba r4 ...` (read or write) | `bph addr, r, 4` (read or write) |
| Read/write watch | `awatch -l ...` | `-w read_write` | `ba r4 ...` | `bph addr, r, 4` |
| Conditional | `break *0x401000 if $rdi == 0x20` | `breakpoint set -a 0x401000 -c '$rdi == 0x20'` | `bp /w "@rdi == 0x20" 0x401000` | `bpcnd 0x401000, "rdi == 0x20"` |
| Log, no stop | `dprintf *0x401000,"%d\n",$rdi` | `--auto-continue true` + command | `bp 0x401000 "r rdi; gc"` | `bplog` + `bpcnd addr, 0` |
| Hit count | `ignore 1 99` | `breakpoint modify -i 99 1` | `bp 0x401000 100` (break on the 100th pass) | `bpcnd addr, "$breakpointcounter == 100"` |
| One-shot | `tbreak` | `breakpoint set -o true ...` | `bp /1 0x401000` | `SetBreakpointSingleshoot addr, 1` |
| On module load | `catch load libfoo` | `breakpoint set -n init -s libfoo.dylib` (pending) | `sxe ld:foo` | Events: DLL load |
| On syscall | `catch syscall ptrace` | n/a, use a breakpoint on the libc stub | `bp ntdll!NtSetInformationThread` | `bp ntdll.NtSetInformationThread` |
| List / delete | `info breakpoints` / `delete 1` | `breakpoint list` / `breakpoint delete 1` | `bl` / `bc 0` | `bplist` / `bc 0` |

Pitfalls:
- x86 `ba r` and `bph addr, r` trap on read **or** write. There is no read-only data breakpoint on x86. gdb `rwatch` on x86 is implemented as read/write and filtered by value change.
- Hardware breakpoints are per thread. A breakpoint set before a thread exists may not apply to it. gdb and WinDbg propagate them; some front ends do not. Re-check with `info breakpoints` after `CreateThread`.
- A program can read and clear DR0–DR7 through `GetThreadContext`/`SetThreadContext` or by raising an exception and inspecting the `CONTEXT`. ScyllaHide hooks those calls.
- PIE and ASLR: `break *0x401122` is wrong for a PIE binary. Start with `starti`, read the base from `info proc mappings`, then break at `base + RVA`. pwndbg has `breakrva RVA`. GEF has `pie breakpoint RVA`.

## Execution Control

| Action | gdb | lldb | WinDbg | x64dbg |
|---|---|---|---|---|
| Step into, one instruction | `stepi` / `si` | `thread step-inst` / `si` | `t` | `sti` (F7) |
| Step over, one instruction | `nexti` / `ni` | `thread step-inst-over` / `ni` | `p` | `sto` (F8) |
| Run to return | `finish` | `thread step-out` / `finish` | `gu` (or `pt` to stop at the `ret`) | `rtr` |
| Continue | `continue` | `process continue` | `g` | `run` / `erun` |
| Run to address | `until *ADDR` / `advance *ADDR` | `thread until -a ADDR` | `g ADDR` | `run ADDR` |
| Stop at first instruction | `starti` | `process launch -s` | loader bp (default) | System breakpoint event |

`gu` returns to the caller. `pt` stops on the `ret` instruction itself. They are different.

## State Inspection

| Need | gdb | lldb | WinDbg |
|---|---|---|---|
| 16 qwords at SP | `x/16gx $sp` | `memory read -f x -s 8 -c 16 $sp` | `dq @rsp L10` |
| C string | `x/s ADDR` | `memory read -f s ADDR` | `da ADDR` / `du ADDR` |
| 5 instructions at PC | `x/5i $pc` | `disassemble -s $pc -c 5` | `u @rip L5` |
| Registers | `info registers rdi rsi` | `register read rdi rsi` | `r rdi, rsi` |
| Backtrace | `bt` / `thread apply all bt` | `bt` / `bt all` | `k` / `~*k` |
| Memory map | `info proc mappings` (pwndbg `vmmap`) | `memory region ADDR`, `image list` | `!address`, `lm` |
| Dump range to file | `dump binary memory out.bin START END` | `memory read --force --binary --outfile out.bin START END` | `.writemem C:\out.bin START L?SIZE` |
| Core / full dump | `gcore out.core` / `generate-core-file` | `process save-core out.core` | `.dump /ma C:\out.dmp` |
| Symbol at address | `info symbol ADDR` | `image lookup -a ADDR` | `ln ADDR` |

Calling conventions you need to read arguments at a function entry:

| ABI | Integer args | Return | Notes |
|---|---|---|---|
| System V x86-64 (Linux, macOS Intel) | `rdi rsi rdx rcx r8 r9` | `rax` | Syscalls use `r10` instead of `rcx` for arg 4. |
| Microsoft x64 | `rcx rdx r8 r9`, then stack after 32-byte shadow space | `rax` | At entry, arg 5 is at `[rsp+0x28]`. |
| x86 cdecl / stdcall | stack, `[esp+4]` is arg 1 at entry | `eax` | `fastcall`: `ecx edx`. `thiscall`: `this` in `ecx`. |
| AArch64 AAPCS64 / Apple arm64 | `x0`–`x7` | `x0` | Apple variadic args go on the stack. `x8` is the indirect result pointer. |
| ARM32 AAPCS | `r0`–`r3` | `r0` | Thumb bit set in function pointers. |

## Scripted Tracing With The Python APIs

gdb, verified on gdb 15 AArch64 (change the register names for x86-64):

```python
# key_tracer.py — gdb -q -nx -batch -ex "source key_tracer.py" -ex run --args ./sample
import gdb

class KeyTracer(gdb.Breakpoint):
    def __init__(self, spec, ptr_reg, len_reg):
        super().__init__(spec, gdb.BP_BREAKPOINT)
        self.ptr_reg, self.len_reg, self.hits = ptr_reg, len_reg, 0

    def stop(self):
        self.hits += 1
        frame = gdb.selected_frame()
        ptr = int(frame.read_register(self.ptr_reg))
        size = max(0, min(int(frame.read_register(self.len_reg)), 256))
        data = bytes(gdb.selected_inferior().read_memory(ptr, size))
        print(f"[trace] hit={self.hits} len={size} data={data.hex()}")
        return False  # False = do not stop; this is a tracepoint

KeyTracer("check_key", "x0", "x1")
```

Use `gdb.BP_HARDWARE_BREAKPOINT` as the type for a hardware breakpoint. `stop()` runs on every hit, so keep it short.

lldb Python breakpoint function, loaded with `command script import tracer.py`. A command added by breakpoint **name** applies to every breakpoint carrying that name, so keep names unique:

```python
# tracer.py
import lldb

def on_hit(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    ptr = frame.FindRegister("x0").GetValueAsUnsigned()
    size = min(frame.FindRegister("x1").GetValueAsUnsigned(), 256)
    err = lldb.SBError()
    data = proc.ReadMemory(ptr, size, err) if size else b""
    print(f"[trace] {data.hex() if err.Success() else err}")
    return False

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("breakpoint set -n check_key -N ck_py")
    debugger.HandleCommand("breakpoint command add -F tracer.on_hit ck_py")
```

## Processes, Threads, And Forks
- gdb: `set follow-fork-mode child`, `set detach-on-fork off` (keep both under control), `catch fork`, `catch exec`, `info inferiors`, `inferior 2`. `set scheduler-locking step` stops other threads from running while you step.
- lldb: `settings set target.process.follow-fork-mode child`. `target.process.stop-on-exec` defaults to true.
- WinDbg: `.childdbg 1` or `cdb -o`. `sxe cpr` breaks on process creation. `~` lists threads, `~3s` switches, `~*k` dumps all stacks.
- x64dbg: one process per instance. For a child, break on `CreateProcessInternalW`, start the child suspended (`CREATE_SUSPENDED` in the flags), let the parent run, then attach a second x64dbg to the child PID before resuming it.
- A sample that injects into another process moves the interesting code out of your debuggee. Break on `WriteProcessMemory`, `NtMapViewOfSection`, `SetThreadContext`, `NtQueueApcThread`, and `ResumeThread`, then follow the target PID.

## Anti-Debug Interplay
Name the check before you defeat it. A bypass you cannot name hides the next one.

| Check | How it detects | Neutralize in the lab |
|---|---|---|
| `ptrace(PTRACE_TRACEME)` (Linux) | Fails with `EPERM` if already traced | gdb catchpoint below, or patch the branch in a lab copy |
| `/proc/self/status` `TracerPid` | Non-zero while traced | Attach after the check, or hook `read`/`fopen` with Frida |
| `PEB.BeingDebugged` | `gs:[0x60]+0x2` (x64), `fs:[0x30]+0x2` (x86) | WinDbg `eb @$peb+2 0`. ScyllaHide "PEB BeingDebugged" |
| `PEB.NtGlobalFlag` = `0x70` | Heap debug flags set when spawned under a debugger | `ed @$peb+0xbc 0` (x64), `+0x68` (x86). Or attach instead of spawn. Or set `_NO_DEBUG_HEAP=1` |
| Heap `Flags`/`ForceFlags` | Debug heap values | ScyllaHide "Heap Flags" |
| `NtQueryInformationProcess` classes `7` (DebugPort), `0x1e` (DebugObjectHandle), `0x1f` (DebugFlags) | Non-zero port, a handle, flags `0` | ScyllaHide `NtQueryInformationProcess` |
| `NtSetInformationThread(ThreadHideFromDebugger = 0x11)` | Debugger stops receiving events, then the process "vanishes" | Break on it and skip the call, or ScyllaHide |
| `CloseHandle(invalid)` / `NtClose` | Raises `EXCEPTION_INVALID_HANDLE` only under a debugger | Pass the exception, or ScyllaHide `NtClose` |
| `int 2d`, `int3` scanning, `0xCC` checksums | Debugger swallows the exception, or text bytes change | Hardware breakpoints. Pass exceptions to the program |
| DR0–DR3 read via `GetThreadContext` | Non-zero debug registers | ScyllaHide `NtGetContextThread`. Use page breakpoints instead |
| `rdtsc`, `QueryPerformanceCounter`, `GetTickCount` deltas | Stepping inflates the delta | Do not step through the check. Break after it. ScyllaHide `GetTickCount`/`rdtsc` options are partial |
| Parent process name | Parent is `x64dbg.exe`, not `explorer.exe` | Attach to a process started normally and suspended |
| Debugger windows / processes | `FindWindow`, process list | Rename the debugger binary. ScyllaHide `NtUserFindWindowEx` |

Linux `ptrace` catchpoint, verified on gdb 15 AArch64. The sample printed `debugger detected` without it and `clean run` with it. A syscall catchpoint stops on entry and again on return. Only the return value matters, so toggle a flag:

```text
set $in_ptrace = 0
catch syscall ptrace
commands
  silent
  if $in_ptrace == 0
    set $in_ptrace = 1
  else
    set $in_ptrace = 0
    set $x0 = 0
  end
  continue
end
run
```

Use `$rax` instead of `$x0` on x86-64. A sample that calls `ptrace(PTRACE_TRACEME)` twice and expects the second call to fail sees a forged `0`. Read the code before you assume one call.

ScyllaHide is a user-mode plugin (x64dbg, IDA, standalone injector). It hooks `ntdll` in the debuggee, which a sample can detect by checking for hooked prologues. TitanHide hides at kernel level and needs test-signing mode. Use both only inside the lab VM. Neither defeats timing checks fully. When a check survives both, patch it in a lab copy and record the patch.

## Verification
- After the first breakpoint hit, confirm the address maps to the function you meant: `info symbol $pc`, `image lookup -a $pc`, `ln @rip`.
- Before trusting a value read at a breakpoint, check which ABI applies and whether the function has already moved its arguments (read at the first instruction, not after the prologue).
- After defeating an anti-debug check, re-run without the debugger in the same VM and compare one observable (exit code, a file written, a server request). Differences mean another check exists.
- Record the debugger, its version, the stub, the guest, and every bypass applied in the evidence ledger.

## Boundaries
- The sample, the debug stub, and ScyllaHide/TitanHide run in the guest. The host runs the client.
- Never leave a debug stub listening on a routable interface.
- Do not single-step a hot loop over a remote link. Use a tracepoint, `dprintf`, or Frida.
- Software breakpoints on self-checking code change its behavior. Use hardware breakpoints there.
