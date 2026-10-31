# Deobfuscation And Anti-Analysis Countermeasures

## When To Open
Open this file when the decompiler output is unreadable because of the build, not because of the logic. Typical signs are a `while(1) switch(state)` around a whole function, opaque `if` conditions on globals, long `&`/`|`/`^`/`+` chains that compute a constant or a simple sum, indirect jumps through computed tables, VM sections (`.vmp0`, `.themida`), or checks for debuggers, VMs, and Frida. Identify the obfuscator family first. The removal tool depends on it.

Scope: OLLVM-family passes (flattening, bogus control flow, substitution, indirect branches), MBA simplification, VM-based protectors, and an anti-debug / anti-VM / anti-instrumentation catalog per OS with the check and the bypass.

---

## 0. Recover At The API Boundary Before Lifting

Identify the protector, then take the cheapest layer that answers the question. Order: decrypted strings, then control flow, then a VM lift. A runtime dump beats a static devirtualizer that was built for one version. When the lift is blocked, recover the logic by staged fuzzing of input/output and handler coverage. That procedure is [fuzzing-for-reversing.md](../02-dynamic-instrumentation/fuzzing-for-reversing.md).

Hook the function that consumes the secret, not the decryptor. `strcmp`, `dlsym`, `GetProcAddress`, JNI `FindClass` / `GetMethodID` / `NewStringUTF`, and file opens receive plaintext no matter which packer produced it. Filter by return address so only calls from the target module are kept. An unqualified export match with zero hits is ambiguous. Retry as `Module!symbol`.

On Android, unpacking often finishes inside `JNI_OnLoad`. A legitimate `.so` almost never has an `RWX` segment. Watch `mprotect`: `r-x` to `rwx` and back to `r-x` is the dump point. Identify the module by an export at a known offset, not by a filename the packer can change. Section names `.vmp0`, `.themida`, `.winlice` select the protector. The lift, if you still need it, is section 5. Dumping is [unpacking-memory-dump.md](../02-dynamic-instrumentation/unpacking-memory-dump.md).

Anything in this file that runs the sample belongs in the lab VM, under the dynamic rules. Static removal (d810-ng, deflat on a copy, MBA simplification) does not execute the target.

---

## 1. Recognize The Obfuscator

| Family | Signature in the binary | Passes |
|---|---|---|
| OLLVM 4.0 (original) | `.comment` may say `Obfuscator-LLVM clang version 4.0.1`. BCF predicates on two globals `x`/`y`: `y < 10 \|\| ((x*(x-1)) & 1) == 0` | `-fla`, `-bcf`, `-sub`, `-split` |
| Hikari / Hikari-LLVM15 | ObjC-heavy iOS code, string decryption stubs called from every function, `objc_msgSend` wrappers, anti-class-dump | Flattening, BCF, substitution, string encryption, function wrappers, indirect branch, anti-debug/anti-hook |
| goron / Arkari | `br x8` / `jmp rax` where the target is `table[i] + key` loaded from a global table | Indirect branch, indirect call, indirect global variable, string encryption |
| Pluto / Polaris | Flattening plus heavy MBA. Pluto has a pass that targets angr. | Flattening, MBA, global encryption |
| O-MVLL (Open-Obfuscator) | Android/iOS, configured by a Python file | Arithmetic MBA, opaque constants, flattening, string encoding, anti-hook |
| Tigress | Research/CTF. Flattening with `switch`, `goto` tables, or indirect jumps; VM with custom bytecode | Flatten, Virtualize, EncodeArithmetic, Split |
| Commercial mobile (DexGuard/iXGuard, Arxan/Digital.ai, Approov SDK) | Flattened native libraries, integrity checks over `.text`, encrypted strings | Varies. d810-ng ships an Approov config. |

Version tags in `.comment` (`readelf -p .comment "$BIN"`) or Mach-O `LC_BUILD_VERSION` sometimes name the fork. Their absence is normal.

---

## 2. Control-Flow Flattening

### Recognize
- Entry block writes a constant to `state` and jumps to a dispatcher.
- The dispatcher loads `state` and branches by comparisons (binary-search tree of `cmp state, imm`) or a jump table.
- Every real block ends with `state = CONST` or `state = cond ? S1 : S2` (`cmov`/`csel`) and jumps back to a common latch.
- Constants look random (`0x5F3E1A2B`). Each appears exactly once as a write and once as a compare.

Block classes: prologue, dispatcher, sub-dispatchers (only compare/branch on `state`), relevant blocks (real code plus a `state` write), latch (jumps to the dispatcher), return.

### Remove: Decision Table
| Situation | Tool | How |
|---|---|---|
| IDA 9 with Hex-Rays | **d810-ng** (`w00tzenheimer/d810-ng`) | Copy into the IDA plugins directory. Optional speedups: `pip3 install d810-ng[speedups]` then `python -m d810.speedups.install`. `Ctrl-Shift-D` opens the GUI. Load `default_unflattening_ollvm.json` (or `default_unflattening_approov.json`, `hodur_deobfuscation.json`) and start, then decompile again. Rules: `Unflattener` (OLLVM), `UnflattenerSwitchCase` (Tigress `switch`), `UnflattenerTigressIndirect` (needs `goto_table_info`), `HodurUnflattener` (PlugX-style nested loops), `UnflattenerFakeJump`, `JumpFixer`. |
| IDA 7.5–8.x | joydo/d810 (original, `pip3 install z3-solver`, same hotkey) or HexRaysDeob forks | IDA 8.4 is the newest version a HexRaysDeob fork claims |
| x86/x64/ARM ELF, no IDA, patched binary wanted | `cq674350529/deflat` (angr) | `python3 deflat.py -f "$BIN" --addr 0x400530` (function start). BCF: `python3 debogus.py -f "$BIN" --addr 0x80483e0`. Writes `<name>_recovered` beside the input. Run it on a copy. Pin the angr version the repo was tested with. |
| x86/x64, Miasm | `mrT4ntr4/MODeflattener` | `python3 modeflattener.py [-a] "$BIN" patched.bin 0x401200`. `-a` follows calls. |
| Binary Ninja | `amimo/ollvm-breaker` | Example script `tests/fix-libvdog.py` for an Android `.so`. It is a script template, not a package. Adapt it per target. |
| Hex-Rays, cloud allowed | obpo-plugin (archived 2023) | Closed-source core. It sends function bytes to a remote server. Do not use it on confidential samples. |
| Nothing fits | The algorithm below with your own emulator | |

### Algorithm (Any Tool)
1. Find `state`: the register or stack slot the dispatcher compares. Its value at the prologue's exit is the start state.
2. Find relevant blocks: predecessors of the latch that are not dispatcher nodes.
3. For each relevant block, compute the next state. Emulate the block alone (Unicorn) or solve its last write symbolically. If the write depends on a flag (`cmov`/`csel`), solve both outcomes.
4. Map state constants to blocks by walking the dispatcher with each constant (concrete emulation of only the dispatcher is enough).
5. Patch: replace the `state` write + jump-to-latch with `jmp target`, or `jcc T; jmp F` for two-way blocks. Leave the dispatcher unreachable. Do not delete it. Fill freed bytes with `nop` (`0x90`, arm64 `0xD503201F`).
6. Re-decompile and check that every relevant block has exactly the successors you derived.

Pitfalls: `state` can be updated through an MBA or a lookup table (resolve it per block, not by pattern). Some forks split `state` into two variables or encode it (`state ^ key`). Relevant blocks can call functions that never return; give them no successor. Loops in the original code show up as a relevant block whose next state is its own or an earlier state. That is correct.

---

## 3. Bogus Control Flow And Opaque Predicates

OLLVM BCF wraps real blocks in `if (P)` where `P` is constant at runtime. The dead branch holds a mutated clone of the real block.

| Predicate | Why it is constant | Holds modulo 2ⁿ? |
|---|---|---|
| `(x*(x+1)) & 1 == 0` (OLLVM uses `x*(x-1)`) | Product of consecutive integers is even | Yes (Z3, 32-bit) |
| `7*y*y - 1 != x*x` | `7y²−1 mod 8 ∈ {3,6,7}`, squares mod 8 ∈ {0,1,4} | Yes (Z3, 8- and 16-bit) |
| `y < 10 \|\| ...` on a global | The global is never written | Only if no code writes it. Check xrefs. |

```python
# Prove a branch condition constant. uv run --with z3-solver python -I opaque.py
from z3 import BitVec, Solver, unsat
x, y = BitVec("x", 32), BitVec("y", 32)
cond = (x * (x + 1)) & 1 == 0          # transcribe the decompiled predicate
s = Solver(); s.add(cond == False)
print("always true" if s.check() == unsat else f"not constant: {s.model()}")
```

Patch `jcc` to `jmp` (always taken) or `nop` (never taken), then let the decompiler drop the dead block. d810-ng's predicate rules and `debogus.py` do this automatically. When the predicate reads globals, treat them as symbolic only if something can write them. Otherwise substitute their initial values.

---

## 4. Instruction Substitution And MBA

### Substitution Identities (Verified With Z3 At 32 Bits)
| Original | Obfuscated forms |
|---|---|
| `x + y` | `(x ^ y) + 2*(x & y)`, `(x \| y) + (x & y)`, `x - (-y)`, `2*(x \| y) - (x ^ y)` |
| `x - y` | `x + ~y + 1`, `(x ^ y) - 2*(~x & y)` |
| `x ^ y` | `(x \| y) - (x & y)`, `(x & ~y) \| (~x & y)` |
| `x \| y` | `(x & y) + (x ^ y)` |
| `x & y` | `(x \| y) - (x ^ y)` |
| `~x` | `-x - 1` |
| `x * y` | `(x & y)*(x \| y) + (x & ~y)*(~x & y)` (non-linear; proved at 8 bits) |

`(x ^ ~y) + 2*(~x & y) + 1` equals `y - x`, not `x - y`. Check direction with a solver before you rewrite.

### Linear Vs Non-Linear
A linear MBA is `Σ aᵢ · bitwiseᵢ(x, y, ...)`. It is fully determined by its values on inputs in `{0,1}`, so it simplifies in polynomial time (SiMBA). Products of variables or of bitwise terms make it non-linear (GAMBA, msynth, synthesis).

| Expression type | Tool | Command |
|---|---|---|
| Linear | SiMBA | `python3 src/simplify.py "(x^y)+2*(x&y)" -b 32 -z` (`-z` proves with Z3, `-l` checks linearity) |
| Polynomial / mixed | GAMBA | `python3 src/simplify_general.py "<expr>" -b 32 -z` |
| From a binary function | msynth (Miasm) | `python scripts/gen_oracle.py database/3_variables_constants_7_nodes.txt oracle.pickle`, then `python scripts/symbolic_simplification.py "$BIN" 0x1290 oracle.pickle` |
| Inside IDA | d810-ng | Pattern and Z3 rules run on microcode during decompilation |
| From a trace | Triton (`pip install triton-library`) | Lift, then `ctx.simplify(node, llvm=True)` or `ctx.synthesize(node, constant=True, subexpr=True, opaque=False)` |

Do not hand-simplify long expressions. Copy the expression from the decompiler, simplify it with a tool, then prove equality with Z3 at the real bit width.

### Linear MBA Simplifier (Self-Contained)
Implements the truth-table idea behind SiMBA. Tested: `(x|y)-(x&y)` → `x^y`, `(x^y)+2*(x&y)` → `1*(x) + 1*(y)`, `-x-1` → `~(x)`, and a 3-variable expression whose result Z3 proved equal at 32 bits. Linear input only. A non-linear input gives a wrong answer, so prove the output with Z3.

```python
# linmba.py. python3 -I linmba.py "<linear MBA>" [bits]
import itertools, re, sys

def simplify_linear(expr, bits=64):
    mask = (1 << bits) - 1
    names = sorted(set(re.findall(r"\b[a-z]\w*\b", expr)))
    f = eval("lambda " + ",".join(names) + ": " + expr)  # your own expression text, not sample data
    pts = list(itertools.product((0, 1), repeat=len(names)))
    sig = [f(*p) & mask for p in pts]
    signed = lambda c: c - (1 << bits) if c >> (bits - 1) else c

    # 1. Try a*g + b for one bitwise function g.
    cands = list(names)
    for a, b in itertools.combinations(names, 2):
        cands += [f"{a}&{b}", f"{a}|{b}", f"{a}^{b}", f"{a}&~{b}", f"~{a}&{b}"]
    if len(names) > 2:
        cands += ["&".join(names), "|".join(names), "^".join(names)]
    cands += [f"~({c})" for c in cands]
    best = None
    for c in cands:
        g = eval("lambda " + ",".join(names) + ": " + c)
        gs = [g(*p) & mask for p in pts]
        diff = next((i for i in range(len(pts)) if gs[i] != gs[0]), None)
        if diff is None or (gs[diff] - gs[0]) % 2 == 0:
            continue
        a = ((sig[diff] - sig[0]) * pow(gs[diff] - gs[0], -1, 1 << bits)) & mask
        b = (sig[0] - a * gs[0]) & mask
        if all((a * gs[i] + b) & mask == sig[i] for i in range(len(pts))):
            a, b = signed(a), signed(b)
            out = c if a == 1 else f"-({c})" if a == -1 else f"{a}*({c})"
            out += f" + {b}" if b > 0 else f" - {-b}" if b < 0 else ""
            if best is None or (abs(a) != 1, b != 0) < best[0]:
                best = ((abs(a) != 1, b != 0), out)
    if best:
        return best[1]

    # 2. General linear form: sum of c_S * AND(S), by Moebius inversion.
    terms = []
    for k in range(len(names) + 1):
        for S in itertools.combinations(range(len(names)), k):
            c = sum((-1) ** (len(S) - len(T)) * f(*[1 if i in T else 0 for i in range(len(names))])
                    for j in range(len(S) + 1) for T in itertools.combinations(S, j)) & mask
            if c:
                terms.append(f"{signed(c)}*({'&'.join(names[i] for i in S) or '1'})")
    return " + ".join(terms) or "0"

if __name__ == "__main__":
    print(simplify_linear(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 64))
```

Prove the result before you use it:
```python
# uv run --with z3-solver python -I prove.py
from z3 import BitVec, Solver, unsat
x, y = BitVec("x", 32), BitVec("y", 32)
s = Solver(); s.add((x | y) - (x & y) != x ^ y)
print("equal" if s.check() == unsat else s.model())
```
Z3 proves linear identities at 32/64 bits in seconds. Non-linear ones (products) can take minutes or time out at 32 bits. Prove at 8 and 16 bits first, then add a random-test sweep at full width.

---

## 5. Indirect Branches (goron, Arkari, Hikari)

Pattern (arm64):
```text
adrp x8, table@PAGE
add  x8, x8, table@PAGEOFF
ldr  x9, [x8, w10, uxtw #3]   ; table entry
add  x9, x9, x11              ; + per-function key, sometimes from another global
br   x9
```
1. The table and the key are constants in `.data`/`.rodata`, or written once by an `.init_array` constructor.
2. Resolve each site by constant propagation with the data section frozen. In IDA, mark the table segment read-only (or set the globals `const`) so Hex-Rays folds the loads, then use d810-ng's `JumpFixer`. Otherwise emulate the few instructions before `br` with Unicorn and read the target.
3. If the constructor computes the table, emulate the constructor first and use its output, or dump `.data` after init in the lab.
4. Patch `br x9` to `b target` (or add a code xref and set the indirect-jump target in IDA) and re-analyze.

Indirect calls are the same with `blr`. Recovering them restores the call graph, which is usually more valuable than the CFG inside one function.

---

## 6. Symbolic Execution Limits
- Do not run `explore()` over a whole flattened function. State count grows with every dispatcher pass. Execute one relevant block at a time with a step limit, as `deflat.py` does.
- Pluto/Polaris add constructs aimed at angr (loops on symbolic input, large MBA). Concretize everything except `state` and the branch flag.
- Hook or skip calls inside relevant blocks (`project.hook(addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())`). Their internals do not decide `state`.
- Unicorn is faster when the next state does not depend on input. Use symbolic execution only for blocks whose next state does.

---

## 7. Virtualization Protectors (VMProtect, Themida/WinLicense, Code Virtualizer)

### Recognize
| Protector | Signs |
|---|---|
| VMProtect 3.x | Sections `.vmp0`, `.vmp1` (renamable). VM entry is `push <imm32>; call <vm_entry>` where the immediate is the encrypted bytecode pointer. Entry saves all GPRs and flags. Mutated junk around every handler. Imports resolved through stubs. |
| Themida / WinLicense | Sections `.themida` / `.winlice` (or blank names). Large mutated entry, multiple VM architectures (FISH, TIGER, SHARK, PUMA, ...), heavy anti-debug before OEP. |
| Code Virtualizer | Same vendor as Themida. VM only, no packer. |

### Approach
1. Decide whether you need the VM at all. Most questions are answered at the API boundary (section 0) or by an OEP dump with fixed imports.
2. Find VM entries: all `push imm; call X` sites with the same `X`, or calls into the VM section from normal code.
3. Find the dispatcher: the block that fetches from the virtual instruction pointer, decodes (XOR/ADD/ROL with a rolling key), and jumps through a table or a computed `jmp reg`/`ret`.
4. Classify handlers by effect on the virtual stack and context: arithmetic (`vadd`, `vnand`/`vnor` from which all logic is built), loads/stores, push/pop of virtual registers, branch, VM exit.
5. Lift a trace or the handlers to an IR (VTIL, LLVM IR, Triton AST), optimize (stack-to-register, dead code, MBA), and decompile the result.
6. Verify: run the lifted code and the original on the same inputs in the lab and compare outputs.

| Tool | Target | Usage | Notes |
|---|---|---|---|
| NoVmp (`can1357/NoVmp`) | VMProtect 3.0–3.5 x64 | `NoVmp.exe dumped.exe [-vms 0x729B81 ...] [-sections .xxx0] [-base 0x140000000] [-opt:constant]` | Static, built on VTIL. Needs an unpacked dump. |
| titan (`archercreat/titan`) | VMProtect < 3.8 | `titan -i intrinsics/vmprotect64.ll -b "$BIN" -e 0x140103FF4` | Triton + LLVM. Emulates handlers. |
| Mergen (`NaC-L/Mergen`) | VMProtect 3.4–3.6, 3.8.1; Themida example | `lifter "$BIN" 0x<vm_entry>` | Lifts to LLVM IR |
| themida-unmutate (`pip install themida-unmutate`) | Themida 3.x mutation (tested to 3.1.9) | `themida-unmutate -a 0x<addr> -o out.exe "$BIN"` | Static. Binary Ninja plugin `themida-unmutate-bn`. |
| unlicense (`ergrelet/unlicense`) | Themida/WinLicense 2.x/3.x unpack | `unlicense.exe "$BIN" [--pause_on_oep] [--force_oep=<RVA>]` | **Executes the target.** Lab VM only. 32-bit Python for 32-bit targets. |
| vmpdump (`0xnobody/vmpdump`) | VMProtect 3.x x64 dump + import fix | `VMPDump.exe <PID> "<module>" [-ep=<RVA>]` | Live process. Lab VM only. |
| VMPImportFixer (`mike1k/VMPImportFixer`) | VMProtect import stubs | `-p <pid or name> -mod:<module> -section:<vmp section>` | Live process. Lab VM only. |

Each tool targets a version range. A protector update breaks them silently. When a lift produces nonsense, fall back to trace-based handler classification or to behavior recovery by fuzzing.

---

## 8. Anti-Analysis Catalog

Static first: find the check by its API, syscall number, string, or constant, then decide whether it matters for the question. Patching it in a copy is often enough. Bypasses that run the sample are lab-only.

### Windows
| Check | How it reads | Bypass |
|---|---|---|
| `IsDebuggerPresent` / `PEB.BeingDebugged` | PEB at `gs:[0x60]` (x64) / `fs:[0x30]` (x86). Byte at `+0x02`. | Zero the byte. ScyllaHide does it. |
| `PEB.NtGlobalFlag` | `+0xBC` (x64) / `+0x68` (x86). `0x70` = heap debug flags set when launched by a debugger. | Zero it, or attach instead of launching. |
| Heap flags | `ProcessHeap` at PEB `+0x30`/`+0x18`. `Flags` `+0x70`/`+0x40` should be 2. `ForceFlags` `+0x74`/`+0x44` should be 0. | Attach after start, or patch. ScyllaHide covers it. |
| `CheckRemoteDebuggerPresent` / `NtQueryInformationProcess` | Classes `ProcessDebugPort` (7, returns -1), `ProcessDebugObjectHandle` (0x1E), `ProcessDebugFlags` (0x1F, returns 0 under a debugger) | Hook `NtQueryInformationProcess`: port 0, handle NULL with `STATUS_PORT_NOT_SET`, flags 1. |
| `NtSetInformationThread(h, ThreadHideFromDebugger=0x11)` | Debugger stops receiving events from the thread | Hook and return success without the syscall. |
| `NtQuerySystemInformation(SystemKernelDebuggerInformation=0x23)`, `KUSER_SHARED_DATA.KdDebuggerEnabled` (`0x7FFE02D4`) | Kernel debugger present | Patch the result. Do not kernel-debug the analysis VM with protected samples. |
| Hardware breakpoints | `GetThreadContext` / exception context `Dr0`–`Dr7` | Hide debug registers (ScyllaHide `NtGetContextThread`). |
| Software breakpoints / integrity | Scan for `0xCC`, CRC of `.text` | Hardware breakpoints only, or break outside the checked range. |
| `CloseHandle(invalid)` / `NtClose` | Raises `EXCEPTION_INVALID_HANDLE` only under a debugger | Pass the exception to the program. |
| Exceptions as control flow | `int 3`, `int 2d`, `ud2`, VEH/SEH handlers that do the real work | Pass exceptions to the program. Break inside the registered handler. |
| TLS callbacks | Run before the entry point | Read `IMAGE_DIRECTORY_ENTRY_TLS` statically. Break there, not at `main`. |
| Anti-attach | Patched `DbgUiRemoteBreakin` / `DbgBreakPoint` in ntdll | Restore the original bytes from disk. |
| Parent / windows / processes | Parent is not `explorer.exe`; `FindWindow` for debugger classes; process names | Rename tools, launch from Explorer. |
| Timing | `rdtsc`, `QueryPerformanceCounter`, `GetTickCount64` deltas | Patch the compare. Do not single-step through the measured region. |

### Linux
| Check | How it reads | Bypass |
|---|---|---|
| `ptrace(PTRACE_TRACEME)` | Returns -1 (`EPERM`) when already traced | `LD_PRELOAD` hook only works for the libc wrapper. A raw `syscall` (nr 101 x86_64, 117 arm64) needs a patch, or gdb `catch syscall ptrace` then `set $rax = 0` on return. |
| Self-attach / fork-and-attach | Child `PTRACE_ATTACH`es the parent so nobody else can | Patch the fork path. Debug the child with `set follow-fork-mode child`. |
| `/proc/self/status` `TracerPid` | Non-zero means traced | Hook `open`/`read` for that path, or patch the parser. |
| `/proc/self/stat` state, `/proc/self/wchan` | `t` (tracing stop), `ptrace_stop` | Same as above. |
| Parent name | `/proc/<ppid>/cmdline` contains `gdb`, `strace`, `ltrace` | Launch through a neutral wrapper. |
| `prctl(PR_SET_DUMPABLE, 0)` | Blocks non-root attach and core dumps | Patch, or trace as root. |
| `LD_PRELOAD` / `/etc/ld.so.preload` checks | Detects injection | Use a debugger or Frida spawn instead of preload. |
| `SIGTRAP` self-signal | `raise(SIGTRAP)` / `int3` with a handler doing real work | gdb: `handle SIGTRAP nostop noprint pass`. |
| Timing | `rdtsc`, `clock_gettime` | Patch the compare. |

### macOS / iOS
| Check | How it reads | Bypass |
|---|---|---|
| `ptrace(PT_DENY_ATTACH=31)` | Debugger cannot attach; an attached one kills the process. Often inlined as `svc #0x80` with `x16 = 26`. | Break on the `ptrace`/syscall site and skip it, or patch the immediate. |
| `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID)` | `kinfo_proc.kp_proc.p_flag & P_TRACED (0x800)` | Hook `sysctl` and clear the bit. |
| `task_get_exception_ports` | Debugger installs exception ports | Hook and return an empty set. |
| `csops(pid, CS_OPS_STATUS)` | `CS_DEBUGGED (0x10000000)` | Hook `csops`. |
| `getppid() != 1` | Not launched by launchd | Launch via `open` / launchd. |
| Jailbreak / injection | Paths (`/Applications/Cydia.app`, `/var/jb`), `DYLD_INSERT_LIBRARIES`, `_dyld_get_image_name` scan | Hook the file APIs and the image list in the lab. |

### Android
| Check | How it reads | Bypass |
|---|---|---|
| Java debugger | `Debug.isDebuggerConnected()`, `ApplicationInfo.FLAG_DEBUGGABLE` | Hook the Java method. |
| Native tracer | `TracerPid`, `ptrace(PTRACE_TRACEME)` in `JNI_OnLoad` or `.init_array` | Hook early (spawn mode) or patch the library. |
| Frida server | Connect to `127.0.0.1:27042`, D-Bus `AUTH` probe on open ports | Run the server on another port: `frida-server -l 0.0.0.0:41921`, then `frida -H 127.0.0.1:41921`. |
| Frida in-process | `/proc/self/maps` contains `frida-agent` / `frida-gadget`; thread names in `/proc/self/task/*/comm` (`gum-js-loop`, `gmain`, `gdbus`, `pool-frida`); named pipes / sockets with `frida` | Hook the `open`/`read` of those paths, or use a renamed Frida build. Detection often runs in its own thread: find it via `pthread_create` callers. |
| Inline hook detection | Compare libc prologues in memory with the file on disk | Hook later, below the checked function, or use hardware breakpoints. |
| Root / emulator | `su` paths, Magisk files, `ro.debuggable`, `ro.kernel.qemu`, build fingerprint | Out of scope for the logic. Hook or patch in the lab. |

### Anti-VM / Sandbox
| Check | Detail | Countermeasure |
|---|---|---|
| CPUID leaf 1, ECX bit 31 | Hypervisor present | QEMU/KVM `-cpu host,-hypervisor,kvm=off`. VMware `.vmx`: `hypervisor.cpuid.v0 = "FALSE"`. |
| CPUID leaf `0x40000000` | `VMwareVMware`, `Microsoft Hv`, `KVMKVMKVM`, `VBoxVBoxVBox`, `XenVMMXenVMM`, `TCGTCGTCGTCG` | Same settings. Hiding the leaf is a hypervisor config, not a guest patch. |
| VMware backdoor | `in eax, dx` with `EAX = 0x564D5868` (`VMXh`), `DX = 0x5658` | `.vmx`: `monitor_control.restrict_backdoor = "TRUE"` (breaks VMware Tools). |
| MAC OUI | VMware `00:05:69`, `00:0C:29`, `00:1C:14`, `00:50:56`; VirtualBox `08:00:27`; Hyper-V `00:15:5D`; QEMU `52:54:00` | Set a physical-vendor MAC. |
| Firmware / drivers / services | SMBIOS strings (`VMware`, `VBOX`, `QEMU`), `VBoxGuest.sys`, `vmtoolsd.exe`, `vmci.sys`, registry `HARDWARE\DESCRIPTION\System\BIOS` | Edit SMBIOS strings in the hypervisor config; skip guest tools in the detonation VM. |
| Resources and activity | < 4 CPUs, < 4 GB RAM, < 60 GB disk, no recent files, no mouse movement, short uptime | Size the VM realistically. Age the image. |

When a sample exits early with no visible check, diff the trace of the lab run against a run on a hardened VM. The first divergent API call is usually the check.

---

## 9. Verify
- After deflattening: every relevant block has the successors the algorithm derived, and the function returns on the same inputs (emulate it with fixed inputs before and after).
- After MBA simplification: Z3 proves the old and new expressions equal at the real bit width.
- After an opaque-predicate patch: Z3 proves the condition constant, and no code writes the globals it reads.
- After a VM lift: outputs match the original on at least a handful of inputs.
- After an anti-debug bypass: the program reaches the same code with and without the debugger.

## 10. Boundaries And Anti-Patterns
- Do not trust a deobfuscator's output without one of the checks above. A wrong patch looks like clean code.
- Do not run full-function symbolic exploration on flattened code.
- Do not apply OLLVM tools to a VM-protected function. Flattening removal does nothing to a bytecode interpreter.
- Do not use cloud deobfuscation services on confidential samples.
- Do not run unpackers that execute the target (unlicense, vmpdump, VMPImportFixer) outside the lab VM.
- Removing a license check to avoid paying is out of scope. Documenting how it works is in scope.
