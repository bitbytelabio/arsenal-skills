# Rule 5: Dynamic Analysis Discipline & Scripting Constraints

## Mandate
All dynamic analysis, debugger sessions, and instrumentation run non-interactively, from a script or a batch command that ends on its own. An agent never sits at an interactive prompt: no bare `gdb`, `lldb`, `cdb`, or `frida` REPL waiting for input, and no x64dbg GUI clicking. The allowed forms are below. Each one has a hard time bound.

| Tool | Non-interactive form |
|---|---|
| gdb | `timeout 30 gdb -batch -nx -x cmds.gdb --args "$BIN" ARGS` |
| lldb | `timeout 30 lldb --batch -s cmds.lldb -k bt -- "$BIN" ARGS` |
| cdb | `cdb -logo out.log -G -c "...; g; q" "$BIN"`, run from a job with `Wait-Job -Timeout` |
| Frida CLI | `frida -U -f "$PKG" -l hook.js -q -t 30 --kill-on-exit` (`-q` quits after loading, `-t` is the quiet-mode timeout) |
| Frida Python/Node API | spawn, `create_script`, `resume`, then a wall-clock timer that detaches and kills |
| IDA debugger | official `ida-mcp` `execute_python` with `ida/re_dbg.py`; every wait is capped at `MAX_WAIT` seconds. See [ida-mcp-remote-debugging.md](../references/04-tool-usage/ida-mcp-remote-debugging.md) |
| x64dbg | a script file in the Windows VM, run with `scriptload`, ending in `ret`; the VM orchestrator kills it on timeout |

Command recipes and checked flags are in [debugger-workflows.md](../references/02-dynamic-instrumentation/debugger-workflows.md) and [frida.md](../references/04-tool-usage/frida.md).

## Hard Execution Timeouts
Every dynamic command has a process-level timeout, so an anti-debug trap, an infinite loop, or a network wait cannot hang the session.
- Linux: `timeout 30 <command>` (coreutils). Add `-k 5` to send SIGKILL if SIGTERM is ignored.
- macOS: `timeout` and `gtimeout` come from Homebrew `coreutils`; stock macOS has neither. Without them, run the command from Python `subprocess.run(..., timeout=30)`.
- Windows: a PowerShell job with `Wait-Job -Timeout`, or `Start-Process -PassThru` plus `WaitForExit(ms)` and `Kill()`.
- macOS with Developer Mode off asks for authorization on the first `process launch`, `process attach`, or `frida -f`. Unattended, that prompt is a hang until the timeout. `DevToolsSecurity -status` tells you in advance.

## Frida Instrumentation Constraints
Every Frida script follows a batch lifecycle:
1. **Targeted Hooks**: Hook specific functions or addresses. Do not hook broad wildcards across system libraries.
2. **Explicit Data Transmission**: Serialize arguments, return values, and buffers with `send(obj, bytes)`. Do not rely on `console.log` scraping.
3. **Clean Teardown**: Call `Interceptor.detachAll()` when the objective is met, then `send({type: "done"})`.
4. **Deterministic Exit**: The harness ends the session. A Frida script cannot exit the process itself; there is no `Process.exit`. On `done`, or at the timeout, the CLI exits through `-q -t`, and the API harness calls `session.detach()` and kills the spawned PID.
5. **Bridges (Frida 17)**: `Java`, `ObjC`, and `Swift` exist under the `frida` CLI. A script loaded through the Python or Node API, or built with frida-compile, must bundle `frida-java-bridge` / `frida-objc-bridge`, or guard with `typeof Java !== "undefined"`.

## Anti-Debugging & Evasion Handling
Do not step through anti-debug routines or virtualization stubs by hand for long. Prefer deterministic countermeasures:
1. **Direct Memory Patching**: Patch the environment flag or the API result the check reads (`PEB.BeingDebugged`, `NtGlobalFlag`, the `ptrace(PTRACE_TRACEME)` return value, `sysctl` `P_TRACED`).
2. **Hardware Breakpoints**: Use hardware execution breakpoints rather than software `0xCC` breakpoints, so code-integrity checksums do not see a modified byte.
3. **Memory Dumping from OEP**: Let the unpacking stub run inside containment. Break on the OEP transition or on the injection or protection call (`VirtualAllocEx`, `VirtualProtect`, `mprotect`). Dump the decrypted payload for static analysis: `uv run scripts/dump_memory.py` on Linux and macOS, and `pe-sieve` or `procdump -ma` on Windows. Procedures are in [unpacking-memory-dump.md](../references/02-dynamic-instrumentation/unpacking-memory-dump.md).
