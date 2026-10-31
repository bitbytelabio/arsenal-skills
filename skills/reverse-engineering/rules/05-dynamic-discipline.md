# Rule 5: Dynamic Analysis Discipline & Scripting Constraints

## Mandate
All dynamic analysis, debugger sessions, and instrumentation workflows must execute strictly in non-interactive batch or script mode. Interactive REPL sessions (manual interactive GDB, WinDbg prompt, x64dbg GUI interaction, Frida interactive CLI) are **STRICTLY FORBIDDEN**.

## Hard Execution Timeouts
Every dynamic command execution must enforce an explicit process-level timeout to prevent hangs on anti-debugging traps, infinite loops, or network waits:
- Standard command prefix: `timeout 15s <command>` or `timeout 30s <command>`.
- GDB batch invocation example:
  ```bash
  timeout 15s gdb -batch -ex "set pagination off" -ex "file <target>" -ex "run" -ex "bt" -ex "quit"
  ```
- LLDB batch invocation example:
  ```bash
  timeout 15s lldb --batch -o "process launch" -o "thread backtrace" -o "quit" <target>
  ```

## Frida Instrumentation Constraints
All Frida instrumentation scripts must follow strict batch lifecycle contracts:
1. **Targeted Hooks**: Hook specific functions or addresses; avoid broad wildcard intercepts across shared system libraries.
2. **Explicit Data Transmission**: Collect runtime parameters or return buffers and serialize them via `send()`.
3. **Clean Teardown**: Call `Interceptor.detachAll()` upon fulfilling the extraction objective.
4. **Deterministic Exit**: Terminate cleanly via `Process.exit(0)` or signal completion to the harness to ensure execution does not hang indefinitely.

## Anti-Debugging & Evasion Handling
Prolonged interactive step-debugging through anti-debug routines or virtualization stubs is prohibited. Prefer deterministic, lightweight countermeasures:
1. **Direct Memory Patching**: Patch known environment flags or API return values in memory (e.g. `PEB.BeingDebugged`, `ptrace` return values).
2. **Hardware Breakpoints**: Use non-invasive hardware execution breakpoints over software `0xCC` breakpoints to avoid code-integrity integrity scans.
3. **Memory Dumping from OEP**: Let the sample execute its unpacking stub in VM containment, set a breakpoint on the OEP transition or process injection call (`VirtualAllocEx` / `mprotect`), and dump the fully decrypted payload to disk (`dump_memory.py`) for static analysis.
