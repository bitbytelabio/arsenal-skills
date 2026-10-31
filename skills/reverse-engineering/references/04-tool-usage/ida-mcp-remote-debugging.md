# Remote debugging through the official `HexRaysSA/ida-mcp`

Load this when the task allows execution and you drive IDA's debugger from an agent through `HexRaysSA/ida-mcp`. Debug-server placement, ports, and the lab VMs are in [../05-environment/ida-remote-debugging.md](../05-environment/ida-remote-debugging.md). Containment rules are in [../02-dynamic-instrumentation/malware-sandbox-isolation.md](../02-dynamic-instrumentation/malware-sandbox-isolation.md).

## What the server gives you

`ida-mcp` has six tools and no debugger tool:

| Tool | Use in a debug session |
|---|---|
| `open_database(path, set_current, load_options, gui)` | Open the target. Use `gui=true` for debugging. |
| `execute_python(code, instance_id, timeout)` | Runs IDAPython in the IDA process. Imports and globals persist for the agent's database lease. |
| `reference(query)` | Looks up the `ida-domain` API. It does not cover `ida_dbg`; use the helper below for debugger calls. |
| `list_databases()` | Find the GUI instance id when several IDBs are open. |
| `save_database(instance_id)` | Keep renames and comments made during the session. |
| `close_database(instance_id)` | Release the lease. A GUI database stays open. |

Globals persisting across `execute_python` calls is what makes debugging workable. Load one helper once, then make short calls to it. You do not need a fork of `ida-mcp` or `ida-domain`.

## Rules

1. **Never wait without a bound.** `execute_python` runs on IDA's main thread. `ida_dbg.wait_for_next_event(..., -1)` freezes the IDA GUI and the MCP call until the target stops. If the target is reading the network or a pipe, that is never. The helper caps every wait at `MAX_WAIT` (5 s). A longer run returns `RUNNING`; check it later with `re_dbg.poll()`.
2. **Use the GUI database or an `idat` worker.** Open the sample with `open_database(path, gui=true)` when the user wants to watch, or attach to the IDB they already have open. Headless workers run inside `idat` when the ida-mcp GUI plugin is installed. That path was verified: `ida/re_dbg.py` in IDA 9.4 `idat` against `armlinux_server` started a process, stepped, traced, and saw the exit. Do not set `IDA_NEXUS_IDALIB_ONLY=1` for a debug session. It moves workers into plain idalib, and the debugger is untested there.
3. **Invalidate before reading live state.** IDA caches registers and memory. The helper calls `invalidate_dbg_state` before every read. If you call `ida_dbg` directly, do the same.
4. **Read the debuggee directly.** `ida_idd.dbg_read_memory` (`re_dbg.read`) asks the debug server. `ida_bytes.get_bytes` goes through IDA's memory cache and can return stale bytes after the target writes memory.
5. **Trace loops; do not single-step them over MCP.** A decryption loop hit 500 times costs 500 round trips by stepping. A trace breakpoint logs registers and memory on every hit and does not stop the target. Collect the records with one call afterwards.
6. **Keep each call small.** One action per `execute_python`, and return a dict. Big dumps go to a file with `re_dbg.dump`, not into the reply.
7. **The debug server runs in the lab, never on the host.** Containment comes first. The helper does not change that.

## Bootstrap

1. Start the debug server in the guest or container, and forward its port (default 23946). See the environment reference.
2. `open_database(path="<sample or .i64>", gui=true)`. Note the returned instance id.
3. Read [`ida/re_dbg.py`](../../ida/re_dbg.py) and pass its full text as `code` to `execute_python`. The call returns `re_dbg.status()`, which should be `NO_PROCESS`.
4. Later calls are one line each, for example `re_dbg.poll()`.

Loading the helper again is safe. It unhooks the previous event logger first.

The helper is also published as `__main__.re_dbg`. IDA evaluates Python breakpoint conditions in `__main__`, and trace breakpoints depend on that.

## Pick the debugger module

| Server in the lab | `re_dbg.load(...)` module |
|---|---|
| `win64_remote.exe`, `win32_remote32.exe` | `"win32"` |
| `linux_server`, `linux_server32` | `"linux"` |
| `armlinux_server`, `android_server`, `android_server32` | `"armlinux"` |
| `mac_server`, `mac_server_arm` | `"mac"` |
| `gdbserver`, QEMU `-s` gdbstub | `"gdb"` |

`path` and `sdir` passed to `re_dbg.start` are paths **on the debug server's machine**, such as `/workspace/sample` in the Docker container or `C:\Workspace\sample.exe` in the Windows VM.

## Session recipes

Each line below is one `execute_python` call.

### Start under the debugger, stop at the entry point

```python
re_dbg.load("armlinux", host="127.0.0.1", port=23946)       # Docker ida_debug_target
re_dbg.start("/workspace/sample", args="", sdir="/workspace")
re_dbg.regs()
re_dbg.bp(0x401560)
re_dbg.cont()          # returns within 5 s: SUSPENDED at the bp, or RUNNING
re_dbg.poll()          # repeat until state is SUSPENDED or events show process_exit
```

### Attach to a running process

```python
re_dbg.load("win32", host="127.0.0.1", port=23946)          # Windows VM, forwarded port
re_dbg.attach(4312)
re_dbg.modules()
```

### Trace a loop without stopping

```python
re_dbg.trace_bp(0x4015A0, regs=["RSI", "RDI", "RCX"], mem=[("RSI", 32)])
re_dbg.cont(wait=0)    # let it run; returns at once
re_dbg.poll()          # state + new events (breakpoints, exceptions, exit)
re_dbg.trace_take()    # list of {ea, tid, RSI, RDI, RCX, *RSI} records
re_dbg.bp_del(0x4015A0)
```

The condition handler returns `False`, so IDA logs the hit and keeps running. An exception inside the handler is recorded as `{"error": ...}` and does not stop the target. `trace_limit` (5000) caps the buffer.

### Step

```python
re_dbg.step_over()
re_dbg.step_into()
re_dbg.step_out()
re_dbg.run_to(0x401700)
```

Each step returns `{status, events, event_code}`. A step that does not finish within 5 s returns `RUNNING`. That means the code under the cursor is waiting on something, such as I/O, a lock, or a sleep. Use `re_dbg.pause()` and then read the stack.

### Read and change state

```python
re_dbg.read(0x7ffe1000, 64)          # hex of live bytes
re_dbg.read_str(0x7ffe1000, wide=True)
re_dbg.set_reg("RAX", 0)
re_dbg.write(0x404000, "9090")
re_dbg.dump(0x10000000, 0x20000, "/path/on/ida/host/region.bin")
re_dbg.bp(0x404010, hw="w", size=4)  # hardware write watchpoint
```

### Tear down

```python
re_dbg.kill()          # or re_dbg.detach()
re_dbg.uninstall()
```

Then `save_database()` if you renamed anything, and `close_database()`.

## Reading results

| `status.state` | Meaning | Next call |
|---|---|---|
| `NO_PROCESS` | Not started, exited, or detached | `poll()` events show `process_exit` with the exit code |
| `RUNNING` | The wait expired while the target runs | `poll()` again, or `pause()` |
| `SUSPENDED` | Stopped at a breakpoint, step, exception, or pause | `regs()`, `read()`, and step or continue |

`event_code` is the raw `wait_for_next_event` result. A value of 0 or less means the wait timed out or no event arrived.

`exception` events carry the code (for example `0xc0000005`). Breakpoints and exceptions are also recorded while the target runs between calls, so check `poll()` before you assume nothing happened.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `load()` returns `loaded: False` | Wrong module name, or the debugger plugin is missing for this IDB's processor | Match the module table. An ARM64 IDB needs `armlinux` or `mac`, not `linux`. |
| `start()` stays `NO_PROCESS`, no events | The server is not reachable | `nc -vz 127.0.0.1 23946` from the IDA host. Check the port forward and the guest firewall. |
| A dialog appears in the IDA GUI and the call times out | IDA asked a question, such as path mapping or "process is already running" | Answer it once in the GUI. Pass the remote `path` and `sdir` explicitly. |
| `regs()` returns `{}` | The process is not suspended, or the register names do not match the processor | Call `pause()` first. Pass `names=[...]` for unusual targets. |
| Trace records never appear | The condition did not resolve `re_dbg` | Reload the helper. It republishes itself into `__main__`. |
| MCP call returns a timeout error | You called `ida_dbg` directly with a long or `-1` wait | Use the helper methods. Restart the IDA GUI if it is frozen. |

## When a fork would be worth it

Only in two cases. One is a small model that cannot write correct IDAPython and needs fixed tools such as `dbg_step`. The other is push notifications, where IDA wakes the agent on a breakpoint instead of the agent polling. The helper covers everything else, and `ida-mcp` updates do not conflict with it.
