"""Bounded remote-debug helper for the official HexRaysSA/ida-mcp server.

This is IDAPython, not a uv script. It runs inside IDA. Send the whole file as
the `code` argument of ida-mcp `execute_python` once per database lease;
ida-mcp keeps globals for the lease, so later calls just use `re_dbg.*`.
It also works from File > Script file in the IDA GUI.

Why it exists: execute_python runs on IDA's main thread. A debugger wait with
no timeout (wait_for_next_event(..., -1)) freezes the GUI and the MCP call
until the target stops, which may be never. Every wait here is capped
(MAX_WAIT seconds). Long runs return "RUNNING" and are checked later with
re_dbg.poll().

Debugger module names for load():
  win64_remote.exe / win32_remote32.exe -> "win32"
  linux_server / linux_server32         -> "linux"
  armlinux_server / android_server*     -> "armlinux"
  mac_server / mac_server_arm           -> "mac"
  gdbserver / QEMU gdbstub              -> "gdb"
"""

import __main__
import time

import ida_dbg
import ida_ida
import ida_idd
import ida_kernwin
import idc

MAX_WAIT = 5  # seconds; keep each execute_python call short

_STATES = {
    ida_dbg.DSTATE_NOTASK: "NO_PROCESS",
    ida_dbg.DSTATE_RUN: "RUNNING",
    ida_dbg.DSTATE_SUSP: "SUSPENDED",
}

_REGS_X64 = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "EFL"]
_REGS_X86 = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFL"]
_REGS_A64 = ["X%d" % i for i in range(29)] + ["FP", "LR", "SP", "PC", "PSR"]
_REGS_A32 = ["R%d" % i for i in range(13)] + ["SP", "LR", "PC", "PSR"]


def _hex(v):
    return None if v is None else hex(v)


class _EventLog(ida_dbg.DBG_Hooks):
    """Records debugger events so a later poll() sees what happened while the
    target ran between MCP calls. Never changes how IDA handles the event."""

    def __init__(self, limit=500):
        super().__init__()
        self.events = []
        self.limit = limit

    def _add(self, kind, **kw):
        kw["kind"] = kind
        kw["t"] = round(time.time(), 3)
        self.events.append(kw)
        del self.events[:-self.limit]

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self._add("process_start", pid=pid, ea=_hex(ea), name=name)

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self._add("process_attach", pid=pid, ea=_hex(ea), name=name)

    def dbg_process_exit(self, pid, tid, ea, code):
        self._add("process_exit", pid=pid, exit_code=code)

    def dbg_process_detach(self, pid, tid, ea):
        self._add("process_detach", pid=pid)

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        self._add("library_load", name=name, base=_hex(base))

    def dbg_bpt(self, tid, ea):
        self._add("breakpoint", tid=tid, ea=_hex(ea))
        return 0

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        self._add("exception", tid=tid, ea=_hex(ea), code=_hex(exc_code & 0xFFFFFFFF), info=exc_info)
        return 0

    def dbg_suspend_process(self):
        self._add("suspended", ip=_hex(idc.get_reg_value(_ip_name())) if ida_dbg.is_debugger_on() else None)


def _ip_name():
    proc = ida_ida.inf_get_procname().lower()
    if proc.startswith("arm"):
        return "PC"
    return "RIP" if ida_ida.inf_is_64bit() else "EIP"


class ReDbg:
    def __init__(self):
        self.log = _EventLog()
        self.log.hook()
        self._seen = 0
        self.trace = []          # filled by trace breakpoints
        self.trace_limit = 5000
        self._trace_specs = {}   # ea -> {"regs": [...], "mem": [(reg, size)]}

    # ---- session ---------------------------------------------------------
    def load(self, debugger, host="127.0.0.1", port=23946, password=""):
        """Select a remote debugger module and its server address."""
        ok = ida_dbg.load_debugger(debugger, True)
        ida_dbg.set_remote_debugger(host, password, port)
        return {"loaded": bool(ok), "debugger": debugger, "host": host, "port": port}

    def start(self, path="", args="", sdir="", break_on_entry=True, wait=MAX_WAIT):
        """Start a process on the debug server. path/sdir are paths on the
        remote machine; empty path uses the database input file."""
        # set_debugger_options returns the previous value; there is no getter.
        opts = ida_dbg.set_debugger_options(0)
        flag = ida_dbg.DOPT_ENTRY_BPT
        ida_dbg.set_debugger_options((opts | flag) if break_on_entry else (opts & ~flag))
        ida_dbg.request_start_process(path or None, args or None, sdir or None)
        ida_dbg.run_requests()
        return self._wait(wait)

    def attach(self, pid, wait=MAX_WAIT):
        ida_dbg.request_attach_process(pid, -1)
        ida_dbg.run_requests()
        return self._wait(wait)

    def detach(self):
        ida_dbg.request_detach_process()
        ida_dbg.run_requests()
        return self._wait(MAX_WAIT)

    def kill(self):
        ida_dbg.request_exit_process()
        ida_dbg.run_requests()
        return self._wait(MAX_WAIT)

    # ---- state -----------------------------------------------------------
    def status(self):
        state = ida_dbg.get_process_state()
        res = {"state": _STATES.get(state, "UNKNOWN(%d)" % state)}
        if state == ida_dbg.DSTATE_SUSP:
            ida_dbg.invalidate_dbg_state(ida_dbg.DBGINV_ALL)
            ip = idc.get_reg_value(_ip_name())
            res["ip"] = _hex(ip)
            res["disasm"] = idc.generate_disasm_line(ip, 0)
            res["func"] = idc.get_func_name(ip) or None
            res["tid"] = ida_dbg.get_current_thread()
        return res

    def poll(self):
        """Non-blocking: state plus debugger events since the last poll."""
        new = self.log.events[self._seen:]
        self._seen = len(self.log.events)
        return {"status": self.status(), "events": new}

    # ---- execution (every wait is bounded) -------------------------------
    def _wait(self, timeout):
        # The SDK takes whole seconds; -1 would wait forever, so clamp to 0..MAX_WAIT.
        timeout = int(max(0, min(float(timeout), MAX_WAIT)))
        ev = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT, timeout) if timeout > 0 else 0
        ida_dbg.invalidate_dbg_state(ida_dbg.DBGINV_ALL)
        out = self.poll()
        out["event_code"] = ev
        return out

    def _need_suspended(self):
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            return {"error": "process is not suspended", "status": self.status()}
        return None

    def step_into(self, wait=MAX_WAIT):
        err = self._need_suspended()
        if err:
            return err
        ida_dbg.request_step_into()
        ida_dbg.run_requests()
        return self._wait(wait)

    def step_over(self, wait=MAX_WAIT):
        err = self._need_suspended()
        if err:
            return err
        ida_dbg.request_step_over()
        ida_dbg.run_requests()
        return self._wait(wait)

    def step_out(self, wait=MAX_WAIT):
        err = self._need_suspended()
        if err:
            return err
        ida_dbg.request_step_until_ret()
        ida_dbg.run_requests()
        return self._wait(wait)

    def cont(self, wait=MAX_WAIT):
        """Resume. wait=0 returns at once (target keeps RUNNING); use poll()."""
        ida_dbg.request_continue_process()
        ida_dbg.run_requests()
        return self._wait(wait)

    def run_to(self, ea, wait=MAX_WAIT):
        ida_dbg.request_run_to(ea)
        ida_dbg.run_requests()
        return self._wait(wait)

    def pause(self, wait=MAX_WAIT):
        ida_dbg.request_suspend_process()
        ida_dbg.run_requests()
        return self._wait(wait)

    # ---- registers and memory -------------------------------------------
    def regs(self, names=None):
        err = self._need_suspended()
        if err:
            return err
        ida_dbg.invalidate_dbg_state(ida_dbg.DBGINV_REGS)
        if not names:
            proc = ida_ida.inf_get_procname().lower()
            if proc.startswith("arm"):
                names = _REGS_A64 if ida_ida.inf_is_64bit() else _REGS_A32
            else:
                names = _REGS_X64 if ida_ida.inf_is_64bit() else _REGS_X86
        out = {}
        for n in names:
            try:
                out[n] = hex(idc.get_reg_value(n))
            except Exception:
                pass
        return out

    def set_reg(self, name, value):
        err = self._need_suspended()
        if err:
            return err
        return {"ok": bool(idc.set_reg_value(value, name)), name: hex(value)}

    def read(self, ea, size=64):
        """Live memory from the debuggee (not the IDB copy)."""
        err = self._need_suspended()
        if err:
            return err
        ida_dbg.invalidate_dbg_state(ida_dbg.DBGINV_MEMORY)
        data = ida_idd.dbg_read_memory(ea, size)
        return {"ea": hex(ea), "size": size, "hex": data.hex() if data else None}

    def read_str(self, ea, limit=256, wide=False):
        r = self.read(ea, limit)
        raw = bytes.fromhex(r["hex"]) if r.get("hex") else b""
        if wide:
            text = raw.decode("utf-16le", "replace").split("\x00", 1)[0]
        else:
            text = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        return {"ea": hex(ea), "text": text}

    def write(self, ea, data_hex):
        err = self._need_suspended()
        if err:
            return err
        data = bytes.fromhex(data_hex)
        n = ida_idd.dbg_write_memory(ea, data)
        return {"ea": hex(ea), "written": n}

    def dump(self, ea, size, host_path):
        """Write live memory to a file on the machine running IDA."""
        r = self.read(ea, size)
        if not r.get("hex"):
            return {"error": "read failed", "ea": hex(ea)}
        with open(host_path, "wb") as f:
            f.write(bytes.fromhex(r["hex"]))
        return {"path": host_path, "size": size}

    def modules(self):
        mods = []
        mi = ida_idd.modinfo_t()
        ok = ida_dbg.get_first_module(mi)
        while ok:
            mods.append({"name": mi.name, "base": hex(mi.base), "size": mi.size})
            ok = ida_dbg.get_next_module(mi)
        return mods

    def threads(self):
        return [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]

    # ---- breakpoints -----------------------------------------------------
    def bp(self, ea, enabled=True, hw=None, size=1):
        """hw: None (software), "x", "w", or "rw" for a hardware breakpoint."""
        kinds = {None: ida_idd.BPT_DEFAULT, "x": ida_idd.BPT_EXEC,
                 "w": ida_idd.BPT_WRITE, "rw": ida_idd.BPT_RDWR}
        size = 0 if hw in (None, "x") else size
        ida_dbg.add_bpt(ea, size, kinds[hw])
        ida_dbg.enable_bpt(ea, enabled)
        return {"bp": hex(ea), "type": hw or "sw", "enabled": enabled}

    def bp_del(self, ea):
        self._trace_specs.pop(ea, None)
        return {"bp": hex(ea), "deleted": bool(ida_dbg.del_bpt(ea))}

    def bps(self):
        out = []
        for i in range(ida_dbg.get_bpt_qty()):
            b = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(i, b):
                out.append({"ea": hex(b.ea), "enabled": b.enabled(), "condition": b.condition or None})
        return out

    # ---- tracing without stopping ----------------------------------------
    def trace_bp(self, ea, regs=None, mem=None):
        """Log registers (and memory at registers) each time ea is hit, then
        continue without suspending. mem: list of (reg_name, size).

        Uses a Python breakpoint condition that returns False. IDA evaluates
        conditions in the __main__ namespace, which is why install() also
        publishes the helper there."""
        self._trace_specs[ea] = {"regs": regs or [], "mem": mem or []}
        ida_dbg.add_bpt(ea, 0, ida_idd.BPT_DEFAULT)
        b = ida_dbg.bpt_t()
        ida_dbg.get_bpt(ea, b)
        b.elang = "Python"
        b.condition = "re_dbg._on_trace(%d)" % ea
        ida_dbg.update_bpt(b)
        return {"trace_bp": hex(ea), "regs": regs, "mem": mem}

    def _on_trace(self, ea):
        try:
            spec = self._trace_specs.get(ea, {})
            rec = {"ea": hex(ea), "tid": ida_dbg.get_current_thread()}
            for r in spec.get("regs", []):
                rec[r] = hex(idc.get_reg_value(r))
            for reg, size in spec.get("mem", []):
                ptr = idc.get_reg_value(reg)
                data = ida_idd.dbg_read_memory(ptr, size)
                rec["*%s" % reg] = data.hex() if data else None
            self.trace.append(rec)
            del self.trace[:-self.trace_limit]
        except Exception as exc:  # never let a condition error stop the target
            self.trace.append({"ea": hex(ea), "error": str(exc)})
        return False

    def trace_take(self, clear=True):
        out = list(self.trace)
        if clear:
            self.trace.clear()
        return out

    # ---- teardown --------------------------------------------------------
    def uninstall(self):
        self.log.unhook()
        return {"unhooked": True}


def install():
    old = getattr(__main__, "re_dbg", None)
    if old is not None:
        try:
            old.uninstall()
        except Exception:
            pass
    helper = ReDbg()
    __main__.re_dbg = helper
    globals()["re_dbg"] = helper
    return helper


re_dbg = install()
ida_kernwin.msg("re_dbg loaded: %r\n" % (re_dbg.status(),))
re_dbg.status()
