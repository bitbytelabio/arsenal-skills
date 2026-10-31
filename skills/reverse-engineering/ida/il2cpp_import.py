"""Apply an il2cpp-dumper-rs dump to the open IDB without dialogs.

IDAPython, not a uv script. Run through ida-mcp `execute_python` (or File >
Script file) after setting two globals:

    IL2CPP_SCRIPT_JSON = "/path/Dump0/script.json"
    IL2CPP_HEADER      = "/path/Dump0/il2cpp.h"
    IL2CPP_IDA_SCRIPT  = "/path/il2cpp-dumper-rs/scripts/ida_with_struct_py3.py"  # optional

The upstream ida_with_struct_py3.py asks for both files with ask_file, which
blocks a headless ida-mcp worker forever, and calls get_inf_structure, which
IDA 9 removed. This wrapper answers the dialogs from the globals above, shims
the removed API, and then runs the upstream script unchanged.

Il2CppInspectorRedux output does not need this: its il2cpp.py for IDA finds
its JSON next to itself and runs without prompts.
"""

import os
import urllib.request

import ida_ida
import ida_kernwin
import idaapi

UPSTREAM = "https://raw.githubusercontent.com/rodroidmods/il2cpp-dumper-rs/master/scripts/ida_with_struct_py3.py"

script_json = globals().get("IL2CPP_SCRIPT_JSON")
header = globals().get("IL2CPP_HEADER")
if not (script_json and os.path.isfile(script_json) and header and os.path.isfile(header)):
    raise RuntimeError("Set IL2CPP_SCRIPT_JSON and IL2CPP_HEADER to existing files first")

upstream_path = globals().get("IL2CPP_IDA_SCRIPT")
if upstream_path and os.path.isfile(upstream_path):
    with open(upstream_path, encoding="utf-8") as f:
        upstream_src = f.read()
else:
    with urllib.request.urlopen(UPSTREAM, timeout=60) as resp:
        upstream_src = resp.read().decode("utf-8")

_answers = {"*.json": script_json, "*.h": header}
_saved = {name: getattr(idaapi, name, None) for name in ("ask_file", "get_inf_structure", "show_wait_box", "hide_wait_box")}


class _InfProxy:
    """Stands in for the IDA 8 idainfo object: inf.max_ea -> inf_get_max_ea(),
    inf.is_64bit() -> inf_is_64bit()."""

    def __getattr__(self, name):
        if name.startswith(("is_", "get_")):
            fn = getattr(ida_ida, "inf_" + name, None)
            if fn is not None:
                return fn
        fn = getattr(ida_ida, "inf_get_" + name, None)
        if fn is not None:
            return fn()
        raise AttributeError(name)


def _ask_file(for_saving, mask, prompt):
    return _answers.get(mask)


try:
    idaapi.ask_file = _ask_file
    ida_kernwin.ask_file = _ask_file
    if _saved["get_inf_structure"] is None:  # removed in IDA 9
        idaapi.get_inf_structure = lambda: _InfProxy()
    # Wait boxes are GUI-only; make them no-ops so idat/idalib workers do not stall.
    idaapi.show_wait_box = lambda *a, **k: None
    idaapi.hide_wait_box = lambda *a, **k: None
    exec(compile(upstream_src, "ida_with_struct_py3.py", "exec"), {"__name__": "__main__"})
finally:
    for name, fn in _saved.items():
        if fn is not None:
            setattr(idaapi, name, fn)
        elif hasattr(idaapi, name):
            delattr(idaapi, name)
    if _saved["ask_file"] is not None:
        ida_kernwin.ask_file = _saved["ask_file"]

print("il2cpp import done:", script_json)
