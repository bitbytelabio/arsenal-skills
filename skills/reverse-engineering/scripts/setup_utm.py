#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""UTM hypervisor, QCOW2 snapshot, AppleScript automation, and IDA Pro remote debugging helper.

Provides management commands for UTM VMs via utmctl and AppleScript (osascript),
QCOW2 disks via qemu-img, guest agent interaction, and configuration templates
for IDA Pro remote debugging servers.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NotRequired, TypedDict


class VmEntry(TypedDict):
    uuid: str
    status: str
    name: str


class StatusReport(TypedDict):
    utm_app_present: bool
    utmctl_path: str | None
    qemu_img_path: str | None
    vms: list[VmEntry]
    error: NotRequired[str]


class SnapshotEntry(TypedDict):
    name: str
    raw: NotRequired[str]


class Qcow2SnapshotEntry(TypedDict):
    id: str
    tag: str
    vm_size: str
    date: str
    vm_clock: str
class ServerBinaryEntry(TypedDict):
    name: str
    path: str
    executable: bool

class AppleScriptResult(TypedDict):
    success: bool
    output: NotRequired[str]
    error: NotRequired[str]
    exit_code: NotRequired[int]



def run_cmd(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return None


def get_utmctl_path() -> str | None:
    found = shutil.which("utmctl")
    if found is not None:
        return found
    bundled = Path("/Applications/UTM.app/Contents/MacOS/utmctl")
    if bundled.exists():
        return str(bundled)
    return None
def run_osascript(script: str, timeout: int = 60) -> subprocess.CompletedProcess[str] | None:
    return run_cmd(["osascript", "-e", script], timeout=timeout)


def escape_applescript_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def applescript_vm_target(vm: str) -> str:
    # Check if VM looks like a UUID (8-4-4-4-12 hex)
    uuid_pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    escaped = escape_applescript_string(vm)
    if uuid_pattern.match(vm.strip()):
        return f'virtual machine id "{escaped}"'
    return f'virtual machine named "{escaped}"'



def get_qemu_img_path() -> str | None:
    return shutil.which("qemu-img")


def parse_utmctl_list(output: str) -> list[VmEntry]:
    lines = output.strip().splitlines()
    vms: list[VmEntry] = []
    if not lines:
        return vms

    # First line may be header: UUID  Status  Name
    start_idx = 0
    if len(lines) > 0 and "UUID" in lines[0] and "Status" in lines[0]:
        start_idx = 1

    uuid_pattern = re.compile(
        r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s+(\S+)\s+(.+)$"
    )

    for line in lines[start_idx:]:
        line = line.strip()
        if not line:
            continue
        m = uuid_pattern.match(line)
        if m:
            vms.append({"uuid": m.group(1), "status": m.group(2), "name": m.group(3)})
        else:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                vms.append({"uuid": parts[0], "status": parts[1], "name": parts[2]})
            elif len(parts) == 2:
                vms.append({"uuid": parts[0], "status": parts[1], "name": ""})
    return vms


def cmd_status(json_mode: bool) -> int:
    utm_app_present = Path("/Applications/UTM.app").exists()
    utmctl_path = get_utmctl_path()
    qemu_img_path = get_qemu_img_path()

    vms: list[VmEntry] = []
    error_msg: str | None = None

    if utmctl_path:
        proc = run_cmd([utmctl_path, "list"])
        if proc and proc.returncode == 0:
            vms = parse_utmctl_list(proc.stdout)
        elif proc:
            error_msg = proc.stderr.strip() or f"utmctl list exited with {proc.returncode}"
    else:
        error_msg = "utmctl not found on host"

    report: StatusReport = {
        "utm_app_present": utm_app_present,
        "utmctl_path": utmctl_path,
        "qemu_img_path": qemu_img_path,
        "vms": vms,
    }
    if error_msg:
        report["error"] = error_msg

    if json_mode:
        print(json.dumps(report, indent=2))
    else:
        print("=== UTM & QCOW2 Host Status ===")
        print(f"UTM.app present: {utm_app_present}")
        print(f"utmctl path:     {utmctl_path or 'Not installed'}")
        print(f"qemu-img path:   {qemu_img_path or 'Not installed'}")
        print(f"VM Count:        {len(vms)}")
        for vm in vms:
            print(f"  [{vm['status']}] {vm['name']} ({vm['uuid']})")
        if error_msg:
            print(f"Notice:          {error_msg}")
    return 0


def cmd_list_vms(json_mode: bool) -> int:
    utmctl = get_utmctl_path()
    if not utmctl:
        err = {"error": "utmctl executable not found"}
        if json_mode:
            print(json.dumps(err, indent=2))
        else:
            print("Error: utmctl executable not found", file=sys.stderr)
        return 1

    proc = run_cmd([utmctl, "list"])
    if not proc or proc.returncode != 0:
        err_msg = proc.stderr.strip() if proc else "Failed to execute utmctl list"
        if json_mode:
            print(json.dumps({"error": err_msg}, indent=2))
        else:
            print(f"Error: {err_msg}", file=sys.stderr)
        return 1

    vms = parse_utmctl_list(proc.stdout)
    if json_mode:
        print(json.dumps(vms, indent=2))
    else:
        for vm in vms:
            print(f"{vm['uuid']}\t{vm['status']}\t{vm['name']}")
    return 0


def cmd_snapshot_list(vm: str, json_mode: bool) -> int:
    utmctl = get_utmctl_path()
    if not utmctl:
        if json_mode:
            print(json.dumps({"error": "utmctl not found"}, indent=2))
        else:
            print("Error: utmctl not found", file=sys.stderr)
        return 1

    # utmctl snapshot list supports --json directly
    proc = run_cmd([utmctl, "snapshot", "list", vm, "--json"])
    if proc and proc.returncode == 0:
        stdout_clean = proc.stdout.strip()
        try:
            parsed = json.loads(stdout_clean) if stdout_clean else []
            if json_mode:
                print(json.dumps(parsed, indent=2))
            else:
                if not parsed:
                    print(f"No snapshots found for VM '{vm}'.")
                else:
                    for s in parsed:
                        print(s)
            return 0
        except json.JSONDecodeError:
            pass

    # Fallback to plain list without --json
    proc_plain = run_cmd([utmctl, "snapshot", "list", vm])
    if not proc_plain or proc_plain.returncode != 0:
        err = proc_plain.stderr.strip() if proc_plain else "Failed to run utmctl snapshot list"
        if json_mode:
            print(json.dumps({"error": err}, indent=2))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    lines = [line.strip() for line in proc_plain.stdout.splitlines() if line.strip()]
    if json_mode:
        print(json.dumps(lines, indent=2))
    else:
        if not lines:
            print(f"No snapshots found for VM '{vm}'.")
        else:
            for line in lines:
                print(line)
    return 0


def cmd_snapshot_create(vm: str, name: str, json_mode: bool) -> int:
    utmctl = get_utmctl_path()
    if not utmctl:
        if json_mode:
            print(json.dumps({"error": "utmctl not found"}, indent=2))
        else:
            print("Error: utmctl not found", file=sys.stderr)
        return 1

    proc = run_cmd([utmctl, "snapshot", "create", vm, "--name", name], timeout=120)
    if not proc or proc.returncode != 0:
        err = proc.stderr.strip() if proc else "Failed to create snapshot"
        if json_mode:
            print(
                json.dumps({"error": err, "vm": vm, "snapshot": name, "success": False}, indent=2)
            )
        else:
            print(f"Error creating snapshot: {err}", file=sys.stderr)
        return 1

    if json_mode:
        print(
            json.dumps(
                {"vm": vm, "snapshot": name, "success": True, "output": proc.stdout.strip()},
                indent=2,
            )
        )
    else:
        print(f"Snapshot '{name}' successfully created for VM '{vm}'.")
    return 0


def cmd_snapshot_restore(vm: str, name: str, json_mode: bool) -> int:
    utmctl = get_utmctl_path()
    if not utmctl:
        if json_mode:
            print(json.dumps({"error": "utmctl not found"}, indent=2))
        else:
            print("Error: utmctl not found", file=sys.stderr)
        return 1

    proc = run_cmd([utmctl, "snapshot", "restore", vm, "--snapshot", name], timeout=120)
    if not proc or proc.returncode != 0:
        err = proc.stderr.strip() if proc else "Failed to restore snapshot"
        if json_mode:
            print(
                json.dumps({"error": err, "vm": vm, "snapshot": name, "success": False}, indent=2)
            )
        else:
            print(f"Error restoring snapshot: {err}", file=sys.stderr)
        return 1

    if json_mode:
        print(
            json.dumps(
                {"vm": vm, "snapshot": name, "success": True, "output": proc.stdout.strip()},
                indent=2,
            )
        )
    else:
        print(f"VM '{vm}' successfully restored to snapshot '{name}'.")
    return 0


def cmd_qcow2_create(output_path: str, size_gb: str, backing: str | None, json_mode: bool) -> int:
    qemu_img = get_qemu_img_path()
    if not qemu_img:
        if json_mode:
            print(json.dumps({"error": "qemu-img not found"}, indent=2))
        else:
            print("Error: qemu-img not found", file=sys.stderr)
        return 1

    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    size_param = f"{size_gb}G" if size_gb.isdigit() else size_gb

    args = [qemu_img, "create", "-f", "qcow2"]
    if backing:
        backing_path = str(Path(backing).resolve())
        args.extend(["-b", backing_path, "-F", "qcow2"])
    args.extend([str(out_file), size_param])

    proc = run_cmd(args, timeout=60)
    if not proc or proc.returncode != 0:
        err = proc.stderr.strip() if proc else "Failed to run qemu-img create"
        if json_mode:
            print(json.dumps({"error": err, "path": str(out_file), "success": False}, indent=2))
        else:
            print(f"Error creating QCOW2 image: {err}", file=sys.stderr)
        return 1

    result = {
        "success": True,
        "path": str(out_file),
        "size": size_param,
        "backing_file": str(Path(backing).resolve()) if backing else None,
        "output": proc.stdout.strip(),
    }
    if json_mode:
        print(json.dumps(result, indent=2))
    else:
        print(f"Created QCOW2 image: {out_file} (size {size_param})")
        if backing:
            print(f"Backing file: {Path(backing).resolve()}")
    return 0


def cmd_qcow2_snapshot(
    qcow2_path: str,
    action: str,
    snap_name: str | None,
    json_mode: bool,
) -> int:
    qemu_img = get_qemu_img_path()
    if not qemu_img:
        if json_mode:
            print(json.dumps({"error": "qemu-img not found"}, indent=2))
        else:
            print("Error: qemu-img not found", file=sys.stderr)
        return 1

    target = Path(qcow2_path).resolve()
    if not target.exists():
        err = f"File not found: {target}"
        if json_mode:
            print(json.dumps({"error": err}, indent=2))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    if action == "list":
        # First try qemu-img info --out=json
        proc_info = run_cmd([qemu_img, "info", "--out=json", str(target)])
        if proc_info and proc_info.returncode == 0:
            try:
                info_data = json.loads(proc_info.stdout)
                snapshots = info_data.get("snapshots", [])
                if json_mode:
                    print(json.dumps(snapshots, indent=2))
                    return 0
            except json.JSONDecodeError:
                pass

        proc = run_cmd([qemu_img, "snapshot", "-l", str(target)])
        if not proc or proc.returncode != 0:
            err = proc.stderr.strip() if proc else "Failed to list snapshots"
            if json_mode:
                print(json.dumps({"error": err}, indent=2))
            else:
                print(f"Error: {err}", file=sys.stderr)
            return 1

        if json_mode:
            lines = [line_str.strip() for line_str in proc.stdout.splitlines() if line_str.strip()]
            print(json.dumps(lines, indent=2))
        else:
            print(proc.stdout)
        return 0

    if not snap_name:
        err = f"Snapshot name required for --{action}"
        if json_mode:
            print(json.dumps({"error": err}, indent=2))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    flag_map = {
        "create": "-c",
        "restore": "-a",
        "delete": "-d",
    }
    flag = flag_map.get(action)
    if not flag:
        return 1

    proc = run_cmd([qemu_img, "snapshot", flag, snap_name, str(target)], timeout=60)
    if not proc or proc.returncode != 0:
        err = proc.stderr.strip() if proc else f"Failed to execute snapshot {action}"
        if json_mode:
            print(
                json.dumps(
                    {"error": err, "action": action, "snapshot": snap_name, "success": False},
                    indent=2,
                )
            )
        else:
            print(f"Error executing snapshot {action}: {err}", file=sys.stderr)
        return 1

    result = {
        "success": True,
        "action": action,
        "snapshot": snap_name,
        "image": str(target),
        "output": proc.stdout.strip(),
    }
    if json_mode:
        print(json.dumps(result, indent=2))
    else:
        print(f"Snapshot '{snap_name}' {action} operation succeeded on {target}.")
    return 0


def locate_dbgsrv_dir() -> Path | None:
    # 1. Check $IDADIR/dbgsrv or $IDA_DBGSRV
    for env_var in ("IDA_DBGSRV", "IDADIR", "IDA_DIR"):
        val = os.environ.get(env_var)
        if val:
            p = Path(val)
            if p.name == "dbgsrv" and p.is_dir():
                return p
            if (p / "dbgsrv").is_dir():
                return p / "dbgsrv"

    # 2. Glob general /Applications/IDA*.app/Contents/MacOS/dbgsrv (highest version first)
    matches_mac = sorted(
        glob.glob("/Applications/IDA*.app/Contents/MacOS/dbgsrv"),
        reverse=True,
    )
    if matches_mac:
        return Path(matches_mac[0])

    # 3. Check user ~/Applications
    user_mac = sorted(
        glob.glob(str(Path.home() / "Applications/IDA*.app/Contents/MacOS/dbgsrv")),
        reverse=True,
    )
    if user_mac:
        return Path(user_mac[0])

    # 4. Check Linux standard locations
    for opt_path in sorted(Path("/opt").glob("ida*/dbgsrv"), reverse=True):
        if opt_path.is_dir():
            return opt_path

    return None


def cmd_ida_server_info(json_mode: bool) -> int:
    dbgsrv_dir = locate_dbgsrv_dir()
    servers: list[ServerBinaryEntry] = []

    if dbgsrv_dir and dbgsrv_dir.is_dir():
        for item in sorted(dbgsrv_dir.iterdir()):
            if item.is_file() and not item.name.startswith("."):
                servers.append(
                    {
                        "name": item.name,
                        "path": str(item),
                        "executable": os.access(item, os.X_OK),
                    }
                )

    docker_examples = {
        "command_template": (
            "docker run --rm -it "
            "--ipc=host "
            "--pid=host "
            "--cap-add=SYS_PTRACE "
            "--security-opt seccomp=unconfined "
            "-p 23946:23946 "
            "-v $(pwd):/workspace "
            "<image> /workspace/linux_server -p23946"
        ),
        "flags_explanation": {
            "-p 23946:23946": "Forwards default IDA Pro remote debug server port to host",
            "--ipc=host": "Shares host IPC namespace allowing cross-process synchronization and debug hooks",
            "--pid=host": "Shares host PID namespace allowing debugger to attach to host / sibling container processes",
            "--cap-add=SYS_PTRACE": "Permits ptrace(2) system calls necessary for breakpoints and memory read/write",
            "--security-opt seccomp=unconfined": "Disables seccomp filter restrictions on tracing syscalls",
        },
    }

    utm_examples = {
        "shared_nat_port_forwarding": {
            "description": "Port forwarding rule in UTM VM Network Settings",
            "host_port": 23946,
            "guest_port": 23946,
            "guest_ip": "Leave blank (applies to VM interface)",
            "ida_target": "127.0.0.1:23946",
        },
        "bridged_networking": {
            "description": "VM receives dedicated IP from local network",
            "ip_query_cmd": "utmctl ip-address <vm_uuid_or_name>",
            "ida_target": "<guest_ip>:23946",
        },
        "guest_commands": {
            "linux": "./linux_server -p23946",
            "linux_arm64": "./armlinux_server -p23946",
            "windows_cmd": "win64_remote.exe -p23946",
            "disable_aslr_linux": "echo 0 | sudo tee /proc/sys/kernel/randomize_va_space",
        },
    }

    report = {
        "dbgsrv_found": dbgsrv_dir is not None,
        "dbgsrv_dir": str(dbgsrv_dir) if dbgsrv_dir else None,
        "server_binaries": servers,
        "docker_configuration": docker_examples,
        "utm_configuration": utm_examples,
    }

    if json_mode:
        print(json.dumps(report, indent=2))
    else:
        print("=== IDA Pro Remote Debugger Server Setup ===")
        print(f"dbgsrv directory: {dbgsrv_dir or 'Not found'}")
        if servers:
            print("\nAvailable Debug Servers:")
            for s in servers:
                print(f"  - {s['name']}")
        else:
            print("\nNo server binaries found in dbgsrv directory.")

        print("\n--- Docker Remote IPC Execution ---")
        print(docker_examples["command_template"])
        print("\nRequired Flags:")
        for flag, desc in docker_examples["flags_explanation"].items():
            print(f"  {flag:<30} {desc}")

        print("\n--- UTM VM Remote Debugging Setup ---")
        print("1. Shared Network (NAT) Port Forwarding:")
        print("   - Host Port: 23946 -> Guest Port: 23946")
        print("   - Connect IDA Pro to: 127.0.0.1:23946")
        print("2. Bridged Network:")
        print("   - Query Guest IP: utmctl ip-address <vm>")
        print("   - Connect IDA Pro to: <guest_ip>:23946")
        print("3. Guest Command Examples:")
        print("   - Linux x64:   ./linux_server -p23946")
        print("   - Linux arm64: ./armlinux_server -p23946")
        print("   - Windows x64: win64_remote.exe -p23946")

    return 0
def cmd_start_disposable(vm: str, json_mode: bool) -> int:
    vm_target = applescript_vm_target(vm)
    script = f'''tell application "UTM"
    set target_vm to {vm_target}
    start target_vm without saving
end tell'''
    res = run_osascript(script)
    if res is None:
        err = "Failed to run osascript (timed out or execution error)"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    if res.returncode != 0:
        err = res.stderr.strip() or f"osascript exited with code {res.returncode}"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return res.returncode

    if json_mode:
        print(json.dumps({"success": True, "vm": vm, "mode": "disposable", "message": "VM started in disposable mode without saving"}))
    else:
        print(f"VM '{vm}' successfully started in disposable mode (changes will not be saved).")
    return 0


def cmd_guest_exec(vm: str, command: str, cmd_args: list[str] | None, timeout: int, json_mode: bool) -> int:
    vm_target = applescript_vm_target(vm)
    esc_cmd = escape_applescript_string(command)
    args_items = [f'"{escape_applescript_string(a)}"' for a in (cmd_args or [])]
    applescript_args = "{" + ", ".join(args_items) + "}"

    # Script captures execution result via QEMU Guest Agent through UTM AppleScript.
    # Note: exit code, signal code, output text, and error text can be missing value
    # (e.g. if stdout/stderr is empty or if process was terminated by signal).
    # Coerce to text safely in AppleScript to avoid runtime concatenation errors.
    script = f'''tell application "UTM"
    set target_vm to {vm_target}
    tell (execute of target_vm at "{esc_cmd}" with arguments {applescript_args} with output capturing)
        repeat
            set res to get result
            if exited of res then exit repeat
            delay 0.5
        end repeat
        set rawExit to exit code of res
        set rawSig to signal code of res
        set rawOut to output text of res
        set rawErr to error text of res

        set exitStr to ""
        if rawExit is not missing value then set exitStr to rawExit as text
        set sigStr to ""
        if rawSig is not missing value then set sigStr to rawSig as text
        set outStr to ""
        if rawOut is not missing value then set outStr to rawOut as text
        set errStr to ""
        if rawErr is not missing value then set errStr to rawErr as text

        return exitStr & "<UTM_EXEC_SPLIT>" & sigStr & "<UTM_EXEC_SPLIT>" & errStr & "<UTM_EXEC_SPLIT>" & outStr
    end tell
end tell'''

    res = run_osascript(script, timeout=timeout)
    if res is None:
        err = f"Guest command execution timed out or failed to invoke osascript (timeout={timeout}s)"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    if res.returncode != 0:
        err = res.stderr.strip() or f"osascript exited with code {res.returncode}"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return res.returncode

    # Do not strip full res.stdout to preserve intentional leading/trailing whitespace in command output
    raw_out = res.stdout
    parts = raw_out.split("<UTM_EXEC_SPLIT>", 3)
    if len(parts) == 4:
        exit_code_str, sig_code_str, error_text, output_text = parts
    else:
        exit_code_str, sig_code_str, error_text, output_text = "", "", "", raw_out

    # Strip newline that osascript appends to the final return string
    if output_text.endswith("\n"):
        output_text = output_text[:-1]

    guest_exit_code: int | None = int(exit_code_str) if exit_code_str.strip() else None
    signal_code: int | None = int(sig_code_str) if sig_code_str.strip() else None

    effective_exit = guest_exit_code if guest_exit_code is not None else (128 + signal_code if signal_code is not None else 0)

    if json_mode:
        print(json.dumps({
            "success": True,
            "vm": vm,
            "command": command,
            "args": cmd_args or [],
            "exit_code": guest_exit_code,
            "signal_code": signal_code,
            "output": output_text,
            "error": error_text,
        }))
    else:
        if output_text:
            sys.stdout.write(output_text + ("\n" if not output_text.endswith("\n") else ""))
        if error_text:
            sys.stderr.write(error_text + ("\n" if not error_text.endswith("\n") else ""))
        if signal_code is not None:
            print(f"[Guest process terminated by signal/exception {signal_code}]", file=sys.stderr)
        elif guest_exit_code is not None and guest_exit_code != 0:
            print(f"[Guest process exited with code {guest_exit_code}]", file=sys.stderr)

    return effective_exit

def cmd_guest_push(vm: str, host_file: str, guest_path: str, json_mode: bool) -> int:
    host_p = Path(host_file).resolve()
    if not host_p.exists():
        err = f"Host file not found: {host_file}"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    vm_target = applescript_vm_target(vm)
    esc_host = escape_applescript_string(str(host_p))
    esc_guest = escape_applescript_string(guest_path)

    script = f'''tell application "UTM"
    set target_vm to {vm_target}
    set input_file to POSIX file "{esc_host}"
    push of (open file of target_vm at "{esc_guest}" for writing) from input_file
end tell'''

    res = run_osascript(script)
    if res is None:
        err = "Failed to push file via osascript (timed out or execution error)"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    if res.returncode != 0:
        err = res.stderr.strip() or f"osascript exited with code {res.returncode}"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return res.returncode

    if json_mode:
        print(json.dumps({
            "success": True,
            "vm": vm,
            "host_file": str(host_p),
            "guest_path": guest_path,
            "message": f"Successfully pushed {host_p} to guest path {guest_path}",
        }))
    else:
        print(f"Successfully pushed '{host_p}' to '{vm}:{guest_path}'.")
    return 0


def cmd_guest_pull(vm: str, guest_file: str, host_path: str, json_mode: bool) -> int:
    host_p = Path(host_path).resolve()
    # If host path is directory, append guest file basename
    if host_p.is_dir():
        host_p = host_p / Path(guest_file).name
    # Ensure parent directory exists
    host_p.parent.mkdir(parents=True, exist_ok=True)

    vm_target = applescript_vm_target(vm)
    esc_host = escape_applescript_string(str(host_p))
    esc_guest = escape_applescript_string(guest_file)

    script = f'''tell application "UTM"
    set target_vm to {vm_target}
    set output_file to POSIX file "{esc_host}"
    pull of (open file of target_vm at "{esc_guest}") to output_file
end tell'''

    res = run_osascript(script)
    if res is None:
        err = "Failed to pull file via osascript (timed out or execution error)"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    if res.returncode != 0:
        err = res.stderr.strip() or f"osascript exited with code {res.returncode}"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return res.returncode

    if json_mode:
        print(json.dumps({
            "success": True,
            "vm": vm,
            "guest_file": guest_file,
            "host_path": str(host_p),
            "message": f"Successfully pulled {guest_file} to {host_p}",
        }))
    else:
        print(f"Successfully pulled '{vm}:{guest_file}' to '{host_p}'.")
    return 0


def cmd_send_input(
    vm: str,
    text: str | None,
    click: list[int] | None,
    modifiers: str | None,
    button: str,
    json_mode: bool,
) -> int:
    if not text and not click:
        err = "Must specify either --text or --click X Y (or both)"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    vm_target = applescript_vm_target(vm)
    script_lines = ['tell application "UTM"', f"    set target_vm to {vm_target}"]

    if text:
        esc_text = escape_applescript_string(text)
        if modifiers:
            script_lines.append(f'    input keystroke of target_vm text "{esc_text}" with modifiers {modifiers}')
        else:
            script_lines.append(f'    input keystroke of target_vm text "{esc_text}"')

    if click:
        x, y = click[0], click[1]
        script_lines.append(f"    input mouse click of target_vm at {{{x}, {y}}} with mouse button {button}")

    script_lines.append("end tell")
    script = "\n".join(script_lines)

    res = run_osascript(script)
    if res is None:
        err = "Failed to send input via osascript (timed out or execution error)"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    if res.returncode != 0:
        err = res.stderr.strip() or f"osascript exited with code {res.returncode}"
        if json_mode:
            print(json.dumps({"success": False, "error": err}))
        else:
            print(f"Error: {err}", file=sys.stderr)
        return res.returncode

    action_summary: dict[str, object] = {"vm": vm}
    if text:
        action_summary["keystroke"] = text
        if modifiers:
            action_summary["modifiers"] = modifiers
    if click:
        action_summary["click"] = {"x": click[0], "y": click[1], "button": button}

    if json_mode:
        print(json.dumps({"success": True, **action_summary}))
    else:
        print(f"Input successfully sent to VM '{vm}': {action_summary}")
    return 0



def main(argv: list[str] | None = None) -> int:
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    parser = argparse.ArgumentParser(
        description="UTM hypervisor, QCOW2 snapshot, and IDA Pro remote debugging helper",
        parents=[parent_parser],
    )

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # status
    subparsers.add_parser("status", parents=[parent_parser], help="Check UTM, utmctl, qemu-img status and list VMs")

    # list-vms
    subparsers.add_parser("list-vms", parents=[parent_parser], help="Enumerate all registered UTM virtual machines")

    # snapshot-list <vm>
    p_snap_list = subparsers.add_parser("snapshot-list", parents=[parent_parser], help="List snapshots for a UTM VM")
    p_snap_list.add_argument("vm", help="VM name or UUID")

    # snapshot-create <vm> <name>
    p_snap_create = subparsers.add_parser("snapshot-create", parents=[parent_parser], help="Create a snapshot for a UTM VM")
    p_snap_create.add_argument("vm", help="VM name or UUID")
    p_snap_create.add_argument("name", help="Snapshot name")

    # snapshot-restore <vm> <name>
    p_snap_restore = subparsers.add_parser("snapshot-restore", parents=[parent_parser], help="Restore a UTM VM snapshot")
    p_snap_restore.add_argument("vm", help="VM name or UUID")
    p_snap_restore.add_argument("name", help="Snapshot name")

    # qcow2-create <output_path> <size_gb> [--backing <base_path>]
    p_qcow2_create = subparsers.add_parser("qcow2-create", parents=[parent_parser], help="Create a QCOW2 disk image")
    p_qcow2_create.add_argument("output_path", help="Path for new QCOW2 image")
    p_qcow2_create.add_argument("size_gb", help="Disk size in GB (e.g. 20 or 20G)")
    p_qcow2_create.add_argument("--backing", help="Optional backing file path for differential disk")

    # qcow2-snapshot <qcow2_path> [--create <name> | --restore <name> | --list | --delete <name>]
    p_qcow2_snap = subparsers.add_parser("qcow2-snapshot", parents=[parent_parser], help="Manage internal QCOW2 snapshots")
    p_qcow2_snap.add_argument("qcow2_path", help="Path to QCOW2 image")
    snap_group = p_qcow2_snap.add_mutually_exclusive_group(required=True)
    snap_group.add_argument("--list", action="store_true", help="List internal snapshots")
    snap_group.add_argument("--create", metavar="NAME", help="Create internal snapshot")
    snap_group.add_argument("--restore", metavar="NAME", help="Restore internal snapshot")
    snap_group.add_argument("--delete", metavar="NAME", help="Delete internal snapshot")

    # ida-server-info
    subparsers.add_parser("ida-server-info", parents=[parent_parser], help="Locate IDA dbgsrv and show Docker/UTM configuration templates")
    # start-disposable <vm>
    p_disp = subparsers.add_parser("start-disposable", parents=[parent_parser], help="Start VM in disposable mode without saving changes")
    p_disp.add_argument("vm", help="VM name or UUID")

    # guest-exec <vm> <command> [--args arg1 arg2...]
    p_gexec = subparsers.add_parser("guest-exec", parents=[parent_parser], help="Run a command inside guest VM via QEMU Guest Agent (AppleScript)")
    p_gexec.add_argument("vm", help="VM name or UUID")
    p_gexec.add_argument("command", help="Command or executable path inside guest")
    p_gexec.add_argument("--args", nargs="*", default=[], help="Command arguments")
    p_gexec.add_argument("--timeout", type=int, default=60, help="Execution timeout in seconds (default: 60)")

    # guest-push <vm> <host_file> <guest_path>
    p_gpush = subparsers.add_parser("guest-push", parents=[parent_parser], help="Copy host file to guest via QEMU Guest Agent")
    p_gpush.add_argument("vm", help="VM name or UUID")
    p_gpush.add_argument("host_file", help="Path to file on host")
    p_gpush.add_argument("guest_path", help="Destination path inside guest VM")

    # guest-pull <vm> <guest_file> <host_path>
    p_gpull = subparsers.add_parser("guest-pull", parents=[parent_parser], help="Copy guest file to host via QEMU Guest Agent")
    p_gpull.add_argument("vm", help="VM name or UUID")
    p_gpull.add_argument("guest_file", help="Path to file inside guest VM")
    p_gpull.add_argument("host_path", help="Destination file or directory on host")

    # send-input <vm> [--text TEXT] [--click X Y]
    p_sinput = subparsers.add_parser("send-input", parents=[parent_parser], help="Send keystrokes or mouse clicks to VM display via AppleScript")
    p_sinput.add_argument("vm", help="VM name or UUID")
    p_sinput.add_argument("--text", help="Text string to type as keystrokes")
    p_sinput.add_argument("--modifiers", choices=["shift", "control", "option", "command"], help="Optional modifier key")
    p_sinput.add_argument("--click", nargs=2, type=int, metavar=("X", "Y"), help="Mouse click coordinates (e.g. --click 100 200)")
    p_sinput.add_argument("--button", choices=["left", "right", "middle"], default="left", help="Mouse button (default: left)")

    args = parser.parse_args(argv)


    if args.subcommand == "status":
        return cmd_status(args.json)
    elif args.subcommand == "list-vms":
        return cmd_list_vms(args.json)
    elif args.subcommand == "snapshot-list":
        return cmd_snapshot_list(args.vm, args.json)
    elif args.subcommand == "snapshot-create":
        return cmd_snapshot_create(args.vm, args.name, args.json)
    elif args.subcommand == "snapshot-restore":
        return cmd_snapshot_restore(args.vm, args.name, args.json)
    elif args.subcommand == "qcow2-create":
        return cmd_qcow2_create(args.output_path, args.size_gb, args.backing, args.json)
    elif args.subcommand == "qcow2-snapshot":
        if args.list:
            return cmd_qcow2_snapshot(args.qcow2_path, "list", None, args.json)
        elif args.create:
            return cmd_qcow2_snapshot(args.qcow2_path, "create", args.create, args.json)
        elif args.restore:
            return cmd_qcow2_snapshot(args.qcow2_path, "restore", args.restore, args.json)
        elif args.delete:
            return cmd_qcow2_snapshot(args.qcow2_path, "delete", args.delete, args.json)
    elif args.subcommand == "ida-server-info":
        return cmd_ida_server_info(args.json)
    elif args.subcommand == "start-disposable":
        return cmd_start_disposable(args.vm, args.json)
    elif args.subcommand == "guest-exec":
        return cmd_guest_exec(args.vm, args.command, args.args, args.timeout, args.json)
    elif args.subcommand == "guest-push":
        return cmd_guest_push(args.vm, args.host_file, args.guest_path, args.json)
    elif args.subcommand == "guest-pull":
        return cmd_guest_pull(args.vm, args.guest_file, args.host_path, args.json)
    elif args.subcommand == "send-input":
        return cmd_send_input(args.vm, args.text, args.click, args.modifiers, args.button, args.json)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
