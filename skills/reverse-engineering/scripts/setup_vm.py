#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""VM Ansible Provisioning & Tool Catalog Manager (Windows, Linux, macOS).

CLI tool to inspect and manipulate guest VM reverse engineering tool catalogs,
generate Ansible inventory configurations (WinRM for Windows, SSH for Linux/macOS),
and trigger Ansible playbook executions.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
ANSIBLE_DIR = SKILL_DIR / "ansible"

# Catalogs
WINDOWS_CATALOG_PATH = ANSIBLE_DIR / "windows_tools.json"
LINUX_CATALOG_PATH = ANSIBLE_DIR / "linux_tools.json"
MACOS_CATALOG_PATH = ANSIBLE_DIR / "macos_tools.json"

# Playbooks
WINDOWS_PLAYBOOK_PATH = ANSIBLE_DIR / "playbook_windows.yml"
LINUX_PLAYBOOK_PATH = ANSIBLE_DIR / "playbook_linux.yml"
MACOS_PLAYBOOK_PATH = ANSIBLE_DIR / "playbook_macos.yml"

# Default inventories
WINDOWS_DEFAULT_INVENTORY = ANSIBLE_DIR / "inventory_windows.ini"
LINUX_DEFAULT_INVENTORY = ANSIBLE_DIR / "inventory_linux.ini"
MACOS_DEFAULT_INVENTORY = ANSIBLE_DIR / "inventory_macos.ini"
LEGACY_WINDOWS_INVENTORY = ANSIBLE_DIR / "inventory.ini"

# Scripts
WINRM_SCRIPT_PATH = ANSIBLE_DIR / "setup_winrm.ps1"
DEFENDER_SCRIPT_PATH = ANSIBLE_DIR / "toggle_defender.ps1"
DEFENDER_PLAYBOOK_PATH = ANSIBLE_DIR / "playbook_defender.yml"

VALID_CATEGORIES: set[str] = {
    "telemetry_monitoring",
    "network_analysis",
    "forensics_triage",
    "debugging_disassembly",
    "pe_analysis",
    "system_utilities",
    "automation_agent",
}

SUPPORTED_OS = ("windows", "linux", "macos")

# Collections the three playbooks import. pywinrm is needed in Ansible's own
# Python for WinRM, which is not the Python on PATH when Ansible came from uv/pipx.
REQUIRED_COLLECTIONS = (
    "ansible.windows",
    "community.windows",
    "chocolatey.chocolatey",
    "community.general",
    "ansible.posix",
)


@dataclass(slots=True)
class ToolEntry:
    id: str
    name: str
    category: str
    description: str
    binary_path: str
    service_name: str | None
    enabled: bool
    tags: list[str]
    extra_fields: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolEntry:
        known_core = {
            "id",
            "name",
            "category",
            "description",
            "binary_path",
            "service_name",
            "enabled",
            "tags",
        }
        extra = {k: v for k, v in data.items() if k not in known_core}
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            category=str(data["category"]),
            description=str(data.get("description", "")),
            binary_path=str(data.get("binary_path", "")),
            service_name=data.get("service_name"),
            enabled=bool(data.get("enabled", True)),
            tags=list(data.get("tags", [])),
            extra_fields=extra,
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
        }
        for k, v in self.extra_fields.items():
            d[k] = v
        d["binary_path"] = self.binary_path
        d["service_name"] = self.service_name
        d["enabled"] = self.enabled
        d["tags"] = self.tags
        return d


def get_paths_for_os(target_os: str) -> tuple[Path, Path, Path]:
    target_os = target_os.lower()
    if target_os == "windows":
        inv = LEGACY_WINDOWS_INVENTORY if LEGACY_WINDOWS_INVENTORY.is_file() else WINDOWS_DEFAULT_INVENTORY
        return WINDOWS_CATALOG_PATH, WINDOWS_PLAYBOOK_PATH, inv
    elif target_os == "linux":
        return LINUX_CATALOG_PATH, LINUX_PLAYBOOK_PATH, LINUX_DEFAULT_INVENTORY
    elif target_os == "macos":
        return MACOS_CATALOG_PATH, MACOS_PLAYBOOK_PATH, MACOS_DEFAULT_INVENTORY
    else:
        raise ValueError(f"Unsupported OS: '{target_os}'. Must be one of {SUPPORTED_OS}")


def load_catalog(catalog_path: Path) -> tuple[dict[str, Any], list[ToolEntry]]:
    if not catalog_path.is_file():
        raise FileNotFoundError(f"Catalog file not found: {catalog_path}")
    raw = json.loads(catalog_path.read_text(encoding="utf-8"))
    raw_tools = raw.get("tools", [])
    tools = [ToolEntry.from_dict(t) for t in raw_tools]
    return raw, tools


def save_catalog(raw: dict[str, Any], tools: list[ToolEntry], catalog_path: Path) -> None:
    raw["tools"] = [t.to_dict() for t in tools]
    content = json.dumps(raw, indent=2) + "\n"
    catalog_path.write_text(content, encoding="utf-8")


def cmd_list(args: argparse.Namespace) -> int:
    target_os = getattr(args, "os", "windows")
    try:
        catalog_path, _, _ = get_paths_for_os(target_os)
        _, tools = load_catalog(catalog_path)
    except Exception as exc:
        print(f"Error loading catalog: {exc}", file=sys.stderr)
        return 1

    filtered = tools
    if args.category:
        filtered = [t for t in filtered if t.category == args.category]
    if args.tag:
        filtered = [t for t in filtered if args.tag.lower() in [tag.lower() for tag in t.tags]]
    if args.enabled_only:
        filtered = [t for t in filtered if t.enabled]

    if args.json:
        print(json.dumps([t.to_dict() for t in filtered], indent=2))
        return 0

    os_title = target_os.capitalize()
    print(f"{os_title} Tools Catalog ({len(filtered)} items):")
    print("-" * 88)
    print(f"{'STATUS':<8} {'ID':<18} {'CATEGORY':<24} {'NAME'}")
    print("-" * 88)
    for tool in filtered:
        status = "[ON] " if tool.enabled else "[OFF]"
        print(f"{status:<8} {tool.id:<18} {tool.category:<24} {tool.name}")
    print("-" * 88)
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    target_os = getattr(args, "os", "windows")
    try:
        catalog_path, _, _ = get_paths_for_os(target_os)
        _, tools = load_catalog(catalog_path)
    except Exception as exc:
        print(f"Error loading catalog: {exc}", file=sys.stderr)
        return 1

    total = len(tools)
    enabled_count = sum(1 for t in tools if t.enabled)
    disabled_count = total - enabled_count

    categories: dict[str, dict[str, int]] = {}
    for t in tools:
        if t.category not in categories:
            categories[t.category] = {"total": 0, "enabled": 0, "disabled": 0}
        categories[t.category]["total"] += 1
        if t.enabled:
            categories[t.category]["enabled"] += 1
        else:
            categories[t.category]["disabled"] += 1

    summary_data = {
        "os": target_os,
        "total_tools": total,
        "enabled_tools": enabled_count,
        "disabled_tools": disabled_count,
        "categories": categories,
    }

    if args.json:
        print(json.dumps(summary_data, indent=2))
        return 0

    os_title = target_os.capitalize()
    print(f"{os_title} Tools Catalog Summary:")
    print(f"  Target OS:      {target_os}")
    print(f"  Total tools:    {total}")
    print(f"  Enabled tools:  {enabled_count}")
    print(f"  Disabled tools: {disabled_count}")
    print("\nBreakdown by Category:")
    print(f"{'CATEGORY':<26} {'TOTAL':<8} {'ENABLED':<8} {'DISABLED'}")
    print("-" * 52)
    for cat, stats in sorted(categories.items()):
        print(f"{cat:<26} {stats['total']:<8} {stats['enabled']:<8} {stats['disabled']}")
    return 0


def cmd_toggle(args: argparse.Namespace, enable: bool) -> int:
    target_os = getattr(args, "os", "windows")
    try:
        catalog_path, _, _ = get_paths_for_os(target_os)
        raw, tools = load_catalog(catalog_path)
    except Exception as exc:
        print(f"Error loading catalog: {exc}", file=sys.stderr)
        return 1

    target_id = args.tool_id.strip()
    found = False
    for t in tools:
        if t.id == target_id:
            t.enabled = enable
            found = True
            break

    if not found:
        print(f"Tool with id '{target_id}' not found in {target_os} catalog.", file=sys.stderr)
        return 1

    save_catalog(raw, tools, catalog_path)
    action = "enabled" if enable else "disabled"
    print(f"Tool '{target_id}' successfully {action} in {target_os} catalog.")
    return 0


def cmd_add_tool(args: argparse.Namespace) -> int:
    target_os = getattr(args, "os", "windows")
    try:
        catalog_path, _, _ = get_paths_for_os(target_os)
        raw, tools = load_catalog(catalog_path)
    except Exception as exc:
        print(f"Error loading catalog: {exc}", file=sys.stderr)
        return 1

    tool_id = args.id.strip().lower()
    if any(t.id == tool_id for t in tools):
        print(f"Error: Tool with id '{tool_id}' already exists in {target_os} catalog.", file=sys.stderr)
        return 1

    category = args.category.strip()
    if category not in VALID_CATEGORIES:
        valid_list = ", ".join(sorted(VALID_CATEGORIES))
        print(f"Error: Invalid category '{category}'. Must be one of: {valid_list}", file=sys.stderr)
        return 1

    tags = [tag.strip() for tag in args.tags.split(",") if tag.strip()] if args.tags else []

    extra_fields: dict[str, Any] = {}
    if target_os == "windows":
        extra_fields["choco_package"] = args.choco.strip() if getattr(args, "choco", None) else None
        extra_fields["winget_id"] = args.winget.strip() if getattr(args, "winget", None) else None
        extra_fields["npm_package"] = args.npm.strip() if getattr(args, "npm", None) else None
    elif target_os == "linux":
        extra_fields["apt_package"] = args.apt.strip() if getattr(args, "apt", None) else None
        extra_fields["dnf_package"] = args.dnf.strip() if getattr(args, "dnf", None) else None
        extra_fields["pacman_package"] = args.pacman.strip() if getattr(args, "pacman", None) else None
    elif target_os == "macos":
        extra_fields["brew_formula"] = args.brew_formula.strip() if getattr(args, "brew_formula", None) else None
        extra_fields["brew_cask"] = args.brew_cask.strip() if getattr(args, "brew_cask", None) else None

    new_tool = ToolEntry(
        id=tool_id,
        name=args.name.strip(),
        category=category,
        description=args.description.strip(),
        binary_path=args.binary_path.strip(),
        service_name=args.service.strip() if args.service else None,
        enabled=not args.disabled,
        tags=tags,
        extra_fields=extra_fields,
    )
    tools.append(new_tool)
    save_catalog(raw, tools, catalog_path)
    print(f"Tool '{tool_id}' successfully added to {target_os} catalog.")
    return 0


def cmd_winrm_script(args: argparse.Namespace) -> int:
    if not WINRM_SCRIPT_PATH.is_file():
        print(f"Error: WinRM script not found at {WINRM_SCRIPT_PATH}", file=sys.stderr)
        return 1

    script_content = WINRM_SCRIPT_PATH.read_text(encoding="utf-8")
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.write_text(script_content, encoding="utf-8")
        print(f"WinRM setup script written to {out_path}")
    else:
        print(script_content)
    return 0


def cmd_generate_inventory(args: argparse.Namespace) -> int:
    target_os = getattr(args, "os", "windows")
    host = args.host.strip()
    user = args.user.strip()
    password = getattr(args, "password", None)
    key_file = getattr(args, "key_file", None)
    become_password = getattr(args, "become_password", None)
    port = args.port
    become_line = f"ansible_become_password={become_password}\n" if become_password else ""

    _, _, default_inv_path = get_paths_for_os(target_os)
    out_path = Path(args.output).resolve() if args.output else default_inv_path

    if target_os == "windows":
        if not password:
            print("Error: Windows WinRM inventory requires --password", file=sys.stderr)
            return 1
        if become_password:
            print("Note: --become-password is ignored for Windows; WinRM runs as the admin user.", file=sys.stderr)
        port = port or 5985
        transport = getattr(args, "transport", "ntlm") or "ntlm"
        scheme = "https" if port == 5986 or transport == "credssp" else "http"
        inventory_text = f"""# Generated Ansible WinRM Inventory for Windows RE VM
[windows_vms]
win-re-vm ansible_host={host} ansible_port={port} ansible_user={user} ansible_password={password}

[windows_vms:vars]
ansible_connection=winrm
ansible_winrm_transport={transport}
ansible_winrm_scheme={scheme}
ansible_winrm_server_cert_validation=ignore
ansible_winrm_operation_timeout_sec=120
ansible_winrm_read_timeout_sec=180
"""
    elif target_os == "linux":
        port = port or 22
        auth_parts: list[str] = []
        if key_file:
            auth_parts.append(f"ansible_ssh_private_key_file={key_file}")
        elif password:
            auth_parts.append(f"ansible_ssh_pass={password}")
        auth_line = " " + " ".join(auth_parts) if auth_parts else ""
        inventory_text = f"""# Generated Ansible SSH Inventory for Linux RE VM
[linux_vms]
linux-re-vm ansible_host={host} ansible_port={port} ansible_user={user}{auth_line}

[linux_vms:vars]
ansible_connection=ssh
ansible_port={port}
ansible_become=true
ansible_become_method=sudo
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
ansible_python_interpreter=auto_silent
{become_line}"""
    elif target_os == "macos":
        port = port or 22
        if not become_password:
            print(
                "Warning: macOS tasks use sudo (CLT, Homebrew, PF, osquery). "
                "Pass --become-password unless the user has NOPASSWD sudo.",
                file=sys.stderr,
            )
        auth_parts = []
        if key_file:
            auth_parts.append(f"ansible_ssh_private_key_file={key_file}")
        elif password:
            auth_parts.append(f"ansible_ssh_pass={password}")
        auth_line = " " + " ".join(auth_parts) if auth_parts else ""
        inventory_text = f"""# Generated Ansible SSH Inventory for macOS RE VM
[macos_vms]
macos-re-vm ansible_host={host} ansible_port={port} ansible_user={user}{auth_line}

[macos_vms:vars]
ansible_connection=ssh
ansible_port={port}
ansible_become=false
ansible_become_method=sudo
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
# /usr/bin/python3 is a Command Line Tools stub on a fresh macOS guest.
# playbook_macos.yml installs CLT with raw tasks before it gathers facts.
ansible_python_interpreter=/usr/bin/python3
{become_line}"""
    else:
        print(f"Error: Unsupported OS '{target_os}'", file=sys.stderr)
        return 1

    out_path.write_text(inventory_text, encoding="utf-8")
    print(f"Inventory for {target_os} generated successfully at {out_path}")
    return 0


def locate_ida_dbgsrv() -> Path | None:
    for env_var in ("IDA_DBGSRV", "IDADIR", "IDA_DIR"):
        val = os.environ.get(env_var)
        if not val:
            continue
        path = Path(val)
        if path.name == "dbgsrv" and path.is_dir():
            return path
        if (path / "dbgsrv").is_dir():
            return path / "dbgsrv"
    matches = sorted(glob.glob("/Applications/IDA*.app/Contents/MacOS/dbgsrv"), reverse=True)
    matches += sorted(glob.glob(str(Path.home() / "Applications/IDA*.app/Contents/MacOS/dbgsrv")), reverse=True)
    if matches:
        return Path(matches[0])
    opt = sorted(Path("/opt").glob("ida*/dbgsrv"), reverse=True)
    return opt[0] if opt else None


def ansible_env() -> dict[str, str]:
    env = os.environ.copy()
    # macOS kills Ansible's forked WinRM workers unless this is set.
    if sys.platform == "darwin":
        env["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
    return env


def ansible_python() -> str | None:
    """Return the interpreter Ansible itself runs on (from the shebang)."""
    ansible_bin = shutil.which("ansible-playbook")
    if not ansible_bin:
        return None
    try:
        first = Path(ansible_bin).resolve().read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return None
    if not first.startswith("#!"):
        return None
    parts = first[2:].strip().split()
    if parts and parts[0].endswith("/env") and len(parts) > 1:
        return shutil.which(parts[1])
    return parts[0] if parts else None


def cmd_deps(args: argparse.Namespace) -> int:
    """Check, and with --install fix, the controller-side Ansible requirements."""
    report: dict[str, Any] = {"ansible_playbook": shutil.which("ansible-playbook")}
    galaxy = shutil.which("ansible-galaxy")
    if not report["ansible_playbook"] or not galaxy:
        report["error"] = "ansible not found; install it with 'uv tool install --with-executables-from ansible-core ansible' or 'brew install ansible'"
        print(json.dumps(report, indent=2))
        return 1

    listing = subprocess.run([galaxy, "collection", "list", "--format", "json"], capture_output=True, text=True, env=ansible_env())
    installed: set[str] = set()
    try:
        for coll_map in json.loads(listing.stdout or "{}").values():
            installed.update(coll_map.keys())
    except json.JSONDecodeError:
        pass
    missing = [c for c in REQUIRED_COLLECTIONS if c not in installed]
    report["missing_collections"] = missing

    py = ansible_python()
    report["ansible_python"] = py
    winrm_ok = bool(py) and subprocess.run([py, "-c", "import winrm"], capture_output=True).returncode == 0
    report["pywinrm"] = winrm_ok

    if args.install:
        if missing:
            subprocess.run([galaxy, "collection", "install", *missing], check=False, env=ansible_env())
        if not winrm_ok and py:
            uv = shutil.which("uv")
            pip_cmd = [uv, "pip", "install", "--python", py, "pywinrm"] if uv else [py, "-m", "pip", "install", "pywinrm"]
            subprocess.run(pip_cmd, check=False)
        args.install = False
        return cmd_deps(args)

    ida = locate_ida_dbgsrv()
    report["ida_dbgsrv"] = str(ida) if ida else None
    print(json.dumps(report, indent=2))
    return 0 if not missing and winrm_ok else 1


def cmd_run_playbook(args: argparse.Namespace) -> int:
    target_os = getattr(args, "os", "windows")
    ansible_bin = shutil.which("ansible-playbook")
    if not ansible_bin:
        print("Error: 'ansible-playbook' executable not found in PATH.", file=sys.stderr)
        print("Install ansible with your host package manager (e.g. brew install ansible or uv pip install ansible).", file=sys.stderr)
        return 1

    _, default_playbook, default_inv = get_paths_for_os(target_os)

    inv_path = Path(args.inventory).resolve() if args.inventory else default_inv
    if not inv_path.is_file():
        # Fallback to legacy inventory.ini if target_os is windows
        if target_os == "windows" and LEGACY_WINDOWS_INVENTORY.is_file():
            inv_path = LEGACY_WINDOWS_INVENTORY
        else:
            print(f"Error: Inventory file '{inv_path}' not found.", file=sys.stderr)
            print(f"Run '{Path(__file__).name} generate-inventory --os {target_os} --host <IP> --user <User> ...' first.", file=sys.stderr)
            return 1

    if not default_playbook.is_file():
        print(f"Error: Playbook '{default_playbook}' not found.", file=sys.stderr)
        return 1

    cmd: list[str] = [ansible_bin, "-i", str(inv_path), str(default_playbook)]

    if args.check:
        cmd.append("--check")
    if args.tags:
        cmd.extend(["--tags", args.tags])
    if args.extra_vars:
        cmd.extend(["--extra-vars", args.extra_vars])
    if "ida_dbgsrv_src" not in (args.extra_vars or ""):
        dbgsrv = locate_ida_dbgsrv()
        if dbgsrv:
            print(f"IDA debug servers: {dbgsrv}")
            cmd.extend(["--extra-vars", json.dumps({"ida_dbgsrv_src": str(dbgsrv)})])
        else:
            print(
                "Warning: IDA dbgsrv directory not found; the guest gets no IDA debug server. "
                "Set IDA_DBGSRV=/path/to/dbgsrv or pass --extra-vars ida_dbgsrv_src=...",
                file=sys.stderr,
            )
    if args.verbose:
        cmd.append("-" + "v" * min(args.verbose, 4))

    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=ansible_env())
    return result.returncode


def cmd_defender(args: argparse.Namespace) -> int:
    action = args.action.strip().lower()
    if action not in {"status", "disable", "enable"}:
        print(f"Error: Invalid action '{action}'. Choices: status, disable, enable", file=sys.stderr)
        return 1

    exclusions = [p.strip() for p in args.exclusions.split(",") if p.strip()]

    if args.script_only:
        if not DEFENDER_SCRIPT_PATH.is_file():
            print(f"Error: Defender script not found at {DEFENDER_SCRIPT_PATH}", file=sys.stderr)
            return 1
        script_content = DEFENDER_SCRIPT_PATH.read_text(encoding="utf-8")
        if args.output:
            out_path = Path(args.output).resolve()
            out_path.write_text(script_content, encoding="utf-8")
            print(f"PowerShell toggle script written to {out_path}")
        else:
            print(script_content)
        return 0

    ansible_bin = shutil.which("ansible-playbook")
    if not ansible_bin:
        print("Error: 'ansible-playbook' executable not found in PATH.", file=sys.stderr)
        return 1

    inv_path = Path(args.inventory).resolve() if args.inventory else LEGACY_WINDOWS_INVENTORY
    if not inv_path.is_file() and WINDOWS_DEFAULT_INVENTORY.is_file():
        inv_path = WINDOWS_DEFAULT_INVENTORY
    if not inv_path.is_file():
        print(f"Error: Inventory file '{inv_path}' not found.", file=sys.stderr)
        return 1

    if not DEFENDER_PLAYBOOK_PATH.is_file():
        print(f"Error: Playbook '{DEFENDER_PLAYBOOK_PATH}' not found.", file=sys.stderr)
        return 1

    extra_vars = {
        "defender_action": action,
        "clear_exclusions": args.clear_exclusions,
        "custom_exclusions": exclusions,
    }

    cmd: list[str] = [
        ansible_bin,
        "-i",
        str(inv_path),
        str(DEFENDER_PLAYBOOK_PATH),
        "-e",
        json.dumps(extra_vars),
    ]
    if args.verbose:
        cmd.append("-" + "v" * min(args.verbose, 4))
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=ansible_env())
    return result.returncode


def cmd_mcp_client_config(args: argparse.Namespace) -> int:
    target_os = getattr(args, "os", "windows")
    host = args.host.strip()
    port = args.port
    fmt = args.format.strip().lower()

    server_key = f"{target_os}-vm-computer-use"

    if fmt == "sse":
        config = {
            "mcpServers": {
                server_key: {
                    "url": f"http://{host}:{port}/mcp"
                }
            }
        }
    elif fmt == "proxy":
        config = {
            "mcpServers": {
                server_key: {
                    "command": "npx",
                    "args": ["-y", "mcp-proxy", f"http://{host}:{port}/mcp"]
                }
            }
        }
    elif fmt == "ssh":
        config = {
            "mcpServers": {
                server_key: {
                    "url": f"http://127.0.0.1:{port}/mcp"
                }
            }
        }
    else:
        print(f"Error: Unknown format '{fmt}'", file=sys.stderr)
        return 1

    output_json = json.dumps(config, indent=2)
    print(output_json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="setup_vm.py",
        description="VM Ansible Provisioning & Tool Catalog Manager for Reverse Engineering Labs (Windows, Linux, macOS).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = subparsers.add_parser("list", help="List tools in catalog")
    p_list.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_list.add_argument("--category", choices=sorted(VALID_CATEGORIES), help="Filter by category")
    p_list.add_argument("--tag", help="Filter by tag")
    p_list.add_argument("--enabled-only", action="store_true", help="Show only enabled tools")
    p_list.add_argument("--json", action="store_true", help="Output as JSON")

    # summary
    p_summary = subparsers.add_parser("summary", help="Show tool counts and category breakdown")
    p_summary.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_summary.add_argument("--json", action="store_true", help="Output as JSON")

    # enable-tool
    p_enable = subparsers.add_parser("enable-tool", help="Enable a tool in the catalog")
    p_enable.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_enable.add_argument("tool_id", help="Tool ID to enable")

    # disable-tool
    p_disable = subparsers.add_parser("disable-tool", help="Disable a tool in the catalog")
    p_disable.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_disable.add_argument("tool_id", help="Tool ID to disable")

    # add-tool
    p_add = subparsers.add_parser("add-tool", help="Add a new tool entry to the catalog")
    p_add.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_add.add_argument("--id", required=True, help="Unique tool ID")
    p_add.add_argument("--name", required=True, help="Display name")
    p_add.add_argument("--category", required=True, choices=sorted(VALID_CATEGORIES), help="Tool category")
    p_add.add_argument("--description", default="", help="Tool description")
    p_add.add_argument("--binary-path", required=True, help="Expected path to installed binary")
    p_add.add_argument("--service", default=None, help="System Service name (if applicable)")
    p_add.add_argument("--tags", default="", help="Comma-separated tags")
    p_add.add_argument("--disabled", action="store_true", help="Add in disabled state")
    # Windows package flags
    p_add.add_argument("--choco", default=None, help="Chocolatey package name (Windows)")
    p_add.add_argument("--winget", default=None, help="Winget package ID (Windows)")
    p_add.add_argument("--npm", default=None, help="NPM package name (Windows)")
    # Linux package flags
    p_add.add_argument("--apt", default=None, help="APT package name (Debian/Ubuntu Linux)")
    p_add.add_argument("--dnf", default=None, help="DNF package name (Fedora Linux)")
    p_add.add_argument("--pacman", default=None, help="Pacman package name (Arch Linux)")
    # macOS package flags
    p_add.add_argument("--brew-formula", default=None, help="Homebrew formula name (macOS)")
    p_add.add_argument("--brew-cask", default=None, help="Homebrew cask name (macOS)")

    # winrm-script
    p_winrm = subparsers.add_parser("winrm-script", help="Print or export PowerShell WinRM setup script (Windows only)")
    p_winrm.add_argument("-o", "--output", help="Write script to output file path")

    # generate-inventory
    p_inv = subparsers.add_parser("generate-inventory", help="Generate Ansible inventory file")
    p_inv.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_inv.add_argument("--host", required=True, help="VM Hostname or IP address")
    p_inv.add_argument("--user", required=True, help="Admin/SSH username")
    p_inv.add_argument("--password", default=None, help="Admin password (required for Windows WinRM, optional for Linux/macOS SSH)")
    p_inv.add_argument("--key-file", default=None, help="SSH private key path (for Linux/macOS SSH)")
    p_inv.add_argument("--become-password", default=None, help="sudo password for Linux/macOS become tasks (omit with NOPASSWD sudo)")
    p_inv.add_argument("--port", type=int, default=None, help="Connection port (defaults: 5985 for WinRM, 22 for SSH)")
    p_inv.add_argument("--transport", default="ntlm", choices=["ntlm", "basic", "credssp"], help="WinRM transport auth (Windows only)")
    p_inv.add_argument("-o", "--output", help="Output file path (default: ansible/inventory_<os>.ini or ansible/inventory.ini)")

    # deps
    p_deps = subparsers.add_parser("deps", help="Check Ansible collections, pywinrm, and the IDA dbgsrv path on the controller")
    p_deps.add_argument("--install", action="store_true", help="Install missing collections and pywinrm into Ansible's Python")

    # run-playbook
    p_play = subparsers.add_parser("run-playbook", help="Run Ansible provisioning playbook")
    p_play.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_play.add_argument("-i", "--inventory", help="Path to inventory file")
    p_play.add_argument("--check", action="store_true", help="Run Ansible in dry-run/check mode")
    p_play.add_argument("--tags", help="Only run plays/tasks tagged with these values")
    p_play.add_argument("--extra-vars", help="Extra variables string for Ansible")
    p_play.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-v, -vv, -vvv)")

    # defender
    p_def = subparsers.add_parser("defender", help="Manage Windows Defender state (Windows only)")
    p_def.add_argument("--action", default="status", choices=["status", "disable", "enable"], help="Action to perform (default: status)")
    p_def.add_argument("--clear-exclusions", action="store_true", default=False, help="Clear specified exclusion paths when enabling/managing Defender")
    p_def.add_argument("--exclusions", default="C:\\Tools,C:\\Workspace", help="Comma-separated exclusion paths (default: C:\\Tools,C:\\Workspace)")
    p_def.add_argument("--script-only", action="store_true", help="Print or export PowerShell toggle script instead of running Ansible")
    p_def.add_argument("-o", "--output", help="Output file path when using --script-only")
    p_def.add_argument("-i", "--inventory", help="Path to Ansible inventory file for remote execution")
    p_def.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-v, -vv, -vvv)")

    # mcp-client-config
    p_mcp = subparsers.add_parser("mcp-client-config", help="Generate Host/Agent MCP client configuration snippet for VM remote server")
    p_mcp.add_argument("--os", choices=SUPPORTED_OS, default="windows", help="Target guest OS (default: windows)")
    p_mcp.add_argument("--host", required=True, help="VM IP address or hostname (e.g. 192.168.64.12)")
    p_mcp.add_argument("--port", type=int, default=4517, help="Computer Use MCP Server port (default: 4517)")
    p_mcp.add_argument("--format", choices=["sse", "proxy", "ssh"], default="sse", help="Client connection format: sse (default), proxy (stdio via mcp-proxy), ssh (loopback with SSH tunnel)")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "list":
        return cmd_list(args)
    elif args.command == "summary":
        return cmd_summary(args)
    elif args.command == "enable-tool":
        return cmd_toggle(args, enable=True)
    elif args.command == "disable-tool":
        return cmd_toggle(args, enable=False)
    elif args.command == "add-tool":
        return cmd_add_tool(args)
    elif args.command == "winrm-script":
        return cmd_winrm_script(args)
    elif args.command == "generate-inventory":
        return cmd_generate_inventory(args)
    elif args.command == "deps":
        return cmd_deps(args)
    elif args.command == "run-playbook":
        return cmd_run_playbook(args)
    elif args.command == "defender":
        return cmd_defender(args)
    elif args.command == "mcp-client-config":
        return cmd_mcp_client_config(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
