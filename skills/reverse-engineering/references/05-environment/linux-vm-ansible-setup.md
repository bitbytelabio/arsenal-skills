# Linux VM Ansible Automated Provisioning & Tool Setup Guide

Automated provisioning for Linux guest virtual machines (Debian/Ubuntu, Fedora/RHEL, Arch Linux) running under UTM (macOS Apple Silicon / Intel) or KVM/QEMU (Linux host).

## Architecture & Prerequisites

1. **Guest OS**: Linux (Ubuntu 22.04/24.04, Debian 12, Fedora 39/40, or Arch Linux).
2. **Hypervisor**: UTM on macOS (Apple Virtualization / QEMU) or native KVM on Linux.
3. **SSH Access**:
   - Install `openssh-server` on guest: `sudo apt update && sudo apt install -y openssh-server`.
   - Ensure the SSH daemon is running and user has `sudo` privileges.
   - Recommended: Configure SSH key-based authentication (`~/.ssh/authorized_keys`).
4. **Ansible**: Installed on host (`brew install ansible` or `uv tool install ansible`). Run `uv run scripts/setup_vm.py deps --install` once for the collections.
5. **UTM networking**: The Ubuntu cloud image got no DHCP lease on UTM 5 Shared Network. Use Emulated VLAN with a port forward (host `127.0.0.1:2222` -> guest 22) and generate the inventory with `--host 127.0.0.1 --port 2222`. A cloud image has only a serial console, so the UTM window shows "Display output is not active"; use SSH.

---

## Tool Catalog (`ansible/linux_tools.json`)

The structured JSON catalog covers essential reverse engineering and monitoring tools:
- **`telemetry_monitoring`**: `osquery` (`/usr/bin/osqueryi`, system audit and telemetry daemon)
- **`network_analysis`**: `tshark` (Wireshark packet capture CLI), `tcpdump` (kernel packet filter)
- **`debugging_disassembly`**:
  - `gdb` (GNU Project debugger)
  - `radare2` (`r2` command-line hex editor and disassembler)
  - `ghidra` (NSA software reverse engineering suite)
  - `strace` (userspace system call tracer)
  - `ltrace` (dynamic library call tracer)
  - `checksec` (ELF security mitigations and hardening inspection)
  - `upx` (executable packer/unpacker)
  - `ida_dbgsrv` (IDA Pro linux_server / armlinux_server on port 23946)
- **`forensics_triage`**: `binwalk` (firmware extractor), `yara` (pattern matching signatures)
- **`system_utilities`**: `python3`, `uv` (fast Python package manager), `git`, `curl`, `7zip` (`p7zip`)
- **`automation_agent`**: `computer-use-mcp` (desktop automation MCP server on port 4517)

---

## Provisioning Workflow

### 1. Generate Inventory
Generate a ready-to-use inventory file using `setup_vm.py`:

```bash
# Key-based SSH authentication (recommended)
uv run scripts/setup_vm.py generate-inventory \
  --os linux \
  --host 192.168.64.20 \
  --user analyst \
  --key-file ~/.ssh/id_ed25519

# Or password-based authentication
uv run scripts/setup_vm.py generate-inventory \
  --os linux \
  --host 192.168.64.20 \
  --user analyst \
  --password labpassword
```

This writes `ansible/inventory_linux.ini`.

### 2. Verify Connectivity
Test SSH and sudo elevation via Ansible ping:

```bash
ansible linux_vms -i ansible/inventory_linux.ini -m ping
```

### 3. Run Provisioning Playbook
Execute `playbook_linux.yml` via the helper CLI:

```bash
uv run scripts/setup_vm.py run-playbook --os linux -v
```

The playbook performs:
1. **Dynamic Analysis Hardening**: Disables Yama ptrace restrictions (`sysctl kernel.yama.ptrace_scope = 0`) to allow `gdb`, `strace`, and debuggers to attach to target processes.
2. **Directory Staging**: Prepares `/opt/ida_dbgsrv` and `/etc/osquery`.
3. **Firewall Rules**: Opens port `23946/tcp` (IDA remote debugger) and port `4517/tcp` (Computer Use MCP) via UFW (Debian/Ubuntu) or firewalld (Fedora).
4. **Package Installations**: Maps catalog entries to `apt`, `dnf`, or `pacman`, asks the package index which names exist, installs those in one call, and lists the rest. One missing name no longer fails the batch. `nodejs`, `npm`, `openjdk-21-jdk`, and `unzip` are catalog entries so npm tools and Ghidra work.
5. **osquery**: Adds pkg.osquery.io with a dearmored key in `/etc/apt/keyrings` and `signed-by`. Ubuntu 24.04 apt ignores an ASCII key in `trusted.gpg.d`.
6. **Ghidra**: Downloads the latest release zip from GitHub into `/opt/ghidra_<version>_PUBLIC` and links `/opt/ghidra`.
7. **IDA debug servers**: Copies `armlinux_server*` (ARM64) or `linux_server*` (x86_64) into `/opt/ida_dbgsrv`.
8. **Telemetry Daemon**: Stages a baseline `osquery.conf` and enables `osqueryd`, then prints `found` and `missing` catalog tools.

Verified on Ubuntu 24.04 ARM64 under UTM: `failed=0`, all 22 enabled tools found.

---

## IDA Remote Debugging Configuration

1. Copy the appropriate IDA debug server from your host IDA Pro installation (`$IDADIR/dbgsrv`):
   - For Linux ARM64 guests: `armlinux_server` or `armlinux_server64`
   - For Linux x86_64 guests: `linux_server` or `linux_server64`
2. Push to VM:
   ```bash
   scp "$IDADIR/dbgsrv/armlinux_server64" analyst@192.168.64.20:/opt/ida_dbgsrv/
   ssh analyst@192.168.64.20 "chmod +x /opt/ida_dbgsrv/armlinux_server64"
   ```
3. Run on guest VM:
   ```bash
   /opt/ida_dbgsrv/armlinux_server64 -p23946
   ```
4. In IDA Pro on the host:
   - Select **Debugger** -> **Select debugger** -> **Remote Linux debugger**.
   - Set **Hostname** to guest IP (`192.168.64.20`) and **Port** to `23946`.

---

## Computer Use MCP Integration

Generate host MCP client configuration:

```bash
uv run scripts/setup_vm.py mcp-client-config --os linux --host 192.168.64.20
```

Add the resulting JSON to your host agent's MCP configuration (`~/.omp/agent/mcp.json` or project MCP settings) to automate the guest Linux desktop session.
