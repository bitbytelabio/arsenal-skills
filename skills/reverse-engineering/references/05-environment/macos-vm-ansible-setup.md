# macOS VM Ansible Automated Provisioning & Tool Setup Guide

Automated provisioning for macOS guest virtual machines running on Apple Silicon hosts under UTM (Apple Virtualization framework with IPSW restore).

## Architecture & Constraints

1. **Apple Silicon Virtualization Constraint**:
   - macOS guest VMs on Apple Silicon (`arm64`) can **ONLY** be created on a macOS host. Apple Virtualization framework (`VZVirtualMachine`) paired with UTM handles initial IPSW installation.
2. **Initial Setup (Guest VM)**:
   - Complete initial macOS setup assistant in UTM.
   - Enable SSH (**Remote Login**):
     - Go to **System Settings** -> **General** -> **Sharing**.
     - Toggle on **Remote Login** and allow access for your user account (or run `sudo systemsetup -setremotelogin on` in Terminal).
   - Verify guest IP address (e.g., via `utmctl ip-address <vm-name>` or Terminal `ifconfig en0`).
3. **Provisioning Model**:
   - Homebrew manages CLI formulae and GUI casks unprivileged as the standard user.
   - System tasks (Packet Filter firewall, `/opt/ida_dbgsrv`) use `sudo` elevation.

---

## Tool Catalog (`ansible/macos_tools.json`)

The structured JSON catalog covers essential reverse engineering and monitoring tools for macOS:
- **`telemetry_monitoring`**: `osquery` (installed via cask `osquery`)
- **`network_analysis`**: `tshark` / `wireshark` (formula `wireshark`)
- **`debugging_disassembly`**:
  - `radare2` (formula `radare2`)
  - `ghidra` (cask `ghidra`)
  - `jtool2` (formula `jtool2`, Mach-O / dyld shared cache symbol inspection)
  - `ida_dbgsrv` (IDA Pro mac_server / mac_server_arm on port 23946)
- **`forensics_triage`**:
  - `binwalk` (formula `binwalk`)
  - `yara` (formula `yara`)
  - `ipsw` (formula `blacktop/tap/ipsw`, Apple firmware & kernelcache parser)
- **`system_utilities`**: `python@3.12`, `uv`, `git`, `p7zip`, `curl`
- **`automation_agent`**: `computer-use-mcp` (desktop automation MCP server on port 4517)

---

## Provisioning Workflow

### 1. Generate Inventory
Generate a ready-to-use inventory file using `setup_vm.py`:

```bash
# Key-based SSH authentication (recommended)
uv run scripts/setup_vm.py generate-inventory \
  --os macos \
  --host 192.168.64.30 \
  --user analyst \
  --key-file ~/.ssh/id_ed25519

# Or password-based authentication
uv run scripts/setup_vm.py generate-inventory \
  --os macos \
  --host 192.168.64.30 \
  --user analyst \
  --password labpassword
```

This writes `ansible/inventory_macos.ini`.

### 2. Verify Connectivity
Test SSH via Ansible ping:

```bash
ansible macos_vms -i ansible/inventory_macos.ini -m ping
```

### 3. Run Provisioning Playbook
Execute `playbook_macos.yml` via the helper CLI:

```bash
uv run scripts/setup_vm.py run-playbook --os macos -v
```

The playbook performs:
1. **Directory Staging**: Prepares `/opt/ida_dbgsrv` owned by the user.
2. **Packet Filter Firewall**: Deploys `/etc/pf.anchors/com.re.tools` and loads PF rules to allow port `23946` (IDA debug server) and `4517` (Computer Use MCP).
3. **Homebrew Bootstrap**: Verifies or bootstraps Homebrew non-interactively if absent, configuring shell environment in `~/.zprofile`.
4. **Formula & Cask Installations**: Installs reverse engineering formulae (`radare2`, `wireshark`, `ipsw`, `jtool2`, `yara`, `uv`, etc.) and casks (`ghidra`, `osquery`).
5. **Telemetry Daemon**: Stages a baseline `osquery.conf` in `/var/osquery/`.

---

## IDA Remote Debugging Configuration

1. Locate `mac_server` or `mac_server_arm` in your host IDA Pro installation (`$IDADIR/dbgsrv` or `/Applications/IDA*.app/Contents/MacOS/dbgsrv/`):
   - For Apple Silicon macOS guests: `mac_server_arm`
   - For Intel macOS guests: `mac_server`
2. Push to VM:
   ```bash
   scp "$IDADIR/dbgsrv/mac_server_arm" analyst@192.168.64.30:/opt/ida_dbgsrv/
   ssh analyst@192.168.64.30 "chmod +x /opt/ida_dbgsrv/mac_server_arm"
   ```
3. Run on guest VM:
   ```bash
   /opt/ida_dbgsrv/mac_server_arm -p23946
   ```
4. In IDA Pro on the host:
   - Select **Debugger** -> **Select debugger** -> **Remote Mac OS X debugger**.
   - Set **Hostname** to guest IP (`192.168.64.30`) and **Port** to `23946`.

---

## Computer Use MCP Integration

Generate host MCP client configuration:

```bash
uv run scripts/setup_vm.py mcp-client-config --os macos --host 192.168.64.30
```

Add the resulting JSON to your host agent's MCP configuration (`~/.omp/agent/mcp.json` or project MCP settings) to automate the guest macOS desktop session.
