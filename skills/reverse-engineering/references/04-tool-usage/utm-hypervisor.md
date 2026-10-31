# UTM Hypervisor & Snapshot Sandboxing Reference

## 1. Title & Overview
- **Domain**: Virtual machine sandboxing, QCOW2 disk snapshot lifecycle, and automation on Apple Silicon macOS (`arm64`) using `utmctl`, `qemu-img`, and `setup_utm.py`.
- **Scope**: Headless VM administration, internal vs copy-on-write (COW) overlay disk architectures, automated sample detonation and snapshot rollback, guest agent command execution and input simulation, and isolated networking for malware triage and remote debugging.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when:
- Executing suspicious or untrusted binaries (Windows PE, Linux ELF) requiring an isolated, disposable sandbox environment.
- Running live dynamic instrumentation or kernel tracing in a Windows 11 ARM64 or Ubuntu Linux ARM64 guest on Apple Silicon.
- Establishing repeatable baseline states for reverse engineering using instant VM snapshots or differential disk trees.
- Establishing secure, isolated network topologies (port-forwarding only, Host-Only, or air-gapped) for malware analysis so samples cannot reach their live servers.

---

## 3. Tooling & CLI Architecture

### Hypervisor Engine & CLI Tools
On Apple Silicon macOS, UTM provides hardware-accelerated hypervisor virtualization through Apple's `Virtualization.framework` alongside QEMU emulation for foreign architectures:
- **`utmctl` CLI**: Bundled inside `/Applications/UTM.app/Contents/MacOS/utmctl` (or symlinked to `/opt/homebrew/bin/utmctl`).
- **`qemu-img`**: Low-level disk image manipulation utility for QCOW2 structures.
- **`setup_utm.py`**: Python helper script (`scripts/setup_utm.py`) providing high-level commands, JSON output formatting, and AppleScript GUI input injection.

---

## 4. Headless VM Administration with `utmctl`

The `utmctl` utility allows full VM lifecycle management without opening the graphical interface:

### Enumeration & Status
```bash
# List all registered virtual machines (returns UUID, Status, Name)
utmctl list

# Query execution status of a specific VM
utmctl status "Win11-ARM64-RE"
utmctl status <VM_UUID>

# Query guest IP address assigned via DHCP (requires QEMU Guest Agent)
utmctl ip-address "Win11-ARM64-RE"
```

### VM Lifecycle Commands
```bash
# Start or resume virtual machine
utmctl start "Win11-ARM64-RE"

# Suspend virtual machine state to RAM/disk
utmctl suspend "Win11-ARM64-RE"

# Stop virtual machine (graceful shutdown signal or force stop)
utmctl stop "Win11-ARM64-RE"

# Discard saved suspended state (restores clean cold boot)
utmctl discard-state "Win11-ARM64-RE"
```

### VM Snapshots via `utmctl`
Native UTM snapshots capture the complete VM state (memory state if suspended, plus disk volume changes):
```bash
# List existing snapshots for a virtual machine
utmctl snapshot list "Win11-ARM64-RE"

# Create a named snapshot before detonating a target
utmctl snapshot create "Win11-ARM64-RE" --name "clean_baseline"

# Rollback virtual machine to clean baseline
utmctl snapshot restore "Win11-ARM64-RE" --snapshot "clean_baseline"

# Remove snapshot when obsolete
utmctl snapshot delete "Win11-ARM64-RE" --snapshot "clean_baseline"
```

---

## 5. QCOW2 Disk Snapshot Mechanics

UTM VMs utilize QCOW2 (QEMU Copy-On-Write version 2/3) format for disk backing. There are two primary snapshot architectures:

```
Internal Snapshots (Single QCOW2)             External Differential Overlay (COW)
+------------------------------------+        +------------------------------------+
|  Virtual Disk (target.qcow2)       |        |  Base Disk (base_win11.qcow2)      |
|  +------------------------------+  |        |  (Read-Only Master Image)          |
|  | Header & Metadata            |  |        +------------------------------------+
|  +------------------------------+  |                          ^
|  | Base L1/L2 Cluster Tables    |  |                          | -b base_win11.qcow2
|  +------------------------------+  |        +-----------------+------------------+
|  | Snapshot Table:              |  |        |  Differential Overlay Image        |
|  | - tag: "clean_baseline"      |  |        |  (analysis_target.qcow2)           |
|  | - date: 2026-10-29           |  |        |  (Writes contained here only)      |
|  | - vm_size: 4.2 GB            |  |        +------------------------------------+
|  +------------------------------+  |
+------------------------------------+
```

### Internal Snapshots vs Copy-on-Write Overlays

| Feature | Internal Snapshots (`qemu-img snapshot`) | Copy-On-Write Overlays (`-b backing`) |
|---|---|---|
| **File Structure** | Single monolithic `.qcow2` file containing all snapshot metadata and cluster deltas. | Separate overlay file storing only modified sectors; master base disk remains untouched. |
| **Integrity Risk** | High; corruption of file header or metadata invalidates all snapshots. | Low; master image is read-only, disposable overlays can be deleted instantly. |
| **Performance** | Minimal overhead during execution; slight file fragmentation over time. | High read performance; writes append to overlay. |
| **Best For** | Ad-hoc checkpoints during interactive dynamic triage. | Automated malware detonation pipelines and disposable sandboxes. |

### Low-Level `qemu-img` Commands
```bash
# 1. Create a differential copy-on-write overlay linked to a base disk
qemu-img create -f qcow2 -b /path/to/base_win11.qcow2 -F qcow2 /path/to/overlay_target.qcow2 64G

# 2. List internal snapshots in a QCOW2 image
qemu-img snapshot -l /path/to/disk.qcow2

# 3. Create an internal snapshot inside a QCOW2 image
qemu-img snapshot -c "baseline" /path/to/disk.qcow2

# 4. Rollback to an internal snapshot
qemu-img snapshot -a "baseline" /path/to/disk.qcow2

# 5. Delete an internal snapshot
qemu-img snapshot -d "baseline" /path/to/disk.qcow2
```

---

## 6. Automated Provisioning & Testing with `setup_utm.py`

The dedicated automation helper (`scripts/setup_utm.py`) provides end-to-end sandbox operations:

### 1. Environment Triage & VM Discovery
```bash
# Check UTM app status, paths, and enumerate registered VMs
uv run scripts/setup_utm.py status --json

# List VMs in JSON format
uv run scripts/setup_utm.py list-vms --json
```

### 2. Automated Snapshot Management
```bash
# List snapshots
uv run scripts/setup_utm.py snapshot-list "Win11-ARM64-RE" --json

# Create baseline snapshot
uv run scripts/setup_utm.py snapshot-create "Win11-ARM64-RE" "pre-detonation" --json

# Rollback snapshot after detonation
uv run scripts/setup_utm.py snapshot-restore "Win11-ARM64-RE" "pre-detonation" --json
```

### 3. Disposable Sandboxing
Start a VM in disposable mode where changes are automatically discarded upon exit:
```bash
uv run scripts/setup_utm.py start-disposable "Win11-ARM64-RE"
```

### 4. AppleScript Native Input Simulation (`send-input`)
Inject keystrokes and mouse clicks directly into the VM graphical window without active network connections:
```bash
# Type text into guest display
uv run scripts/setup_utm.py send-input "Win11-ARM64-RE" --text "calc.exe"

# Send keystroke with modifier (e.g. Command/Control)
uv run scripts/setup_utm.py send-input "Win11-ARM64-RE" --text "r" --modifiers command

# Click specific coordinates inside VM display
uv run scripts/setup_utm.py send-input "Win11-ARM64-RE" --click 450 320 --button left
```

### 5. Remote Debugger Server Templates (`ida-server-info`)
Display configuration templates for running IDA Pro debug servers across UTM guests:
```bash
uv run scripts/setup_utm.py ida-server-info
```

---

## 7. Isolated Network Topologies & Remote Debugging Setup

When detonating malware or triaging network protocols, configure UTM network modes to prevent lateral movement or accidental Internet reachability:

```
                       Isolated Malware Sandbox Topology
+-------------------------------------------------------------------------------+
| macOS Host (Analysis Workstation)                                             |
|                                                                               |
|  +------------------------+                        +-----------------------+  |
|  | IDA Pro / Ghidra /     |                        | Inetsim / FakeNet-NG  |  |
|  | mitmproxy (Host)       |                        | (Simulated Internet)  |  |
|  +-----------+------------+                        +-----------+-----------+  |
|              |                                                 |              |
|              | TCP :23946 (IDA RPC)                            | DNS/HTTP/TLS |
|              v                                                 v              |
|  +-------------------------------------------------------------------------+  |
|  | UTM Host-Only Network Adapter (virbr0: 192.168.105.1/24)                |  |
|  +-------------------------------------+-----------------------------------+  |
+----------------------------------------|--------------------------------------+
                                         |
                                         v
+-------------------------------------------------------------------------------+
| UTM Virtual Machine Guest (Isolated Sandbox: 192.168.105.10)                  |
|                                                                               |
|  - Default Gateway: 192.168.105.1 (Host-Only Adapter)                         |
|  - DNS Server: 192.168.105.1 (Routed to FakeNet/Inetsim)                      |
|  - win64_remote.exe -p23946 (IDA Debug Server listening)                      |
|  - Target Malware Process (Running under debugger)                            |
+-------------------------------------------------------------------------------+
```

### Network Topology Configurations
1. **Shared (NAT) with Specific Port Forwarding**:
   - Best for remote debugging when guest needs to reach controlled services.
   - Forward Host `127.0.0.1:23946` -> Guest Port `23946` (for IDA debug server).
   - Forward Host `127.0.0.1:2222` -> Guest Port `22` (for SSH administration).
2. **Host-Only Network**:
   - Guest can communicate exclusively with the macOS host; all external WAN traffic is blocked at the hypervisor virtual switch.
   - Host runs `mitmproxy` or `inetsim` on the virtual bridge interface to intercept and fake HTTP/DNS responses.
3. **Bridged Network**:
   - Connects guest directly to the host physical Ethernet/Wi-Fi interface. Never use this mode for unknown malware samples.

---

## 8. Boundaries & Anti-Patterns
- **Do not detonate malware in VMs configured with Bridged or Shared NAT networks**: Always isolate the VM via Host-Only networking or simulated default gateways before executing uncharacterized binaries.
- **Do not restore snapshots while the guest is writing critical data**: Gracefully suspend or stop the VM (`utmctl stop` or `utmctl suspend`) prior to issuing `snapshot restore` to prevent disk corruption.
- **Do not edit base disk images when differential overlays exist**: Modifying `base_win11.qcow2` will invalidate the sector cluster mapping of all child overlays (`analysis_target.qcow2`), rendering them unusable.
