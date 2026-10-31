# UTM Hypervisor & QCOW2 Snapshot Management

This reference documents UTM.app virtualization and QCOW2 disk snapshot workflows on Apple Silicon macOS (`arm64`), covering command-line administration via `utmctl`, disk image manipulation with `qemu-img`, sandbox lifecycle management for malware analysis, and network topology configurations.

---

## 1. UTM as Core Hypervisor on Apple Silicon macOS

On Apple Silicon (M1/M2/M3/M4), UTM provides hardware-accelerated virtualization utilizing Apple's `Virtualization.framework` alongside QEMU emulation for cross-architecture targets.

Key characteristics:
- **Architecture**: Native `arm64` virtual machines run with near bare-metal execution speed through Apple Hypervisor / Virtualization framework. Cross-architecture guest VMs (e.g. `x86_64`) run via QEMU TCG emulation.
- **Management CLI**: `utmctl` is bundled inside `/Applications/UTM.app/Contents/MacOS/utmctl` or linked into `/opt/homebrew/bin/utmctl`.
- **Disk Backing**: UTM stores VM bundles (`.utm`) containing configuration plists and disk images (typically formatted as QCOW2 or raw disk images).

---

## 2. Command-Line VM Administration (`utmctl`)

The `utmctl` CLI tool enables automated control of UTM virtual machines without opening the graphical interface.

### Discovering and Querying VMs

```bash
# List all registered virtual machines (UUID, Status, Name)
utmctl list

# Inspect running status of a specific VM
utmctl status "Windows VM - FOR508"
utmctl status <VM_UUID>
```

### VM Lifecycle Operations

```bash
# Start or resume a virtual machine
utmctl start "Windows VM - FOR508"

# Suspend a virtual machine to memory
utmctl suspend "Windows VM - FOR508"

# Discard saved suspended state (forces normal cold boot)
utmctl discard-state "Windows VM - FOR508"

# Gracefully shut down or stop a virtual machine
utmctl stop "Windows VM - FOR508"

# Query assigned guest IP addresses (requires QEMU Guest Agent)
utmctl ip-address "Windows VM - FOR508"
```

### VM Snapshots via `utmctl`

UTM supports native VM snapshots (capturing disk state and memory state when suspended or stopped):

```bash
# List snapshots for a VM (supports --json for automated parsing)
utmctl snapshot list "Windows VM - FOR508"
utmctl snapshot list <VM_UUID> --json

# Create a new snapshot
utmctl snapshot create "Windows VM - FOR508" --name "clean_baseline"

# Restore a snapshot by name or snapshot identifier
utmctl snapshot restore "Windows VM - FOR508" --snapshot "clean_baseline"

# Delete a snapshot
utmctl snapshot delete "Windows VM - FOR508" --snapshot "clean_baseline"
```

---

## 3. QCOW2 Disk Format Architecture

QCOW2 (QEMU Copy-On-Write version 2/3) is the storage format used for flexible snapshotting and disk branching in virtualization pipelines.

### Copy-On-Write (COW) Overlays

A base disk image remains immutable, while guest modifications are written to a lightweight differential overlay.

```
+------------------------------------+
|        Base Disk Image             |  (Read-only master OS installation)
|        `base_win11.qcow2`          |
+------------------------------------+
                  ^
                  | Backing file pointer (-b base_win11.qcow2)
+------------------------------------+
|     Differential Overlay Disk      |  (Contains only modified sectors)
|       `analysis_target.qcow2`      |
+------------------------------------+
```

Creating a copy-on-write overlay using `qemu-img`:
```bash
# Create 64GB overlay linked to base_win11.qcow2
qemu-img create -f qcow2 -b /path/to/base_win11.qcow2 -F qcow2 /path/to/analysis_target.qcow2 64G
```

### Internal Snapshots vs External Differential Disks

| Feature | Internal Snapshots (`qemu-img snapshot`) | External Differential Disks (`-b backing`) |
|---|---|---|
| **Storage** | Single `.qcow2` file holds all states | Separate overlay `.qcow2` file per branch |
| **Creation** | `qemu-img snapshot -c <snap> disk.qcow2` | `qemu-img create -f qcow2 -b base.qcow2 overlay.qcow2` |
| **Rollback** | `qemu-img snapshot -a <snap> disk.qcow2` | Discard overlay file and recreate from base |
| **Integrity** | Corruption risks whole image file | Base disk remains strictly read-only and safe |
| **Best For** | Ad-hoc checkpoints during dynamic triage | Automated detonation pipelines & disposable sandboxes |

### Internal Snapshot Management Commands

```bash
# List internal snapshots in a QCOW2 image
qemu-img snapshot -l /path/to/disk.qcow2

# Create snapshot named "clean_state"
qemu-img snapshot -c clean_state /path/to/disk.qcow2

# Apply (restore) snapshot named "clean_state"
qemu-img snapshot -a clean_state /path/to/disk.qcow2

# Delete snapshot named "clean_state"
qemu-img snapshot -d clean_state /path/to/disk.qcow2

# Inspect QCOW2 image details and snapshots as JSON
qemu-img info --out=json /path/to/disk.qcow2
```

---

## 4. Malware Analysis Sandbox Lifecycle

A repeatable reverse engineering and dynamic detonation workflow follows a strict snapshot lifecycle:

```
+-----------------------+
|  1. Clean Baseline    |  OS installed, tools deployed, analysis agent primed
+-----------------------+
            |
            v
+-----------------------+
|  2. Snapshot Creation |  `utmctl snapshot create <VM> --name "baseline"`
+-----------------------+
            |
            v
+-----------------------+
|  3. Detonation / RE   |  Deploy sample, hook with Frida/IDA, capture network/memory
+-----------------------+
            |
            v
+-----------------------+
|  4. Triage & Evidence |  Dump memory, extract IOCs, harvest logs
+-----------------------+
            |
            v
+-----------------------+
|  5. Instant Rollback  |  `utmctl stop <VM>`
|                       |  `utmctl snapshot restore <VM> --snapshot "baseline"`
+-----------------------+
```

### Operational Rules for Detonation Sandboxes:
1. **Never Detonate on Base**: Always execute malware on a disposable snapshot or differential overlay.
2. **Cold Rollback**: Shut down or stop the VM (`utmctl stop <VM>`) before restoring snapshots to prevent filesystem inconsistencies or state conflicts.
3. **Verify State Restoration**: Confirm the VM returns to its pristine state before beginning the next sample analysis.

---

## 5. VM Networking Configuration

Selecting the appropriate network mode depends on whether the sample requires internet access, local isolation, or host debugging access.

### 1. Shared Network (NAT) with Port Forwarding (Recommended for Remote Debugging)
- **Topology**: Guest VM resides in an isolated private subnet behind macOS NAT.
- **Outbound**: Guest can connect outbound to the internet (or to a host proxy such as mitmproxy at `192.168.64.1` / default gateway).
- **Inbound**: Host cannot connect into the VM directly unless port forwarding rules are configured in UTM VM Settings:
  - Protocol: `TCP`
  - Host Port: `23946`
  - Guest Port: `23946`
  - Guest IP: (empty / all interfaces)
- **IDA Pro Connection**: Connect IDA Pro on host to `127.0.0.1:23946`.

### 2. Bridged Networking
- **Topology**: VM attaches directly to host physical interface (Wi-Fi or Ethernet) and receives a routable IP on the local LAN via DHCP.
- **Inbound**: Direct bidirectional communication between host and guest.
- **Obtaining IP**:
  ```bash
  utmctl ip-address <VM_NAME_OR_UUID>
  ```
- **IDA Pro Connection**: Connect IDA Pro to `<GUEST_IP>:23946`.

### 3. Isolated / Host-Only Network (Malware Containment)
- **Topology**: UTM Host-Only network. Guest has no route to the public internet or local LAN.
- **Safety**: Prevents malware from contacting real C2 servers, scanning internal networks, or leaking host identifiers.
- **Simulated Services**: Run `INetSim`, `fakedns`, or `mitmproxy` on the host to emulate DNS and HTTP C2 responses safely.

---

## 6. UTM AppleScript Scripting Cheat Sheet & Automation Reference

While `utmctl` provides convenient command-line wrappers for basic lifecycle and snapshot operations, UTM exposes a rich AppleScript scripting dictionary (`tell application "UTM"`) on macOS. This interface allows advanced virtualization workflows unavailable in `utmctl`, such as:
- **Disposable execution** without committing disk writes.
- **Deep snapshot synchronization** (scanning for out-of-band `qemu-img` internal snapshots).
- **Network sandboxing and host isolation** flags.
- **Direct guest agent interaction** without network or SSH access (file push, pull, arbitrary command execution with exit code and stdout capture).
- **Input automation** (keystroke injection, mouse clicks, raw PC AT scancodes).
- **Automated VM provisioning and cloning**.
- **USB passthrough management**.

### 1. VM Discovery & Lifecycle (Disposable Execution)

```applescript
tell application "UTM"
    -- Resolve VM by name or UUID
    set vm to virtual machine named "Windows 11 Sandbox"
    -- set vm to virtual machine id "5D419106-2824-4FED-BFE1-24A7F7E253D8"

    -- Standard execution
    start vm

    -- DISPOSABLE EXECUTION: runs VM in volatile RAM/overlay mode
    -- Disk modifications vanish completely when the VM is powered off
    start vm without saving

    -- Suspend & state persistence
    suspend vm
    suspend vm with saving

    -- Shutdown variations
    stop vm              -- ACPI graceful shutdown
    stop vm by force     -- Force power off
    stop vm by kill      -- Kill hypervisor process immediately
end tell
```

Executing from shell:
```bash
osascript -e 'tell application "UTM" to start (virtual machine named "Windows 11 Sandbox") without saving'
```

### 2. Snapshot Management & Scan Synchronization

UTM allows listing, creating, restoring, overwriting, and syncing snapshots via AppleScript.

> **Snapshot Compatibility Note**:
> - **QEMU virtual machines**: Supported across all supported versions of macOS.
> - **Apple Virtualization (`apple` backend) VMs**: Require **macOS 27 or later** and the VM **must be stopped** for every snapshot operation except `delete snapshot`.

```applescript
tell application "UTM"
    set vm to virtual machine named "Windows 11 Sandbox"

    -- Enumerate snapshot names (ordered newest first)
    set snapNames to name of every snapshot of vm

    -- Create a new snapshot
    set snap to create snapshot vm named "clean_baseline"

    -- Query snapshot properties: creation date, size, includes running state
    set snapInfo to {creation date, size, includes running state} of snap

    -- Restore a snapshot
    set targetSnap to snapshot "clean_baseline" of vm
    restore targetSnap

    -- Overwrite snapshot with current VM state
    overwrite targetSnap

    -- Delete snapshot
    delete snapshot targetSnap

    -- Discard suspended RAM state to force cold boot
    discard saved state vm

    -- CRITICAL FOR RE: Scan for snapshots created out-of-band by qemu-img
    scan snapshots vm
end tell
```

### 3. Network Sandboxing & Host Isolation

UTM configuration allows setting custom emulated VLAN addressing and isolating the host from guest network requests.

> **Important Boundary — Host Isolation vs. Air-Gapped Containment**:
> `set isolate from host of nic to true` configures host-level packet filtering on a **Shared Network (NAT)** interface. It blocks the guest VM from reaching services running on the macOS host (e.g. host web servers, ssh, or host LAN devices), but **outbound internet routing remains enabled**.
> For complete malware containment with zero outbound internet connectivity, use an **Isolated / Host-Only Network** (see Section 5.3) or disconnect all network adapters.

```applescript
tell application "UTM"
    set vm to virtual machine named "Windows 11 Sandbox"
    set config to configuration of vm
    set nic to item 1 of network interfaces of config

    -- Configure custom emulated VLAN subnet for QEMU VM in shared network mode
    set vlan guest address of nic to "192.168.100.0/24"
    set vlan dhcp start address of nic to "192.168.100.10"
    set vlan dhcp end address of nic to "192.168.100.100"

    -- Prevent guest from accessing the macOS host
    set isolate from host of nic to true

    -- Save configuration back to VM (VM must be stopped)
    set item 1 of network interfaces of config to nic
    update configuration of vm with config
end tell
```

For Apple backend virtual machines on macOS 26+:
```applescript
tell application "UTM"
    set vm to virtual machine named "Apple Linux"
    set config to configuration of vm
    set mode of item 1 of network interfaces of config to nat network
    update configuration of vm with config
end tell
```

### 4. QEMU Guest Agent: File Transfer & Command Execution (Network-Less)

When the guest OS runs `qemu-ga` (QEMU Guest Agent), UTM can push files, pull files, and execute commands through the virtio-serial channel without requiring guest network connectivity or SSH credentials.

#### Pushing a File from Host to Guest:
```applescript
tell application "UTM"
    set vm to virtual machine named "Windows 11 Sandbox"
    set hostFile to POSIX file "/path/to/host/sample.exe"
    push of (open file of vm at "C:\\Users\\User\\Desktop\\sample.exe" for writing) from hostFile
end tell
```

#### Pulling a File from Guest to Host:
```applescript
tell application "UTM"
    set vm to virtual machine named "Windows 11 Sandbox"
    set hostOut to POSIX file "/path/to/host/memory.dmp"
    pull of (open file of vm at "C:\\Users\\User\\Desktop\\memory.dmp") to hostOut
end tell
```

#### Direct Binary / Command Execution inside Guest:
```applescript
tell application "UTM"
    set vm to virtual machine named "Windows 11 Sandbox"
    tell (execute of vm at "cmd.exe" with arguments {"/c", "whoami"} with output capturing)
        -- Poll until command completes
        repeat
            set res to get result
            if exited of res then exit repeat
            delay 0.5
        end repeat
        -- Extract exit code and standard output text
        set guestExitCode to exit code of res
        set guestOutput to output text of res
        return guestOutput
    end tell
end tell
```

### 5. Input Automation (Display UI Interaction)

Inject keystrokes, modifier keys, raw PC AT scancodes, or mouse clicks directly into the VM window. Useful when automating dynamic UI prompts (e.g. clicking through UAC dialogs, installer wizards, or typing passwords in pre-boot environments):

```applescript
tell application "UTM"
    set vm to virtual machine named "Windows 11 Sandbox"

    -- Send text keystrokes
    input keystroke of vm text "malware_test"

    -- Send keystrokes with modifiers (shift, control, option, command)
    input keystroke of vm text "password" with modifiers shift

    -- Send left mouse click at display coordinates (X=350, Y=220)
    input mouse click of vm at {350, 220} with mouse button left

    -- Send raw PC AT scan codes (make + break pairs, e.g. for enter or special keys)
    input scan code of vm codes {35, 163, 18, 146}
end tell
```

### 6. VM Creation, Duplication & macOS Provisioning

#### Creating a QEMU ARM64 Analysis VM:
```applescript
tell application "UTM"
    set iso to POSIX file "/path/to/installer.iso"
    set vm to make new virtual machine with properties {backend:qemu, configuration:{name:"RE-Lab-ARM64", architecture:"aarch64", drives:{{removable:true, source:iso}, {guest size:65536}}}}
end tell
```

#### Duplicating a VM (Cloning):
```applescript
tell application "UTM"
    set vm to virtual machine named "Base-Win11"
    duplicate vm with properties {configuration:{name:"Detonation-Target-01", hypervisor:true}}
end tell
```

#### macOS Apple Silicon VM with Automated Account Provisioning:
```applescript
tell application "UTM"
    set ipsw to POSIX file "/path/to/UniversalMac_Restore.ipsw"
    set vm to make new virtual machine with properties {backend:apple, configuration:{name:"macOS-Research", os:macOS, macRecoveryIpsw:ipsw, memory:8192, drives:{{guest size:131072}}}}
    install vm
    repeat
        set p to query install vm
        if not installing of p then exit repeat
        delay 10
    end repeat
    -- First boot provisioning: sets username, password, auto-login, and SSH remote login
    start vm provisioning {username:"analyst", password:"analysisPassword123!", automatic login:true, remote login:true}
end tell
```

### 7. USB Device Passthrough

Attach or detach USB hardware devices (such as hardware tokens, SDR dongles, or physical debug probes):

```applescript
tell application "UTM"
    set targetDevice to first usb device
    set vm to virtual machine named "Windows 11 Sandbox"
    connect targetDevice to vm
    -- To disconnect:
    disconnect targetDevice
end tell
```

---

## 7. Companion Automation Script (`setup_utm.py`)

The companion automated helper wraps both `utmctl`, `qemu-img`, and `osascript` AppleScript automation into a single CLI tool:

```bash
# Check host status and list registered VMs
uv run scripts/setup_utm.py status

# List VMs as JSON
uv run scripts/setup_utm.py list-vms --json

# Start VM in disposable mode (AppleScript: changes discarded on shutdown)
uv run scripts/setup_utm.py start-disposable "Windows VM"

# Run command in guest via QEMU Guest Agent without network/SSH
uv run scripts/setup_utm.py guest-exec "Windows VM" "cmd.exe" --args "/c" "whoami"

# Push file to guest via QEMU Guest Agent
uv run scripts/setup_utm.py guest-push "Windows VM" /path/to/sample.exe "C:\\Users\\User\\Desktop\\sample.exe"

# Pull file from guest via QEMU Guest Agent
uv run scripts/setup_utm.py guest-pull "Windows VM" "C:\\Users\\User\\Desktop\\evidence.log" /tmp/evidence.log

# Send mouse click or keystroke input to VM display
uv run scripts/setup_utm.py send-input "Windows VM" --click 400 300
uv run scripts/setup_utm.py send-input "Windows VM" --text "adminPass"

# Manage UTM snapshots
uv run scripts/setup_utm.py snapshot-list "Windows VM"
uv run scripts/setup_utm.py snapshot-create "Windows VM" "clean_base"
uv run scripts/setup_utm.py snapshot-restore "Windows VM" "clean_base"

# Create differential QCOW2 disks
uv run scripts/setup_utm.py qcow2-create /tmp/overlay.qcow2 20 --backing /path/to/base.qcow2

# Manage internal QCOW2 snapshots
uv run scripts/setup_utm.py qcow2-snapshot /tmp/disk.qcow2 --create clean
uv run scripts/setup_utm.py qcow2-snapshot /tmp/disk.qcow2 --list
uv run scripts/setup_utm.py qcow2-snapshot /tmp/disk.qcow2 --restore clean
```

Or reference via skill URI:
`uv run scripts/setup_utm.py <subcommand>`
