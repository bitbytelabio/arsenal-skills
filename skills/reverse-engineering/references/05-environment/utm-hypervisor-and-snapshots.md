# UTM Hypervisor and Snapshots

UTM on Apple Silicon macOS: `utmctl`, AppleScript, `qemu-img`, sandbox lifecycle, and networking. Commands were checked against UTM 5.0.8 (`utmctl version`).

---

## 1. Backends

| Backend | Use | Guest agent features (`exec`, `file`, `ip-address`) | Snapshots |
|---|---|---|---|
| QEMU (HVF for arm64, TCG for x86_64) | Windows ARM, Linux, any non-arm64 guest | Yes, with `qemu-ga` / UTM Guest Tools in the guest | UTM 5.0.7+ (running state included when taken live) |
| Apple Virtualization | macOS guests, fast Linux arm64 | No (no QEMU guest agent) | UTM 5.0.7+ on a macOS 27 host, VM stopped |

- `utmctl` lives at `/Applications/UTM.app/Contents/MacOS/utmctl`. Link it: `ln -s /Applications/UTM.app/Contents/MacOS/utmctl /opt/homebrew/bin/utmctl`.
- VM bundles are `~/Library/Containers/com.utmapp.UTM/Data/Documents/<name>.utm/` with `config.plist` and `Data/*.qcow2` (QEMU) or `Data/*.img` (Apple, raw).
- x86_64 guests under TCG are 5-20x slower. Use them only when the sample needs x86 Linux or 32-bit-only Windows code paths that ARM64 Windows emulation cannot run.

---

## 2. `utmctl`

Identifier is the full name or the UUID from `utmctl list`.

```bash
VM="Windows-RE-Lab"
utmctl list
utmctl status "$VM"
utmctl start "$VM"                    # --disposable, --recovery, --attach, --hide
utmctl suspend "$VM"
utmctl stop "$VM"                     # default --force (power off); --request = ACPI; --kill
utmctl discard-state "$VM"            # drop a suspended state
utmctl ip-address "$VM"               # guest agent required
utmctl exec "$VM" --cmd cmd.exe /c whoami
utmctl file pull "$VM" 'C:\Windows\Temp\out.txt' > out.txt
utmctl file push "$VM" 'C:\Windows\Temp\in.bin' < in.bin
utmctl clone "$VM" --name "$VM-detonate-01"
```

`utmctl start` on a macOS 27 host with a macOS 27 Apple-backend guest can provision the first boot: `--provision-username`, `--provision-password-stdin`, `--provision-auto-login`, `--provision-ssh`.

### Snapshots (`utmctl snapshot`, UTM 5.0.8+)

Older `utmctl` (UTM 4.x, 5.0.7) has no `snapshot` subcommand; run `utmctl --help` to check. Fall back to `qemu-img` (section 3) with the VM stopped.

```bash
utmctl snapshot list "$VM" --json          # newest first; --scan finds qemu-img snapshots
utmctl snapshot create "$VM" --name clean_baseline
utmctl snapshot restore "$VM" --snapshot clean_baseline
utmctl snapshot overwrite "$VM" --snapshot clean_baseline
utmctl snapshot rename "$VM" --snapshot clean_baseline --to tools_v2
utmctl snapshot delete "$VM" --snapshot clean_baseline     # no confirmation
utmctl snapshot scan "$VM"
```

`create` on a running QEMU VM saves RAM too. On a stopped VM or an Apple VM it saves disks only, and `restore` then means a cold boot. A stopped VM resumes from the restored snapshot the next time it starts.

---

## 3. QCOW2 with `qemu-img`

Only touch a qcow2 file when the VM is **stopped**. Writing to an open image corrupts it. Install with `brew install qemu`.

```bash
DISK="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/Linux-RE-Lab.utm/Data/<disk>.qcow2"
qemu-img info --output=json "$DISK"
qemu-img snapshot -l "$DISK"
qemu-img snapshot -c clean_state "$DISK"
qemu-img snapshot -a clean_state "$DISK"
qemu-img snapshot -d clean_state "$DISK"

# Copy-on-write overlay over a read-only base
qemu-img create -f qcow2 -b /path/to/base.qcow2 -F qcow2 /path/to/overlay.qcow2 64G
```

After an out-of-band `qemu-img snapshot -c`, run `utmctl snapshot scan "$VM"` so UTM lists it.

| | Internal snapshot (`snapshot -c`) | Overlay (`create -b`) |
|---|---|---|
| Storage | Inside one qcow2 | One file per branch |
| Rollback | `snapshot -a` | Delete overlay, recreate |
| Risk | Corruption hits every state | Base stays read-only |
| Fit | Ad-hoc checkpoints | Repeated disposable runs |

Do not move or modify a base image once overlays point to it.

---

## 4. Sandbox lifecycle

1. Clean baseline: OS installed, tools provisioned, VM shut down.
2. `utmctl snapshot create "$VM" --name baseline` (or `uv run scripts/setup_utm.py snapshot-create "$VM" baseline`).
3. Detonate or debug. For a throwaway run with no snapshot, `utmctl start "$VM" --disposable` discards all disk writes at shutdown.
4. Pull evidence (`guest-pull`, `utmctl file pull`) before stopping.
5. `utmctl stop "$VM"`, then `utmctl snapshot restore "$VM" --snapshot baseline`.

Rules:
- Never detonate on the base VM without a snapshot, disposable mode, or overlay.
- Stop the VM before restoring a disk-only snapshot.
- Network for detonation: Host Only (section 5), unless the task needs a live server.

---

## 5. Networking

| Mode (QEMU) | Host → guest | Guest → internet | Port forwarding | Default subnet |
|---|---|---|---|---|
| Shared Network | Direct to guest IP | Yes (NAT) | **No** | `192.168.64.0/24`, host `192.168.64.1` |
| Emulated VLAN | Only via forwards | Yes (QEMU user net) | **Yes** | `10.0.2.0/24`, host `10.0.2.2` |
| Bridged | Direct to LAN IP | Via LAN | No | LAN DHCP |
| Host Only | Direct to guest IP | No | No | vmnet host-only subnet |

Apple Virtualization VMs have only `nat network` (like Shared Network) and `bridged`.

- Remote debugger or WinRM/SSH from the host: Shared Network + guest IP, or Emulated VLAN + forward (`127.0.0.1:23946` → `23946`, `127.0.0.1:2222` → `22`, `127.0.0.1:59850` → `5985`).
- Containment: Host Only. Answer DNS/HTTP from the host with INetSim, fakedns, or `mitmdump --server-replay capture.flow --set server_replay_extra=kill`.
- `isolate from host` (Shared Network) blocks guest → host traffic. Internet stays reachable. It is not containment.

### Networking troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Linux guest has no IPv4 on Shared Network | Cloud image netplan does not match the NIC name, or vmnet DHCP did not answer (seen with Ubuntu cloud image on UTM 5) | In guest: `ip link`, then match the name in `/etc/netplan/*.yaml` and `sudo netplan apply`; or switch to Emulated VLAN and forward SSH |
| Window shows "Display output is not active" | Cloud image with serial console only | Use SSH or `utmctl attach "$VM"` |
| Port forward ignored | NIC is Shared Network | Forwards apply only to Emulated VLAN |
| Windows ARM guest has no network | NetKVM driver missing | Install UTM Guest Tools (`spice-guest-tools`/`utm-guest-tools` ISO) |
| Host cannot reach guest on Shared Network | Guest firewall, or `isolate from host` set | Open the port in the guest; clear the flag |
| Guest gets an IP but no DNS | Host VPN/DNS proxy intercepting vmnet | Set guest DNS to `192.168.64.1` or a public resolver; disconnect VPN |

### Guest agent troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `utmctl exec`/`file`/`ip-address` fail or hang | No `qemu-ga` in guest | Linux: `sudo apt install qemu-guest-agent && sudo systemctl enable --now qemu-guest-agent`. Windows: UTM Guest Tools |
| Same commands fail on a macOS guest | Apple backend has no QEMU guest agent | Use SSH; read the IP from `/var/db/dhcpd_leases` on the host |
| `guest-exec` returns before the command finishes | Default timeout 60 s | `--timeout 600` before `--args` |
| AppleScript error -1743 | macOS Automation permission for the terminal | System Settings > Privacy & Security > Automation > allow UTM |

---

## 6. AppleScript (`tell application "UTM"`)

Terms below exist in the UTM 5.0.8 dictionary (`sdef /Applications/UTM.app`). `input keystroke`, `input scan code`, and `input mouse click` work on the QEMU backend only.

### Lifecycle

```applescript
tell application "UTM"
    set vm to virtual machine named "Windows-RE-Lab"   -- or: virtual machine id "<UUID>"
    start vm                         -- normal
    start vm saving false            -- disposable: disk writes discarded at stop
    suspend vm saving true           -- save RAM state to disk
    stop vm by request               -- ACPI shutdown
    stop vm by force                 -- power off
    stop vm by kill                  -- kill the VM process
end tell
```

```bash
osascript -e 'tell application "UTM" to start (virtual machine named "Windows-RE-Lab") saving false'
```

### Snapshots

```applescript
tell application "UTM"
    set vm to virtual machine named "Windows-RE-Lab"
    set snapNames to name of every snapshot of vm      -- newest first
    set snap to create snapshot vm named "clean_baseline"
    get {creation date, size, includes running state} of snap
    restore (snapshot "clean_baseline" of vm)
    overwrite (snapshot "clean_baseline" of vm)
    delete snapshot (snapshot "clean_baseline" of vm)
    discard saved state vm
    scan snapshots vm                                   -- picks up qemu-img snapshots
end tell
```

### Network configuration (VM stopped)

```applescript
tell application "UTM"
    set vm to virtual machine named "Linux-RE-Lab"
    set config to configuration of vm
    set nic to item 1 of network interfaces of config
    set mode of nic to emulated                         -- shared | emulated | host | bridged
    set port forwards of nic to {{protocol:TCP, host address:"127.0.0.1", host port:2222, guest port:22}, {protocol:TCP, host address:"127.0.0.1", host port:23946, guest port:23946}}
    set item 1 of network interfaces of config to nic
    update configuration of vm with config
end tell
```

`vlan guest address`, `vlan dhcp start address`, `vlan dhcp end address`, and `isolate from host` apply to Shared/Host modes. Apple-backend NICs take `mode` `nat network` or `bridged`.

### Guest agent (QEMU backend)

```applescript
tell application "UTM"
    set vm to virtual machine named "Windows-RE-Lab"
    -- push
    set f to open file of vm at "C:\\Workspace\\sample.exe" for writing
    push f from (POSIX file "/path/to/sample.exe")
    -- pull
    set g to open file of vm at "C:\\Workspace\\evidence.log"
    pull g to (POSIX file "/tmp/evidence.log")
    -- exec with output
    set p to execute of vm at "cmd.exe" with arguments {"/c", "whoami"} with output capturing
    repeat
        set r to get result of p
        if exited of r then exit repeat
        delay 0.5
    end repeat
    return {exit code of r, output text of r}
    -- IPs
    query ip of vm
end tell
```

### Input

```applescript
tell application "UTM"
    set vm to virtual machine named "Windows-RE-Lab"
    input keystroke vm text "password"
    input keystroke vm text "r" with modifiers {command}
    input mouse click vm at {350, 220} with mouse button left
    input scan code vm codes {28, 156}                  -- Enter make/break
end tell
```

### Clone and USB

```applescript
tell application "UTM"
    duplicate (virtual machine named "Base-Win11") with properties {configuration:{name:"Detonation-01"}}
    connect (first usb device) to (virtual machine named "Windows-RE-Lab")
end tell
```

---

## 7. `setup_utm.py`

```bash
VM="Windows-RE-Lab"
uv run scripts/setup_utm.py status
uv run scripts/setup_utm.py list-vms --json
uv run scripts/setup_utm.py start-disposable "$VM"
uv run scripts/setup_utm.py guest-exec "$VM" cmd.exe --timeout 120 --args /c whoami
uv run scripts/setup_utm.py guest-push "$VM" ./sample.exe 'C:\Workspace\sample.exe'
uv run scripts/setup_utm.py guest-pull "$VM" 'C:\Workspace\evidence.log' ./evidence.log
uv run scripts/setup_utm.py send-input "$VM" --click 400 300 --button left
uv run scripts/setup_utm.py send-input "$VM" --text "adminPass"
uv run scripts/setup_utm.py snapshot-list "$VM"
uv run scripts/setup_utm.py snapshot-create "$VM" clean_base      # utmctl snapshot, UTM 5.0.8+
uv run scripts/setup_utm.py snapshot-restore "$VM" clean_base
uv run scripts/setup_utm.py qcow2-create ./overlay.qcow2 20 --backing /path/to/base.qcow2
uv run scripts/setup_utm.py qcow2-snapshot "$DISK" --create clean  # VM stopped
uv run scripts/setup_utm.py qcow2-snapshot "$DISK" --list
uv run scripts/setup_utm.py qcow2-snapshot "$DISK" --restore clean
uv run scripts/setup_utm.py ida-server-info
```

`--json` works on every subcommand. In `guest-exec`, everything after `--args` goes to the guest verbatim, so put `--timeout` and `--json` before it.
