# UTM on Apple Silicon: `utmctl`, Snapshots, Disposable Guests, `setup_utm.py`

- **Domain**: Running untrusted samples and remote debug servers in UTM guests on Apple Silicon macOS. Headless lifecycle with `utmctl`, snapshots (`utmctl snapshot` on UTM 5.0.8+, `qemu-img` fallback), disposable runs and clones, guest agent file/exec, networking, and the skill helper `scripts/setup_utm.py`.
- **Verified**: `utmctl` 5.0.8 `--help` for every subcommand below; `utmctl list` and `utmctl snapshot list --json` on this host; `uv run scripts/setup_utm.py <cmd> --help` for every helper subcommand. Lifecycle commands that change VM state were not run here.
- **Deep reference**: backend matrix, AppleScript dictionary, and network troubleshooting live in [../05-environment/utm-hypervisor-and-snapshots.md](../05-environment/utm-hypervisor-and-snapshots.md). Malware containment policy: [../02-dynamic-instrumentation/malware-sandbox-isolation.md](../02-dynamic-instrumentation/malware-sandbox-isolation.md).

---

## 1. Decide before you boot

| Question | Answer |
|---|---|
| Can static analysis settle it? | Then do not boot a VM. Dynamic runs come after triage |
| Sample OS/arch | Windows ARM64 or Linux arm64: QEMU backend with HVF (fast). x86_64-only code: Windows ARM x64 emulation, or a QEMU TCG x86_64 guest (5–20x slower). macOS: Apple Virtualization backend |
| Need `utmctl exec`, `file`, `ip-address`? | QEMU backend + guest agent (`qemu-ga` on Linux, UTM Guest Tools on Windows). Apple backend has no guest agent: use SSH |
| Need RAM state rollback? | `utmctl snapshot create` on a running QEMU VM saves RAM. Stopped or Apple VMs save disks only |
| Throwaway run, no rollback bookkeeping | `utmctl start "$VM" --disposable` |
| Several parallel detonations | `utmctl clone` per run, delete after |
| Network | Host Only for unknown malware. Shared or Emulated VLAN only for debugger/tool traffic to a trusted guest |

Check the backend of a VM:

```bash
plutil -extract Backend raw ~/Library/Containers/com.utmapp.UTM/Data/Documents/"$VM".utm/config.plist   # QEMU | Apple
```

QEMU disks are `Data/*.qcow2`. Apple disks are raw `Data/*.img`.

---

## 2. `utmctl` reference (UTM 5.0.8)

`utmctl` is `/Applications/UTM.app/Contents/MacOS/utmctl` (often linked to `/opt/homebrew/bin/utmctl`). It drives the running UTM app through Apple Events. UTM launches if it is not running; `--hide` keeps the window hidden. The identifier is the full VM name or its UUID.

```bash
VM="Windows-RE-Lab"
utmctl version
utmctl list                                   # UUID, status, name
utmctl status "$VM"                           # started | stopped | paused ...
utmctl start "$VM"                            # also resumes a suspended VM
utmctl start "$VM" --disposable               # run as snapshot; disk writes discarded
utmctl start "$VM" --hide --attach            # serial console in this terminal
utmctl start "$VM" --recovery                 # Apple backend recovery boot
utmctl suspend "$VM" [--save-state]           # pause in RAM; --save-state writes it to disk
utmctl stop "$VM"                             # --force power off (default)
utmctl stop "$VM" --request                   # ACPI shutdown request to the guest
utmctl stop "$VM" --kill                      # kill the VM process
utmctl discard-state "$VM"                    # drop saved suspend state; next start is a cold boot
utmctl attach "$VM" [--index N]               # serial port I/O
utmctl clone "$VM" --name "$VM-run-01"
utmctl delete "$VM-run-01"                    # no confirmation
utmctl usb list ; utmctl usb connect "$VM" 05ac:12a8 ; utmctl usb disconnect "$VM" 05ac:12a8
```

Guest agent commands (QEMU backend with agent running):

```bash
utmctl ip-address "$VM"                                   # IPv4 first, then IPv6
utmctl exec "$VM" --cmd cmd.exe /c whoami                 # returns the guest exit code
utmctl exec "$VM" --env TMP=/tmp --cmd /bin/sh -c 'id; uname -a'
utmctl exec "$VM" --input --cmd /bin/sh < script.sh        # forward stdin
utmctl file push "$VM" 'C:\Users\Public\sample.bin' < sample.bin    # content from stdin
utmctl file pull "$VM" 'C:\Users\Public\out.log' > out.log         # content to stdout
```

`utmctl exec` is documented to return the guest command's exit code. Do not rely on it for stdout. Redirect output to a guest file and `file pull` it, or use `uv run scripts/setup_utm.py guest-exec`, which captures stdout and stderr.

macOS 27 host + macOS 27 Apple-backend guest only: `utmctl start` can provision the first boot (`--provision-username`, `--provision-password-stdin`, `--provision-auto-login`, `--provision-ssh`).

---

## 3. Snapshots

### 3.1 `utmctl snapshot` (UTM 5.0.8+)

```bash
utmctl help snapshot                                       # confirm the subcommand exists on this host
utmctl snapshot list "$VM" --json                          # newest first; --scan picks up qemu-img snapshots
utmctl snapshot create "$VM" --name clean_baseline         # duplicate names get a number appended
utmctl snapshot restore "$VM" --snapshot clean_baseline    # -s accepts name or id
utmctl snapshot overwrite "$VM" --snapshot clean_baseline  # refresh baseline with current state
utmctl snapshot rename "$VM" --snapshot clean_baseline --to tools_v2
utmctl snapshot delete "$VM" --snapshot clean_baseline     # no confirmation
utmctl snapshot scan "$VM"                                 # find external snapshots, flag missing data
```

| VM state at `create` | Captured | Restore result |
|---|---|---|
| QEMU, running | Disks + RAM | Resumes at the captured moment |
| QEMU, stopped | Disks | Cold boot from the captured disk |
| Apple backend (stopped; macOS 27 host) | Disks | Cold boot |

On this host, `utmctl snapshot list --hide` printed `Error from event: ... OSStatus error -10004` lines and still returned the JSON. Treat the JSON as the result; investigate only if it is missing.

### 3.2 `qemu-img` fallback (older UTM, or offline disk work)

Run only with the VM stopped. A running QEMU process holds the qcow2 open; writing snapshots underneath it corrupts the image.

```bash
DISK=~/Library/Containers/com.utmapp.UTM/Data/Documents/"$VM".utm/Data/<uuid>.qcow2
utmctl stop "$VM" --request && utmctl status "$VM"        # wait for "stopped"
qemu-img snapshot -l "$DISK"
qemu-img snapshot -c clean_state "$DISK"
qemu-img snapshot -a clean_state "$DISK"
qemu-img snapshot -d clean_state "$DISK"
qemu-img create -f qcow2 -b /abs/base.qcow2 -F qcow2 /abs/overlay.qcow2   # copy-on-write overlay
utmctl snapshot scan "$VM"                                 # UTM 5.0.8+: make UTM list external snapshots
```

Apple-backend raw `.img` disks have no internal snapshots. Copy the stopped bundle with APFS clones instead: `cp -c -R "$VM.utm" "$VM-baseline.utm"` (near-instant, copy-on-write on APFS). `utmctl clone` does the same through UTM and registers the copy.

---

## 4. Disposable patterns

| Pattern | Commands | Rollback cost | Notes |
|---|---|---|---|
| Disposable start | `utmctl start "$VM" --disposable` … `utmctl stop "$VM"` | None | Writes vanish at stop. Nothing to forget. Cannot keep artifacts on the guest disk; pull them before stop |
| Snapshot + restore | `snapshot create` → run → `stop` → `snapshot restore` | Seconds | Keeps one golden VM. Forgetting the restore leaves the VM dirty |
| Clone per run | `clone` → run clone → `delete` clone | Clone time (fast on APFS) | Parallel runs; base never boots with a sample |
| qcow2 overlay | `qemu-img create -b base` → point a VM at the overlay | Delete overlay | Base must stay read-only; editing it breaks overlays |

Clone-per-run, scripted:

```bash
BASE="Windows-RE-Lab"; RUN="$BASE-run-$(date +%s)"
utmctl status "$BASE" | grep -q stopped || { echo "stop $BASE first"; exit 1; }
utmctl clone "$BASE" --name "$RUN"
utmctl start "$RUN" --hide
until utmctl ip-address "$RUN" >/dev/null 2>&1; do sleep 5; done      # guest agent up
utmctl file push "$RUN" 'C:\Users\Public\sample.bin' < /abs/samples/sample.bin
# ... detonate / debug ...
utmctl file pull "$RUN" 'C:\Users\Public\trace.etl' > /abs/out/trace.etl
utmctl stop "$RUN" --kill
utmctl delete "$RUN"
```

---

## 5. `scripts/setup_utm.py`

All subcommands accept `--json`. Invoke from the skill root.

| Subcommand | Usage | Backend |
|---|---|---|
| `status` | `uv run scripts/setup_utm.py status --json` | UTM app, `utmctl`, `qemu-img` paths and VM list |
| `list-vms` | `uv run scripts/setup_utm.py list-vms --json` | `utmctl list` |
| `snapshot-list` | `uv run scripts/setup_utm.py snapshot-list "$VM" --json` | `utmctl snapshot list` |
| `snapshot-create` | `uv run scripts/setup_utm.py snapshot-create "$VM" pre-detonation --json` | `utmctl snapshot create --name` |
| `snapshot-restore` | `uv run scripts/setup_utm.py snapshot-restore "$VM" pre-detonation --json` | `utmctl snapshot restore --snapshot` |
| `qcow2-create` | `uv run scripts/setup_utm.py qcow2-create /abs/overlay.qcow2 64G --backing /abs/base.qcow2` | `qemu-img create` |
| `qcow2-snapshot` | `uv run scripts/setup_utm.py qcow2-snapshot /abs/disk.qcow2 --list` (or `--create NAME`, `--restore NAME`, `--delete NAME`) | `qemu-img snapshot`; VM stopped |
| `start-disposable` | `uv run scripts/setup_utm.py start-disposable "$VM"` | AppleScript `start … without saving` (same effect as `utmctl start --disposable`) |
| `guest-exec` | `uv run scripts/setup_utm.py guest-exec "$VM" cmd.exe --timeout 600 --args /c whoami` | AppleScript `execute … with output capturing`; returns exit code, stdout, stderr |
| `guest-push` | `uv run scripts/setup_utm.py guest-push "$VM" /abs/sample.bin 'C:\Users\Public\sample.bin'` | Guest agent |
| `guest-pull` | `uv run scripts/setup_utm.py guest-pull "$VM" 'C:\Users\Public\out.log' /abs/out/` | Guest agent |
| `send-input` | `uv run scripts/setup_utm.py send-input "$VM" --text "calc.exe"`; `--text r --modifiers command`; `--click 450 320 --button left` | AppleScript keystrokes/clicks into the VM window |
| `ida-server-info` | `uv run scripts/setup_utm.py ida-server-info --json` | Locates IDA `dbgsrv/` and prints guest setup templates |

`guest-exec`: `--timeout` (default 60 s) must come before `--args`. Everything after `--args` goes to the guest verbatim, including values starting with `-`. `send-input` needs macOS Automation permission for the terminal (System Settings > Privacy & Security > Automation).

---

## 6. Guest agent prerequisites

| Guest | Agent | Check |
|---|---|---|
| Linux (QEMU) | `sudo apt install qemu-guest-agent && sudo systemctl enable --now qemu-guest-agent` | `utmctl ip-address "$VM"` returns addresses |
| Windows ARM (QEMU) | UTM Guest Tools ISO (`utm-guest-tools`, includes qemu-ga and VirtIO/NetKVM drivers) | `utmctl exec "$VM" --cmd cmd.exe /c ver` exit code 0 |
| macOS / Linux (Apple backend) | None available | Use SSH; find the IP in `/var/db/dhcpd_leases` on the host |

The VM config must expose the agent channel (QEMU "Guest Agent"/SPICE agent enabled in UTM). Without it, `exec`, `file`, and `ip-address` hang or fail.

---

## 7. Networking

| Mode | Host → guest | Guest → Internet | Port forwarding | Use |
|---|---|---|---|---|
| Shared Network | Direct to guest IP (`192.168.64.0/24`) | Yes (NAT) | No | Trusted tooling guests; remote debugger to guest IP |
| Emulated VLAN | Only via forwards (`10.0.2.0/24`, host `10.0.2.2`) | Yes (QEMU user net) | Yes | Forward `127.0.0.1:23946→23946` (IDA), `127.0.0.1:2222→22` (SSH) |
| Host Only | Direct to guest IP | No | No | Malware detonation. Serve fake DNS/HTTP from the host (INetSim, fakedns, `mitmdump`) |
| Bridged | LAN IP | Via LAN | No | Never for samples |

Apple-backend VMs have only NAT (like Shared) and Bridged. Change network mode only with the VM stopped. "Isolate from host" on Shared blocks guest→host but leaves the Internet reachable; it is not containment.

---

## 8. Remote debugging in a guest

1. `uv run scripts/setup_utm.py ida-server-info --json` to find the matching server in `$IDA/dbgsrv/` (`win64_remote.exe`, `linux_server`, `armlinux_server`, `mac_server_arm`).
2. Push it: `utmctl file push "$VM" 'C:\Users\Public\win64_remote.exe' < "$IDA/dbgsrv/win64_remote.exe"`.
3. Start it in the guest: `win64_remote.exe -p23946 -P<password>`. 9.4 servers use TLS by default (`-c`/`-k` for your own cert, `-t` for plain TCP). Reach it at the guest IP (Shared/Host Only) or `127.0.0.1:23946` (Emulated VLAN forward).
4. Drive the session from IDA per [ida-mcp-remote-debugging.md](ida-mcp-remote-debugging.md) and [../05-environment/ida-remote-debugging.md](../05-environment/ida-remote-debugging.md).

Windows on ARM runs x64 binaries under emulation; debug them with `win64_remote.exe` inside the guest. ARM64 Windows targets need a native ARM64 debugger (WinDbg) instead.

---

## 9. Pitfalls

- **Snapshot of a running disk with `qemu-img`.** Corrupts the qcow2. Stop first, or use `utmctl snapshot`.
- **Restoring a disk-only snapshot while running.** Stop the VM first; a disk-only snapshot implies a cold boot.
- **Forgotten rollback.** Prefer `--disposable` or clone-per-run for detonation so a missed restore cannot leave a dirty baseline.
- **Base image edits.** Editing a qcow2 backing file invalidates every overlay built on it.
- **Suspended state confusion.** A suspended VM resumes into old RAM after you change disks. Run `utmctl discard-state "$VM"` before restoring disks out of band.
- **Name ambiguity.** Two VMs with similar names: use the UUID from `utmctl list`.
- **Apple backend expectations.** No guest agent, no qcow2. Plan SSH and APFS-clone workflows.
- **`delete` is immediate.** Double-check the identifier; there is no confirmation and no trash.
- **Automation permission.** AppleScript-based helpers fail with error -1743 until the terminal is allowed to control UTM.

---

## 10. Verification checklist

- `utmctl status "$VM"` reports the state you expect before every snapshot or disk operation.
- `utmctl snapshot list "$VM" --json` shows the baseline before detonation and after restore.
- After a run: the base VM is `stopped` and untouched (clone deleted, or snapshot restored, or disposable start used).
- Network mode in `config.plist` is Host Only before any unknown sample executes.
