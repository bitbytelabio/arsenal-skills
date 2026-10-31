# Linux VM Ansible Provisioning

Provision a Debian/Ubuntu, Fedora/RHEL, or Arch guest (UTM on macOS, KVM on Linux) over SSH with `ansible/playbook_linux.yml` and `ansible/linux_tools.json`. Run commands from the skill directory.

## Prerequisites

1. Guest: Ubuntu 22.04/24.04, Debian 12, Fedora 39+, or Arch. x86_64 or aarch64.
2. SSH in the guest: `sudo apt install -y openssh-server` (Debian/Ubuntu), `sudo dnf install -y openssh-server && sudo systemctl enable --now sshd` (Fedora). The user needs sudo.
3. Key auth: `ssh-copy-id -i ~/.ssh/id_ed25519.pub analyst@"$VM_IP"`.
4. Controller: `brew install ansible` or `uv tool install ansible-core`, then `uv run scripts/setup_vm.py deps --install` (installs `ansible.posix`, `community.general`, and the other collections).
5. Optional: `qemu-guest-agent` in the guest so `utmctl ip-address` and `setup_utm.py guest-*` work.

## Tool catalog (`ansible/linux_tools.json`)

| Catalog id | apt / dnf / pacman | Checked path |
|---|---|---|
| `osquery` | pkg.osquery.io repo (Debian/Ubuntu only) | `/usr/bin/osqueryi` |
| `tshark` | `tshark` / `wireshark-cli` / `wireshark-cli` | `/usr/bin/tshark` |
| `tcpdump` | `tcpdump` | `/usr/sbin/tcpdump` |
| `gdb`, `strace`, `ltrace`, `radare2`, `binwalk`, `yara`, `checksec`, `git`, `curl`, `unzip`, `nodejs`, `npm` | same name | `/usr/bin/<name>` (`r2` for radare2, `node` for nodejs) |
| `openjdk` | `openjdk-21-jdk` / `java-21-openjdk-devel` / `jdk21-openjdk` | `/usr/bin/java` |
| `upx` | `upx-ucl` / `upx` / `upx` | `/usr/bin/upx` |
| `python3` | `python3` / `python3` / `python` | `/usr/bin/python3` |
| `7zip` | `p7zip-full` / `p7zip` / `p7zip` | `/usr/bin/7z` |
| `uv` | Astral installer, symlinked to `/usr/local/bin/uv` | `/usr/local/bin/uv` |
| `ghidra` | Latest GitHub release zip into `/opt/ghidra_<ver>_PUBLIC`, link `/opt/ghidra` | `/opt/ghidra/ghidraRun` |
| `ida_dbgsrv` | Copied from the host IDA install | `/opt/ida_dbgsrv` |
| `computer-use-mcp` | `npm install -g @zavora-ai/computer-use-mcp` | `/usr/local/bin/computer-use-mcp` |

23 entries, all enabled. `uv run scripts/setup_vm.py list --os linux` prints the live state.

## Workflow

```bash
VM_IP=192.168.64.20

# 1. Inventory -> ansible/inventory_linux.ini
uv run scripts/setup_vm.py generate-inventory --os linux \
  --host "$VM_IP" --user analyst --key-file ~/.ssh/id_ed25519
# password auth (needs sshpass on the controller):
#   --password "$PASS" --become-password "$PASS"
# UTM Emulated VLAN with host 2222 -> guest 22:
#   --host 127.0.0.1 --port 2222

# 2. Connectivity and sudo
ansible linux_vms -i ansible/inventory_linux.ini -m ping
ansible linux_vms -i ansible/inventory_linux.ini -b -m command -a id

# 3. Provision
uv run scripts/setup_vm.py run-playbook --os linux --check
uv run scripts/setup_vm.py run-playbook --os linux -v
```

Omit `--become-password` only when the user has NOPASSWD sudo.

Play order:
1. `kernel.yama.ptrace_scope=0` (persistent sysctl) so gdb, strace, and IDA can attach.
2. Create `/opt/ida_dbgsrv`; copy `armlinux_server`, `armlinux_server32` (aarch64) or `linux_server`, `linux_server32` (x86_64) from `ida_dbgsrv_src`. `run-playbook` fills that from `$IDA_DBGSRV`, `$IDADIR`, or `/Applications/IDA*.app`. Otherwise it prints "IDA debug servers NOT copied".
3. Firewall: allow TCP 23946 and 4517 in UFW (Debian family) or firewalld (RedHat family). Arch gets no firewall change.
4. Packages: refresh the apt index, ask the index which catalog names exist (`apt-cache show`, `dnf info`, `pacman -Si`), install those in one call, and report the rest as "Not in the package index, skipped".
5. `uv` via `https://astral.sh/uv/install.sh`, linked into `/usr/local/bin`.
6. osquery (Debian/Ubuntu): key to `/etc/apt/keyrings/osquery.gpg` (dearmored), repo line with `signed-by=/etc/apt/keyrings/osquery.gpg`, `apt install osquery`. Not installed on Fedora/Arch.
7. Ghidra: latest `ghidra_*_PUBLIC_*.zip` from the GitHub API into `/opt`, `/opt/ghidra` symlink.
8. `npm install -g @zavora-ai/computer-use-mcp`. The play installs it but does not start a server.
9. `/etc/osquery/osquery.conf` (if absent), `osqueryd` enabled and started.
10. `stat` every catalog `binary_path`, print `found` and `missing`.

Verified on Ubuntu 24.04 ARM64 under UTM: `failed=0`, all enabled tools found.

## UTM networking

- Shared Network: guest gets `192.168.64.x`; connect to it directly. No port forwarding.
- Emulated VLAN: forward host `127.0.0.1:2222` → guest 22 (and 23946, 4517 as needed), then use `--host 127.0.0.1 --port 2222`.
- Ubuntu cloud images have only a serial console. The UTM window shows "Display output is not active". Use SSH or `utmctl attach "$VM"`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Guest has no IPv4 on UTM Shared Network | Cloud-init netplan matches a different NIC name, or no DHCP answer from vmnet (seen with Ubuntu cloud image on UTM 5) | In guest: `ip link`; fix the `match`/name in `/etc/netplan/50-cloud-init.yaml`, `sudo netplan apply`. Or switch the NIC to Emulated VLAN and forward SSH |
| `utmctl ip-address` fails | No guest agent | `sudo apt install -y qemu-guest-agent && sudo systemctl enable --now qemu-guest-agent` |
| `UNREACHABLE ... Permission denied (publickey)` | Key not in `~/.ssh/authorized_keys` | `ssh-copy-id`; check the `--key-file` path |
| `to use the 'ssh' connection type with passwords ... install the sshpass program` | Password auth without sshpass | `brew install sshpass`, or switch to keys |
| `Missing sudo password` | No `--become-password`, no NOPASSWD | Regenerate inventory with `--become-password` |
| `couldn't resolve module/action 'ansible.posix.sysctl'` / `community.general.ufw` | Collections missing | `uv run scripts/setup_vm.py deps --install` |
| `NO_PUBKEY` / `The following signatures couldn't be verified` for pkg.osquery.io | Old ASCII key in `trusted.gpg.d`, no `signed-by` | The play removes `/etc/apt/trusted.gpg.d/osquery.gpg` and `/etc/apt/sources.list.d/osquery.list` and writes a dearmored key with `signed-by`. Rerun |
| `Could not get lock /var/lib/dpkg/lock-frontend` | `unattended-upgrades` running on first boot | Wait, or `sudo systemctl stop unattended-upgrades` and rerun |
| Package listed under "Not in the package index, skipped" | Name missing on this release (e.g. `checksec` on older Debian, `ltrace` on some aarch64 repos) | Expected. Install from upstream if needed |
| Ghidra task fails with HTTP 403 | GitHub API rate limit | Rerun later, or download the zip and unpack to `/opt` |
| `gdb`: `ptrace: Operation not permitted` | `ptrace_scope` not applied (container/WSL kernel) | `sudo sysctl -w kernel.yama.ptrace_scope=0`; run as root |
| UFW rule added but port still blocked | UFW inactive is fine; cloud security group or another firewall is not | `sudo ufw status`; `sudo iptables -S` |

## IDA remote debugging

```bash
ssh analyst@"$VM_IP" /opt/ida_dbgsrv/armlinux_server -p23946   # linux_server on x86_64
```

To copy by hand:

```bash
DBGSRV="$(ls -d /Applications/IDA*.app/Contents/MacOS/dbgsrv | tail -n1)"
scp "$DBGSRV/armlinux_server" analyst@"$VM_IP":/tmp/
ssh analyst@"$VM_IP" 'sudo install -m 0755 /tmp/armlinux_server /opt/ida_dbgsrv/'
```

In IDA: **Debugger > Select debugger... > Remote ARM Linux/Android debugger** (aarch64) or **Remote Linux debugger** (x86_64); **Process options**: Hostname `$VM_IP`, Port `23946`. More: [ida-remote-debugging.md](ida-remote-debugging.md).

## Computer Use MCP

The play installs `@zavora-ai/computer-use-mcp` but starts nothing. Start it inside the guest's graphical session (a cloud image has none), then generate the client snippet:

```bash
uv run scripts/setup_vm.py mcp-client-config --os linux --host "$VM_IP"
```

Give the JSON to the parent. Do not rewrite `mcp.json` yourself.
