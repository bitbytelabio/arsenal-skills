# macOS VM Ansible Provisioning

Provision a macOS guest on an Apple Silicon host (UTM, Apple Virtualization backend, IPSW install) over SSH with `ansible/playbook_macos.yml` and `ansible/macos_tools.json`. Run commands from the skill directory.

## Constraints

- macOS guests on Apple Silicon run only on a macOS host, through Virtualization.framework. UTM installs them from an IPSW (`UniversalMac_*_Restore.ipsw`).
- Apple-backend VMs have no QEMU guest agent. `utmctl exec`, `utmctl file`, `utmctl ip-address`, and `setup_utm.py guest-*` do not work. Use SSH.
- Snapshots of Apple-backend VMs need UTM 5.0.7+ on a macOS 27 host, with the VM stopped.

## Guest preparation

Option A, macOS 27 host and guest (UTM provisioning on first boot):

```bash
VM="macOS-RE-Lab"
printf '%s' "$PASS" | utmctl start "$VM" --provision-username analyst \
  --provision-password-stdin --provision-auto-login --provision-ssh
```

Option B, by hand in the guest:
1. Finish Setup Assistant.
2. Enable Remote Login: **System Settings > General > Sharing > Remote Login**, or `sudo systemsetup -setremotelogin on` (needs Full Disk Access for Terminal on recent macOS).
3. Turn on automatic login for the user. The Homebrew pkg assigns `/opt/homebrew` to the console user.

Find the guest IP: in the guest `ipconfig getifaddr en0`; on the host `grep -A2 "name=<guest-hostname>" /var/db/dhcpd_leases` (entries carry the guest hostname, not the UTM name; Apple NAT uses `192.168.64.0/24`).

Then copy your key: `ssh-copy-id -i ~/.ssh/id_ed25519.pub analyst@"$VM_IP"`.

## Tool catalog (`ansible/macos_tools.json`)

| Catalog id | Homebrew | Checked path |
|---|---|---|
| `osquery` | cask `osquery` | `/usr/local/bin/osqueryi` |
| `tshark` | formula `wireshark` | `/opt/homebrew/bin/tshark` |
| `radare2` | formula `radare2` | `/opt/homebrew/bin/r2` |
| `node` | formula `node` (npm for computer-use-mcp) | `/opt/homebrew/bin/npm` |
| `ghidra` | formula `ghidra` (pulls openjdk; the cask was removed) | `/opt/homebrew/bin/ghidraRun` |
| `binwalk`, `yara`, `git`, `uv` | formula, same name | `/opt/homebrew/bin/<name>` |
| `ipsw` | formula `blacktop/tap/ipsw` | `/opt/homebrew/bin/ipsw` |
| `jtool2` | cask `excitedplus1s/repo/jtool2` | `/opt/homebrew/bin/jtool2` |
| `python3` | formula `python@3.12` | `/opt/homebrew/opt/python@3.12/bin/python3.12` |
| `p7zip` | formula `sevenzip` (binary `7zz`) | `/opt/homebrew/bin/7zz` |
| `curl` | formula `curl` (keg-only) | `/opt/homebrew/opt/curl/bin/curl` |
| `ida_dbgsrv` | copied from the host IDA install | `/opt/ida_dbgsrv` |
| `computer-use-mcp` | `npm install -g @zavora-ai/computer-use-mcp` | `/opt/homebrew/bin/computer-use-mcp` |

16 entries, all enabled. `uv run scripts/setup_vm.py list --os macos` prints the live state.

## Workflow

```bash
VM_IP=192.168.64.30

# 1. Inventory -> ansible/inventory_macos.ini
uv run scripts/setup_vm.py generate-inventory --os macos \
  --host "$VM_IP" --user analyst --key-file ~/.ssh/id_ed25519 \
  --become-password "$PASS"
# password SSH instead of a key: --password "$PASS" (needs sshpass on the controller)

# 2. Connectivity. Before CLT exists, /usr/bin/python3 is a stub, so use raw:
ansible macos_vms -i ansible/inventory_macos.ini -m raw -a 'sw_vers'

# 3. Provision
uv run scripts/setup_vm.py run-playbook --os macos -v
```

The inventory sets `ansible_become=false`; tasks that need root use `become: true` one by one. They need `--become-password` unless the user has NOPASSWD sudo.

Play order:
0. Bootstrap play, `gather_facts: false`: if `/Library/Developer/CommandLineTools/usr/bin/python3` is missing, touch `/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress`, pick the newest `Command Line Tools` label from `softwareupdate --list`, `softwareupdate --install` it (2 retries, 30 s apart), `xcode-select --switch /Library/Developer/CommandLineTools`.
1. Create `/opt/ida_dbgsrv` owned by the user; copy `mac_server_arm` (arm64) or `mac_server` from `ida_dbgsrv_src` (`run-playbook` fills it from `$IDA_DBGSRV`, `$IDADIR`, or `/Applications/IDA*.app`). `DevToolsSecurity -enable`.
2. PF anchor `/etc/pf.anchors/com.re.tools` passing TCP 23946 and 4517, referenced from `/etc/pf.conf`, loaded with `pfctl -a com.re.tools -f`. PF is not enabled (`pfctl -e`) by the play; macOS ships with PF off, so this only matters if you enable it.
3. Temporary `/etc/sudoers.d/zz-ansible-homebrew` NOPASSWD rule (removed in an `always` block). The Homebrew installer and pkg casks call sudo without a TTY.
4. Homebrew from the signed `Homebrew.pkg` release (curl with retries, `pkgutil --check-signature`), falling back to `install.sh` (2 retries). `eval "$(/opt/homebrew/bin/brew shellenv)"` goes into `~/.zprofile`.
5. Tap third-party repos (`blacktop/tap`, `excitedplus1s/repo`) and `brew trust` each one.
6. Install each formula and cask on its own, so one failure does not skip the rest. Then `npm install -g @zavora-ai/computer-use-mcp`.
7. Stage `/var/osquery/osquery.conf` if absent. The play does not load the `io.osquery.osqueryd` daemon.
8. `stat` every catalog `binary_path`, print `found` and `missing`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Fact gathering fails: `xcrun: error: invalid active developer path` or python3 install prompt | No Command Line Tools; `/usr/bin/python3` is a stub | The bootstrap play installs CLT. If it fails, run in the guest: `touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress; softwareupdate --list` and install the listed label |
| `no Command Line Tools label in softwareupdate --list` | Apple catalog unreachable or no CLT for this beta OS | Check guest internet; retry; for beta guests install CLT `.dmg` from developer.apple.com |
| `Missing sudo password` / `sudo: a password is required` | No `--become-password` | Regenerate the inventory with `--become-password` |
| `install.sh` fails with `Connection reset by peer` on `git fetch` | Flaky git over the VM NAT | The play uses the signed pkg first; rerun |
| `/opt/homebrew` owned by root or another user | Homebrew pkg installed while nobody was logged in at the console | Enable automatic login, log in, `sudo chown -R analyst:admin /opt/homebrew`, rerun |
| `Error: Refusing to load ... from untrusted tap` | Homebrew 7 requires trusted third-party taps | `brew trust blacktop/tap` and `brew trust excitedplus1s/repo` (the play does this) |
| `jtool2` missing after the run | It is a cask in `excitedplus1s/repo`, not a formula | `brew install --cask excitedplus1s/repo/jtool2` |
| osquery cask hangs or fails | pkg cask needs sudo without TTY | The temporary sudoers rule covers it; rerun with `--become-password` |
| `osqueryi` works, `osqueryd` not running | Play only stages the config | `sudo osqueryctl start` (or load `/Library/LaunchDaemons/io.osquery.agent.plist`) |
| `mac_server_arm` cannot attach to a process | SIP protects hardened/platform binaries; debugger not authorized | Run the server with sudo; `DevToolsSecurity -enable`; for system targets disable SIP in guest Recovery |
| Host cannot reach 23946/4517 | macOS Application Firewall in the guest | `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /opt/ida_dbgsrv/mac_server_arm` and `--unblockapp` it |
| `utmctl ip-address` fails | Apple backend has no guest agent | Use `/var/db/dhcpd_leases` or `ipconfig getifaddr en0` in the guest |

## IDA remote debugging

```bash
ssh analyst@"$VM_IP" 'sudo /opt/ida_dbgsrv/mac_server_arm -p23946'
```

To copy by hand:

```bash
DBGSRV="$(ls -d /Applications/IDA*.app/Contents/MacOS/dbgsrv | tail -n1)"
scp "$DBGSRV/mac_server_arm" analyst@"$VM_IP":/opt/ida_dbgsrv/
ssh analyst@"$VM_IP" chmod +x /opt/ida_dbgsrv/mac_server_arm
```

`mac_server_arme` is the arm64e build. In IDA: **Debugger > Select debugger... > Remote ARM Mac OS debugger** (`mac_server` on Intel: **Remote Mac OS X debugger**); **Process options**: Hostname `$VM_IP`, Port `23946`. More: [ida-remote-debugging.md](ida-remote-debugging.md).

## Computer Use MCP

The play installs `@zavora-ai/computer-use-mcp` but starts nothing. Start it in the guest's logged-in GUI session and grant it Screen Recording and Accessibility in System Settings > Privacy & Security. Then:

```bash
uv run scripts/setup_vm.py mcp-client-config --os macos --host "$VM_IP"
```

Give the JSON to the parent. Do not rewrite `mcp.json` yourself.
