# Apple Firmware with `ipsw` (blacktop/ipsw)

- **Domain**: Apple iOS, iPadOS, and macOS firmware: IPSW/OTA acquisition, kernelcache extraction and analysis, dyld shared cache (DSC) symbol lookup and dylib extraction, Mach-O metadata, Objective-C/Swift headers, entitlements, and version diffing.
- **Scope**: end-to-end pipelines, verified subcommands and flags, IDA/Ghidra hand-off, pitfalls.
- **Verified**: run against `ipsw` 3.1.740 on macOS 27 (arm64): `download ipsw --urls/--kernel`, `info`, `extract --kernel --device`, `kernel version/kexts/extract/syscall/cpp/mig`, `dyld info/symaddr/a2s/extract`, `macho info --ent --arch`, `class-dump --headers`, `swift-dump --demangle`. `diff`, `extract --dyld` on a full iOS IPSW, `symbolicate`, and `kernel symbolicate` were checked against `--help` only.
- **Related**: iOS app-level work is in [../01-static-architectures/mobile-ios.md](../01-static-architectures/mobile-ios.md). The rooted virtual iPhone (`vphone-cli`) is in [../05-environment/host-and-lab-setup.md](../05-environment/host-and-lab-setup.md) section 5.

---

## 1. Install and orient

```bash
brew install blacktop/tap/ipsw
ipsw version
ipsw <command> --help          # flags change between releases; check before scripting
```

| Artifact | Where it lives | `ipsw` entry point |
|---|---|---|
| Kernelcache (IM4P, LZFSE/LZSS, Mach-O FILESET inside) | IPSW zip root (`kernelcache.release.<board>`) | `extract --kernel`, `download ipsw --kernel` |
| dyld shared cache | iOS 16+/macOS 13+: in a Cryptex DMG inside the IPSW; macOS host: `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e` (+ `.01`… subcaches) | `extract --dyld`, `dyld …` |
| Root filesystem (daemons, plists) | `fs`/`sys` DMG (AEA-encrypted on recent builds) | `extract --files --pattern`, `mount fs` |
| DeviceTree, iBoot, SEP, SPTM/TXM | IM4P files in the IPSW | `extract --dtree/--iboot/--sep/--sptm`, `dtree`, `img4 im4p extract` |

Decision table:

| Goal | Fastest route |
|---|---|
| Kernel of the newest build for one device | `ipsw download ipsw --device <id> --latest --kernel` (remote partial extract, no full download) |
| Kernel or DSC from an IPSW you already have | `ipsw extract --kernel/--dyld --device <id> <ipsw>` |
| One framework for IDA/Ghidra | `ipsw dyld extract <DSC> <dylib path> --objc --stubs -o <dir>` |
| Address in a crash/panic | `ipsw dyld a2s` (userland), `ipsw kernel symbolicate --lookup` (kernel), `ipsw symbolicate <.ips>` |
| What changed between two builds | `ipsw diff old.ipsw new.ipsw --markdown -o <dir>` |
| Who holds an entitlement | `ipsw ent --sqlite ents.db --ipsw <ipsw>` then `--key` / `--value` |

---

## 2. Acquire firmware

```bash
ipsw download ipsw --show-latest-version --device iPhone17,1        # 27.2
ipsw download ipsw --show-latest-build --device iPhone17,1          # 24B119
ipsw download ipsw --device iPhone17,1 --latest --urls              # print CDN URL only
ipsw download ipsw --device iPhone17,1 --build 24B119 -o ~/fw -y    # full IPSW
ipsw download ipsw --device iPhone17,1 --latest --kernel -o ~/fw -y # kernelcache only (remote zip ranges)
ipsw download ipsw --device iPhone17,1 --latest --dyld -a arm64e -o ~/fw -y   # DSC only
ipsw download appledb --os iOS --version '26.1' --device iPhone17,1 --kernel  # betas and older builds
ipsw download ota --help                                              # OTAs (AEA keys needed for newer ones)
ipsw download kdk --help                                              # Kernel Debug Kits (symbols for macOS kernels)
```

Remote `--kernel` extraction fetched a 27.2 kernelcache in about 15 s. Outputs land in `<out>/<build>__<device>/`.

---

## 3. Inspect an IPSW

```bash
ipsw info iPhone17,1_27.2_24B119_Restore.ipsw          # version, build, DMGs, per-device kernelcache names
ipsw info --list UniversalMac_27.0.1_26A434_Restore.ipsw | grep kernelcache
ipsw info --json <ipsw> > info.json
ipsw extract --sys-ver <ipsw>                          # SystemVersion.plist
```

Universal macOS IPSWs carry many kernelcaches and several SystemOS DMGs. Pass `--device <product type or board>` (for example `--device VirtualMac2,1` or `--device Mac16,1`) to pick one.

---

## 4. Kernelcache pipeline

```bash
IPSW=UniversalMac_27.0.1_26A434_Restore.ipsw
ipsw extract --kernel --device VirtualMac2,1 -o kc "$IPSW"
K=kc/26A434__VirtualMac2,1/kernelcache.release.VirtualMac2,1
file "$K"                                  # Mach-O 64-bit arm64e: already decompressed
ipsw kernel version "$K"                   # Darwin version + xnu build tag
ipsw kernel kexts "$K" | head              # bundle ids (--json for machine output)
ipsw kernel extract "$K" com.apple.driver.AppleMobileFileIntegrity -o kexts
ipsw kernel extract "$K" --all -o kexts    # every kext as a standalone Mach-O
ipsw macho info "$K" --loads | head        # FILESET load commands
```

`extract --kernel` already unwraps IM4P and decompresses. Use `ipsw kernel dec <im4p> -o <out>` only for a raw `kernelcache.release.*` pulled from the zip by hand.

Recover structure from a stripped kernel:

| Command | Output |
|---|---|
| `ipsw kernel syscall "$K"` | BSD syscall table: number, handler address, prototype |
| `ipsw kernel mig "$K"` | MIG subsystems and `_X…` routine addresses |
| `ipsw kernel mach "$K"` | Mach trap table |
| `ipsw kernel cpp "$K" [-c Class] [-i] [--json]` | IOKit C++ classes: size, parent, metaclass, vtable address |
| `ipsw kernel symbolsets "$K"` | Exported symbol sets per kext |
| `ipsw kernel symbolicate "$K" --signatures <sigs> --json` | Symbol map from signature files (blacktop/symbolicator); `--lookup 0xfffffe…` for one address |
| `ipsw kernel ctfdump` / `ipsw kernel dwarf` | Types from CTF or a KDK DWARF kernel |

Feed these into IDA: name syscall handlers and MIG routines from the tables, then set vtables from `kernel cpp` output. IDA 9.x loads FILESET kernelcaches natively (choose the full fileset or single kexts at load time). `ipsw kernel ida` (marked WIP) automates IDA loading; prefer IDA's loader plus scripted naming ([ida-pro.md](ida-pro.md) section 7).

---

## 5. dyld shared cache

```bash
DSC=/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e   # macOS host
ipsw extract --dyld -a arm64e -o dsc <ipsw>                 # from an IPSW (iOS: arm64e)
ipsw dyld info "$DSC"                                       # header, platform, subcaches, image count
ipsw dyld info --dylibs "$DSC" | grep -i security
```

Pass the main cache file (no `.01` suffix). `ipsw` finds the subcaches next to it.

### 5.1 Symbols and addresses

```bash
ipsw dyld symaddr "$DSC" _SecItemCopyMatching --image Security    # 0x1845c0c70 ... Security
ipsw dyld a2s "$DSC" 0x1845c0c70 --image                          # address -> symbol + image/section
ipsw dyld a2s "$DSC" 0x1845c0c70 --slide 0x1a2c000                # crash address with runtime slide
ipsw dyld a2f "$DSC" 0x1845c0c70                                  # containing function
ipsw dyld str "$DSC" "com.apple.private.security"                 # fast byte search for a string
ipsw dyld disass "$DSC" --symbol _SecItemCopyMatching --symbol-image Security
ipsw dyld imports "$DSC" Security                                 # which images load this dylib
ipsw dyld objc --help                                             # ObjC optimization tables
```

Addresses printed by `symaddr`/`a2s` are unslid cache addresses. Subtract the runtime slide from crash addresses or pass `--slide`.

### 5.2 Extract a framework for IDA/Ghidra

```bash
ipsw dyld extract "$DSC" /System/Library/Frameworks/Security.framework/Versions/A/Security \
  -o out --objc --stubs        # --objc adds ObjC metadata to the symtab and implies --slide
ipsw dyld extract "$DSC" --all -o out_all                       # every image (slow, large)
ipsw dyld split "$DSC" -o split_dir                             # Xcode dsc_extractor, macOS only
```

Use the full install path of the image (`/System/Library/Frameworks/X.framework/Versions/A/X` on macOS, `/System/Library/Frameworks/X.framework/X` on iOS). Extracted dylibs still reference other cache images by address. For cross-image calls, load the whole DSC in IDA (it has a native DSC loader that adds modules on demand) instead of a single extracted dylib.

---

## 6. Mach-O metadata, headers, entitlements

```bash
ipsw macho info /usr/libexec/amfid --arch arm64e --ent         # entitlements plist
ipsw macho info <macho> --loads --sig                          # load commands + code signature
ipsw macho info <macho> --objc --swift --demangle              # ObjC/Swift metadata
ipsw macho info <macho> --starts --json > starts.json          # function starts for an untagged disassembler
ipsw macho info <macho> --fixups                               # chained fixups
ipsw macho info <kernelcache> --fileset-entry com.apple.kernel --extract-fileset-entry --output kern
```

`macho info` takes one Mach-O, `.app`, or `.ipa`, not a directory. Loop in the shell for many files. Universal binaries need `--arch` when stdout is not a terminal (agents always hit this).

Headers:

```bash
ipsw class-dump "$DSC" /System/Library/Frameworks/Security.framework/Versions/A/Security --headers -o hdr
ipsw class-dump <macho> --class 'NSXPC.*' --re                 # one class regex, with addresses
ipsw class-dump <new_DSC> <dylib> --diff <old_DSC>              # ObjC API delta between builds
ipsw swift-dump "$DSC" /System/Library/Frameworks/CryptoKit.framework/Versions/A/CryptoKit --demangle
ipsw swift-dump <macho> --type 'Foo.*' --demangle
```

Entitlement database across a whole firmware:

```bash
ipsw ent --sqlite ents.db --ipsw iPhone17,1_27.2_24B119_Restore.ipsw
ipsw ent --sqlite ents.db --key com.apple.private.security.no-sandbox
ipsw ent --sqlite ents.db --value LockdownMode
ipsw ent --sqlite ents.db --file WebContent
```

Device tree and other firmware:

```bash
ipsw dtree <ipsw> --summary          # parse DeviceTree straight from the IPSW
ipsw extract --dtree -o dt <ipsw>
ipsw img4 im4p extract --output payload.bin <file.im4p>
ipsw mount fs <ipsw>                 # read-only mount of the filesystem DMG (macOS)
ipsw extract --files --pattern '.*LaunchDaemons.*\.plist$' -o fs <ipsw>
```

---

## 7. Crash and panic symbolication

```bash
ipsw symbolicate panic-full-2026-10-01-120000.000.ips iPhone17,1_27.2_24B119_Restore.ipsw
ipsw symbolicate <crash.ips>                     # falls back to Xcode DeviceSupport DSC (userland only)
ipsw symbolicate <panic.ips> <ipsw> --peek       # disassembly around panic frames
```

Kernel frames need the IPSW (or a symbol server). Userland frames need the DSC of the exact build.

---

## 8. Diff two builds (patch analysis)

```bash
ipsw diff old.ipsw new.ipsw --device iPhone17,1 --markdown -o diff_27.1_27.2
ipsw diff old.ipsw new.ipsw --ent --launchd --fw --strs --starts --markdown -o diff_full
ipsw diff old.ipsw new.ipsw --kdk <old KDK kernel> --kdk <new KDK kernel> -o diff_kdk   # macOS with KDKs
ipsw kernel kexts --diff old_kc new_kc              # kext version delta only
ipsw dyld info --dylibs --diff old_DSC new_DSC      # image version delta only
```

Read the Markdown report for changed kexts and dylibs, then pull both versions of each changed binary (`kernel extract` / `dyld extract`) and diff them in BinDiff or Diaphora ([../03-objectives/vuln-research-patch.md](../03-objectives/vuln-research-patch.md)). `--strs` (cstring changes) and `--starts` (function count changes) point at patched functions fast. Diff results are cached under `~/Library/Caches/ipsw/diffs`; `--clean` resets a pair.

---

## 9. End-to-end: patched kext between two iOS builds

```bash
D=iPhone17,1
ipsw download ipsw --device $D --build 24A335 --kernel -o fw -y
ipsw download ipsw --device $D --build 24B119 --kernel -o fw -y
OLD=fw/24A335__$D/kernelcache.release.$D; NEW=fw/24B119__$D/kernelcache.release.$D
ipsw kernel kexts --diff "$OLD" "$NEW"
for k in "$OLD" "$NEW"; do ipsw kernel extract "$k" com.apple.driver.AppleMobileFileIntegrity -o "$(dirname "$k")/kexts"; done
ipsw kernel syscall "$NEW" > syscalls_new.txt
# load both extracted kexts in IDA, export, BinDiff
```

Build numbers above are examples. Get real ones with `--show-latest-build` or `ipsw download appledb --os iOS --device $D --json`.

---

## 10. Pitfalls

- **Universal binaries in non-TTY.** `macho info` fails with `pass --arch (arm64e, arm64e_x1)`. Always pass `--arch`.
- **Wrong kernelcache in universal macOS IPSWs.** Without `--device`, you may get every board's kernel or the wrong one. Match the board to the target Mac or to `VirtualMac2,1` for VMs.
- **AEA-encrypted DMGs.** Recent `fs`/`sys` DMGs end in `.dmg.aea`. `ipsw` fetches keys when available; otherwise supply `--pem-db` or `--key-db`. Kernelcache extraction does not need them.
- **Decrypting modern kernelcaches.** A9+ kernelcaches are not encrypted, only compressed. Do not look for AES keys.
- **arm64e PAC.** Device code is arm64e. Pointers in data carry PAC bits; IDA/Ghidra strip them when the loader knows the format. Simulator builds are x86_64/arm64 macOS code and say nothing about device behavior.
- **Unslid vs slid addresses.** DSC and kernelcache tools print unslid addresses. Crash logs and live memory are slid.
- **Extracted dylib is not self-contained.** Calls into other cache images resolve to stubs. Use `--stubs`, or load the full DSC.
- **Version drift.** Commands marked 🚧 in `--help` (`swift-dump --interface`, `kernel ida`, `dyld xref`) are work in progress. Verify output before relying on it.

---

## 11. Verification checklist

- `file` on extracted kernelcache/dylib reports `Mach-O 64-bit arm64e` (not `data`).
- `ipsw kernel version` matches the build you meant to analyze.
- A known exported symbol resolves both ways: `dyld symaddr` gives an address, `dyld a2s` on it returns the same name.
- Diff reports name the same build pair you downloaded (check the report header).
