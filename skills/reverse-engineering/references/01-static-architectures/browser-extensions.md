# Browser Extension Reverse Engineering

## When To Open
Open this file for a `.crx` (`Cr24`), an `.xpi`, a Safari `.appex`, an unpacked folder with `manifest.json`, or a profile `Extensions/` directory. JavaScript deobfuscation, bundle unpacking, source maps, JSVMP, and CDP script capture are in [browser-js-wasm.md](browser-js-wasm.md). Live hooking with the jshook MCP server is [jshook-mcp.md](../04-tool-usage/jshook-mcp.md).

## Order Of Work
1. **Acquire and hash.** Keep the original `.crx`/`.xpi`. Record SHA-256 and the version from the manifest.
2. **Parse the container.** CRX3 header, extension ID, signing proofs. Then the ZIP.
3. **Read the manifest before any JS.** Permissions, host permissions, background, content scripts, `externally_connectable`, `web_accessible_resources`, CSP, DNR rulesets, `update_url`.
4. **Map contexts and messages.** Who can send what to whom. That map is the attack surface and the data-flow graph.
5. **Read the privileged sinks.** `chrome.cookies`, `chrome.scripting.executeScript`, `chrome.tabs`, `chrome.webRequest`, `chrome.declarativeNetRequest.updateDynamicRules`, `fetch`, `chrome.runtime.connectNative`.
6. **Deobfuscate only where the sinks are.** See [browser-js-wasm.md](browser-js-wasm.md).
7. **Load it in a lab profile only after static analysis.** Section "Dynamic".

## Acquisition

```bash
# Chrome Web Store CRX (verified 2026-10 with uBlock Origin Lite). prodversion must be a recent Chrome version.
EXT_ID=ddkjiahejlhfcafbddmgiahcphecmpfh
curl -sSL -o "$EXT_ID.crx" \
  "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=140.0&acceptformat=crx2,crx3&x=id%3D${EXT_ID}%26uc"
file "$EXT_ID.crx"          # "Google Chrome extension, version 3"

# Firefox AMO XPI by slug (verified with ublock-origin).
SLUG=ublock-origin
curl -sSL -o "$SLUG.xpi" "https://addons.mozilla.org/firefox/downloads/latest/${SLUG}/latest.xpi"

# Edge Add-ons (format from Edge update service; not verified here).
curl -sSL -o "$EXT_ID.crx" \
  "https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&x=id%3D${EXT_ID}%26installsource%3Dondemand%26uc"
```

Installed extensions are already unpacked:

| Browser / OS | Path |
| :--- | :--- |
| Chrome macOS | `~/Library/Application Support/Google/Chrome/<Profile>/Extensions/<id>/<version>_0/` |
| Chrome Linux | `~/.config/google-chrome/<Profile>/Extensions/<id>/<version>_0/` |
| Chrome Windows | `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\Extensions\<id>\<version>_0\` |
| Chrome state (same profile) | `Local Extension Settings/<id>/` (LevelDB, `chrome.storage.local`), `Sync Extension Settings/`, `Managed Extension Settings/`, `DNR Extension Rules/`, `Extension Cookies` |
| Chrome policy installs | `Preferences` / `Secure Preferences` JSON, policy `ExtensionInstallForcelist` |
| Firefox | `<profile>/extensions/<gecko-id>.xpi`; storage in `<profile>/storage/default/moz-extension+++<uuid>/` |
| Safari | `<App>.app/Contents/PlugIns/<Name>.appex/Contents/Resources/` (manifest and JS) |

`<Profile>` is `Default`, `Profile 1`, and so on. Edge and Brave use the same layout under their own vendor directory.

## CRX Format
All integers are little-endian.

| Offset | CRX3 | CRX2 (legacy, rejected by current Chrome) |
| :--- | :--- | :--- |
| 0 | `Cr24` (`43 72 32 34`) | `Cr24` |
| 4 | `u32 version = 3` | `u32 version = 2` |
| 8 | `u32 header_size` | `u32 pubkey_len`, `u32 sig_len` |
| 12 | `CrxFileHeader` protobuf, `header_size` bytes | public key, then signature |
| 12 + header_size | ZIP archive | ZIP at `16 + pubkey_len + sig_len` |

`CrxFileHeader` (Chromium `components/crx_file/crx3.proto`):

| Field | Number | Content |
| :--- | :--- | :--- |
| `sha256_with_rsa` | 2 | repeated `AsymmetricKeyProof { public_key = 1 (X.509 SPKI DER); signature = 2 }` |
| `sha256_with_ecdsa` | 3 | repeated `AsymmetricKeyProof`, P-256 |
| `verified_contents` | 4 | gzip'd verified-contents JSON (optional) |
| `signed_header_data` | 10000 | bytes of `SignedData { crx_id = 1 (16 bytes) }` |

Signatures cover `"CRX3 SignedData\x00" + u32le(len(signed_header_data)) + signed_header_data + zip`.

- **Extension ID.** First 16 bytes of SHA-256 over the developer public key (DER SPKI), hex digits `0-f` mapped to `a-p`. It equals `crx_id`.
- **Several proofs is normal.** A Web Store CRX carries the developer RSA proof plus Web Store RSA and ECDSA proofs. Only one key hashes to `crx_id`. Verified on uBlock Origin Lite: three proofs, one matching.
- **The ZIP.** `unzip` accepts a CRX with a warning about extra leading bytes. Python `zipfile` accepts it too. A strict tool needs the slice from `12 + header_size`.
- **`_metadata/verified_contents.json`.** Web Store content hashes for each file. Chrome uses it to detect on-disk tampering ("This extension may have been corrupted").

Parser and extractor. Verified on a Web Store CRX3; stdlib only.

```python
# crx_unpack.py: uv run crx_unpack.py ext.crx [out_dir]
import hashlib, io, json, struct, sys, zipfile

def varint(b, i):
    v = s = 0
    while True:
        c = b[i]; i += 1; v |= (c & 0x7F) << s; s += 7
        if c < 0x80: return v, i

def fields(b):                      # minimal protobuf walker: (field_no, bytes) for length-delimited fields
    i = 0
    while i < len(b):
        key, i = varint(b, i)
        no, wt = key >> 3, key & 7
        if wt == 2:
            n, i = varint(b, i); yield no, b[i:i + n]; i += n
        elif wt == 0: _, i = varint(b, i)
        else: raise ValueError(f"wire type {wt}")

def ext_id(raw16):
    return "".join(chr(ord("a") + int(h, 16)) for h in raw16.hex())

data = open(sys.argv[1], "rb").read()
assert data[:4] == b"Cr24", "not a CRX"
ver = struct.unpack_from("<I", data, 4)[0]
if ver == 3:
    hlen = struct.unpack_from("<I", data, 8)[0]
    zip_off = 12 + hlen
    for no, val in fields(data[12:zip_off]):
        if no in (2, 3):
            key = dict(fields(val)).get(1, b"")
            print(f"proof {'rsa' if no == 2 else 'ecdsa'}: key-derived id {ext_id(hashlib.sha256(key).digest()[:16])}")
        elif no == 10000:
            print("signed crx_id:", ext_id(dict(fields(val))[1]))
elif ver == 2:
    klen, slen = struct.unpack_from("<II", data, 8)
    zip_off = 16 + klen + slen
    print("crx2 id:", ext_id(hashlib.sha256(data[16:16 + klen]).digest()[:16]))
else:
    sys.exit(f"unknown CRX version {ver}")
z = zipfile.ZipFile(io.BytesIO(data[zip_off:]))
m = json.loads(z.read("manifest.json").decode("utf-8-sig"))
print("zip at", hex(zip_off), "| files", len(z.namelist()), "| mv", m.get("manifest_version"), "|", m.get("name"), m.get("version"))
if len(sys.argv) > 2:
    z.extractall(sys.argv[2])       # zipfile strips ".." and absolute paths
```

`__MSG_extName__` in `name` means the string is in `_locales/<default_locale>/messages.json`.

## Firefox XPI And Safari
- **XPI** is a plain ZIP. AMO-signed packages contain `META-INF/manifest.mf`, `mozilla.sf`, `mozilla.rsa` (PKCS#7) and `cose.manifest`, `cose.sig`. Verified on the AMO uBlock Origin XPI.
- **ID** comes from `browser_specific_settings.gecko.id` (legacy key `applications.gecko.id`). Unsigned XPIs install only as temporary add-ons (`about:debugging`) or on Developer Edition, Nightly, and ESR with `xpinstall.signatures.required=false`.
- **Firefox MV3** uses `background.scripts` (event page), not a service worker. Firefox still supports MV2. Host permissions in Firefox MV3 are opt-in by the user.
- **Native messaging in Firefox** uses `allowed_extensions` (gecko IDs) in the host manifest instead of `allowed_origins`.
- **Safari Web Extensions** ship inside an app. JS and `manifest.json` are in the `.appex` `Resources/`. `browser.runtime.sendNativeMessage` goes to the app extension's `SafariWebExtensionHandler` (`NSExtensionRequestHandling`); reverse that Swift/ObjC code as a native target, see [mobile-ios.md](mobile-ios.md). Legacy `.safariextz` (xar) is obsolete.

## Manifest V2 And V3

| Area | MV2 | MV3 |
| :--- | :--- | :--- |
| Background | Persistent or event page (`background.scripts`/`page`) | Chrome: service worker (`background.service_worker`, optional `"type": "module"`). Firefox: event page. |
| Network | `webRequest` + `webRequestBlocking` can read and change requests | `declarativeNetRequest` rules. `webRequest` is observe-only; `webRequestBlocking` only for policy-installed extensions. |
| Remote code | `eval`, remote `<script>` allowed by a relaxed CSP | Remotely hosted code banned; extension-page CSP cannot allow `unsafe-eval` |
| Hosts | Inside `permissions` | Separate `host_permissions` |
| Injection | `tabs.executeScript` | `scripting.executeScript`, optional `world: "MAIN"` |
| Exposed files | `web_accessible_resources: ["a.png"]` | `[{resources, matches, extension_ids, use_dynamic_url}]` |

Chrome status: MV2 extensions are disabled for all users from Chrome 138. The `ExtensionManifestV2Availability` enterprise exemption ends in Chrome 139. Remaining MV2 items were removed from the Web Store by August 31, 2026. An MV2 CRX is now a legacy sample, an Edge/Firefox target, or an old install.

MV3 service worker lifetime (Chrome docs): stops after 30 s idle; an event or extension API call resets the timer (Chrome 110+); a single event or API call over 5 min, or a `fetch()` response slower than 30 s, terminates it. Native messaging ports (105+), long-lived ports (114+), WebSockets (116+), and debugger sessions (118+) keep it alive. Globals do not survive; state lives in `chrome.storage` or an offscreen document.

How MV3 malware runs server-controlled logic without remote code:
- Dynamic DNR rules from a server (`updateDynamicRules`): redirects, header stripping (`Content-Security-Policy`, `X-Frame-Options`), affiliate rewriting.
- `scripting.executeScript({world: "MAIN", func, args})` with server-supplied `args`, or a content script that writes server HTML into the DOM.
- `sandbox.pages` iframes may `eval`; the service worker passes code to them by `postMessage`.
- `chrome.userScripts` (developer-mode or "Allow User Scripts" toggle required).
- A JSVMP interpreter that runs a server-supplied bytecode string. See [browser-js-wasm.md](browser-js-wasm.md).
- Delayed activation: `chrome.alarms` plus a server flag, or a check of install age in `chrome.storage`.

## Permission Risk Table

| Permission / key | What it grants | Read next |
| :--- | :--- | :--- |
| `<all_urls>`, `*://*/*` in `host_permissions` or content-script `matches` | Read/modify every page; cookie and fetch access to all hosts | Every content script and every `fetch` in the worker |
| `cookies` (+ hosts) | Read session cookies, including `HttpOnly` | `cookies.getAll` callers and where results go |
| `scripting` (+ hosts) | Inject code into any matching tab | `executeScript` `func`/`files`/`world` |
| `debugger` | Full CDP on any tab: read network bodies, run JS | Every `chrome.debugger.sendCommand` |
| `nativeMessaging` | Talk to a local executable | Host manifest and binary (section below) |
| `webRequest` (+`webRequestBlocking` in MV2) | Observe (MV2: modify) all requests, including headers | Listener filters and `extraInfoSpec` (`requestHeaders`, `extraHeaders`) |
| `declarativeNetRequest`, `declarativeNetRequestWithHostAccess` | Block, redirect, rewrite headers | Static rulesets and `updateDynamicRules`/`updateSessionRules` |
| `tabs`, `history`, `topSites`, `webNavigation` | URLs and titles of browsing | What is sent off-device |
| `management` | List, disable, uninstall other extensions | Calls that disable security extensions |
| `proxy`, `privacy`, `contentSettings` | Route traffic, weaken settings | Proxy PAC strings and server hosts |
| `downloads`, `downloads.open` | Write and open files | URLs and file names |
| `clipboardRead`, `clipboardWrite` | Clipboard (crypto-address swap malware) | Offscreen document with `CLIPBOARD` reason |
| `identity`, `identity.email` | OAuth tokens, signed-in email | Token use and destination |
| `offscreen` | Hidden DOM document for the worker | `offscreen.createDocument` reasons |
| `externally_connectable` | Listed sites/extensions may message the worker | `onMessageExternal` / `onConnectExternal` handlers |
| `content_security_policy` | Relaxed CSP (MV2) | `unsafe-eval`, remote script hosts |
| `update_url` not Google's | Self-hosted updates outside the Web Store | That server and its update XML |

## Contexts And Messaging
Trust order, least to most: web page, content script, extension pages (popup, options, offscreen, sandbox), service worker / background, native host.

- **Content scripts** run in an isolated world. They share the DOM, not JS globals. They can use `runtime` (`sendMessage`, `connect`, `onMessage`, `getURL`, `id`, `getManifest`), `storage`, `i18n`, and `dom`. Everything else goes through a message to the worker. A content script with `"world": "MAIN"` has no `chrome.*` access and shares globals with the page.
- **Internal messaging.** `chrome.runtime.sendMessage(msg)` from a content script reaches `chrome.runtime.onMessage` in the worker with `sender.tab`, `sender.frameId`, `sender.url`, `sender.origin`. Worker to tab is `chrome.tabs.sendMessage(tabId, msg)`. Return `true` from the listener to keep `sendResponse` valid for an async reply.
- **The bug pattern.** A content script relays `window.postMessage` data to the worker without checking `event.source === window` and `event.origin`. The worker then acts on `msg.action` without checking `sender.url`/`sender.origin`. Any page can then drive the worker's privileges.
- **External messaging.** Without `externally_connectable`, other extensions can message the extension but web pages cannot. With it, only the listed `matches` (no `<all_urls>`; a second-level domain is required) and `ids` can. Pages call `chrome.runtime.sendMessage(EXT_ID, msg)`; the handler is `onMessageExternal`. Check `sender.origin` there too.
- **`web_accessible_resources`.** Listed files load in any matching page. They fingerprint the extension (`chrome-extension://<id>/file`) unless `use_dynamic_url` is set. An accessible HTML page that reads `location.hash` or `postMessage` is a page-reachable privileged context.
- **Extension pages** (`popup.html`, `options.html`) have full API access. `sandbox.pages` have none, but may `eval`.

## Native Messaging
1. Find the host name in `connectNative("<name>")` / `sendNativeMessage`.
2. Locate the host manifest:

| OS | Chrome location |
| :--- | :--- |
| macOS | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<name>.json`, system `/Library/Google/Chrome/NativeMessagingHosts/` |
| Linux | `~/.config/google-chrome/NativeMessagingHosts/<name>.json`, system `/etc/opt/chrome/native-messaging-hosts/` |
| Windows | Registry `HKCU\Software\Google\Chrome\NativeMessagingHosts\<name>` (or `HKLM`), default value is the manifest path |

3. Read `path` and `allowed_origins` (`chrome-extension://<id>/`). A wildcard or a missing origin check in the binary is a finding.
4. Framing: each message is UTF-8 JSON preceded by a 32-bit length in native byte order (little-endian on x86/ARM). Host-to-browser messages are capped at 1 MB; browser-to-host at 64 MiB. The browser starts the host with the caller origin as an argument (`chrome-extension://<id>/`), plus `--parent-window=<hwnd>` on Windows.
5. Reverse the host binary as a native target. Look for the `stdin` length read, the JSON dispatch on a command field, and `exec`/`CreateProcess`/file writes. See [native-cpp-abi.md](native-cpp-abi.md).

## Static Audit Commands

```bash
DIR=./ext_src
jq '{mv: .manifest_version, bg: .background, perms: .permissions, opt: .optional_permissions,
     hosts: (.host_permissions // []), cs: [.content_scripts[]? | {matches, js, world, all_frames, run_at}],
     ext: .externally_connectable, war: .web_accessible_resources, csp: .content_security_policy,
     dnr: .declarative_net_request, upd: .update_url, sandbox: .sandbox}' "$DIR/manifest.json"
# Privileged sinks and message handlers.
rg -n --no-heading -e 'chrome\.(cookies|scripting|debugger|management|proxy|declarativeNetRequest|webRequest|identity)' \
   -e 'onMessage(External)?\.addListener' -e 'connectNative|sendNativeMessage' \
   -e 'addEventListener\(\s*["'"'"']message' -e 'updateDynamicRules|executeScript' "$DIR"
# Remote endpoints after deobfuscation.
rg -o --no-filename -e 'https?://[^"'"'"' )]+' -e 'wss?://[^"'"'"' )]+' "$DIR" | sort | uniq -c | sort -rn | head -50
```

Obfuscated code hides `chrome.cookies.getAll` as `chrome[_0x1a(0x10)][_0x1a(0x11)]`. A grep over raw obfuscated files misses it. Deobfuscate first ([browser-js-wasm.md](browser-js-wasm.md), `webcrack` then the Babel script), then grep.

Compare versions. A clean extension that turns malicious after an ownership change differs in a few files. Diff two unpacked versions (`diff -r`, or `git diff --no-index`) before reading the whole tree.

## Malicious Shapes

| Shape | Static evidence |
| :--- | :--- |
| Session/cookie theft | `cookies.getAll({})` or `{domain}` loops, results batched into `fetch(..., {method:'POST'})` or `navigator.sendBeacon` |
| Search/affiliate hijack | `chrome_settings_overrides.search_provider`, DNR `redirect` rules with `regexSubstitution`, `tabs.onUpdated` rewriting URLs |
| Injected ads / scripts | Content scripts on `<all_urls>` that create `<script>`/`<iframe>` from server data; `executeScript` with `world: "MAIN"` |
| Credential capture | Content script listeners on `input[type=password]`, `form` submit, `keydown`; data relayed to the worker |
| Crypto-wallet / clipboard swap | Address regexes (`^0x[a-fA-F0-9]{40}$`, `bc1`), `offscreen` + clipboard, `document.execCommand('copy')` |
| Security-header stripping | DNR `modifyHeaders` removing `content-security-policy`, `x-frame-options` |
| Server-driven behavior | Config fetched at startup or on `chrome.alarms`, stored in `chrome.storage`, then interpreted (rule lists, selectors, URLs, VM bytecode) |
| Sleeper | Install-time check (`runtime.onInstalled` stores a date) and a delay before enabling the above |
| Anti-analysis | Disables itself when `chrome://extensions` or DevTools is open (`tabs.query` for those URLs), checks `management.getSelf().installType === 'development'` |

## Evidence To Record
- CRX/XPI SHA-256, extension ID and how it was derived, version, and the store or path it came from.
- The manifest summary: permissions, host permissions, content-script matches and worlds, external connectivity, web-accessible resources, CSP, update URL.
- The message map: each `onMessage`/`onMessageExternal`/`postMessage` handler, the actions it accepts, the sender checks it performs, and the privileged API it reaches.
- Every remote endpoint with the file and line that builds it, after deobfuscation.
- For dynamic claims: browser build, profile, and which hook produced the observation.

## Dynamic (When Execution Is Allowed)
Use a throwaway profile in the lab. Branded Chrome 137+ ignores `--load-extension`. Use Chromium, Chrome for Testing, Playwright's bundled Chromium, or "Load unpacked" on `chrome://extensions`.

- **DevTools.** `chrome://extensions` > Developer mode > the extension's "service worker" link opens the worker's DevTools. `chrome://serviceworker-internals` shows worker state. Content scripts appear in a page's Sources panel under "Content scripts" and in the console context dropdown.
- **CDP.** The worker is a target of type `service_worker` with URL `chrome-extension://<id>/...`. The script-capture technique in [browser-js-wasm.md](browser-js-wasm.md) works against that target.
- **The worker restarts.** Hooks installed by `evaluate` vanish after the 30 s idle stop. Re-install on each `serviceworker` event, or keep the worker alive with an open port during tracing.
- **jshook MCP.** Worker selection, content-script hooks, and request initiator tracing: [jshook-mcp.md](../04-tool-usage/jshook-mcp.md).

```javascript
// sw_trace.js: npm i playwright ; npx playwright install chromium ; node sw_trace.js ./ext_src
const { chromium } = require('playwright');
const path = require('path');
(async () => {
  const ext = path.resolve(process.argv[2]);
  const ctx = await chromium.launchPersistentContext('', {
    channel: 'chromium',                 // bundled Chromium; branded Chrome ignores --load-extension
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  const hook = async (sw) => {
    console.log('[sw]', sw.url());
    await sw.evaluate(() => {
      const f = self.fetch;
      self.fetch = function (...a) { console.log('[fetch]', String(a[0]), a[1]?.method || 'GET'); return f.apply(this, a); };
    });
  };
  ctx.serviceWorkers().forEach(hook);
  ctx.on('serviceworker', hook);         // fires again after each worker restart
  ctx.on('console', (m) => console.log('[console]', m.text()));   // includes worker console
  const page = await ctx.newPage();
  await page.goto(process.argv[3] || 'https://example.com');
  await page.waitForTimeout(15000);
  await ctx.close();
})();
```

Verified with Playwright 1.64.1 and its bundled Chromium 156 on a test MV3 extension: the hook fired and the worker's `[fetch]` line arrived through `ctx.on('console')`. A request also shows in the proxy log; see [network-traffic-proxy.md](../02-dynamic-instrumentation/network-traffic-proxy.md).

## Pitfalls
- A content script cannot call `chrome.cookies` or `chrome.tabs`. Find the message relay to the worker; that relay is the boundary.
- `sender.url` and `sender.origin` are set by the browser and trustworthy. Fields inside `message` are not.
- `externally_connectable` absent does not mean "no external callers". Other extensions can still message it.
- A matching `crx_id` proves who signed, not what the code does. Web Store review does not cover server-driven DNR rules or server data.
- `chrome.storage.local` content is LevelDB on disk. Read it with a LevelDB tool from a copy of the directory, not from the live profile.
- MV3 static rulesets are JSON files listed in `declarative_net_request.rule_resources`. Dynamic rules exist only at runtime (`DNR Extension Rules/` on disk).
- Do not run obfuscated extension code in host Node. Use the lab VM; `vm.createContext` is not a sandbox.
