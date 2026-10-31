# Network Traffic Interception with mitmproxy

## Purpose

Use this reference to put an authorized client's traffic through `mitmproxy` and read it. The client can be a desktop app, a CLI tool, an Electron or Java app, a process in a lab VM or container, or a mobile app. The steps are: pick a capture mode, make the client trust the proxy CA, defeat pinning only if it rejects that CA, then turn the decrypted flows into an API map or a protocol state machine. Frida hook scripts are in [`frida.md`](../04-tool-usage/frida.md). Flutter's BoringSSL verifier is in [`flutter-dart.md`](../01-static-architectures/flutter-dart.md). Binary framing, protobuf, and gRPC wire layout are in [`protocol-recovery.md`](../03-objectives/protocol-recovery.md).

## Choose the capture mode

Pick the mode from how the client finds the network. Do not start with a pinning bypass.

| Client | Mode | Command | Note |
|---|---|---|---|
| Honors `HTTP(S)_PROXY` or the OS proxy setting | `regular` (default) | `mitmdump -p 8080` | Set the proxy in the app, the OS, or the environment. |
| Ignores proxy settings, runs on this Mac or a Windows host | `local` | `mitmdump --mode local:<process-name>` | Captures one process by name or PID, with no proxy config. `local:!name` captures everything except that process. Needs the macOS system extension or Windows redirector on first run. |
| Lab VM, device, or container that ignores proxies | `wireguard` | `mitmdump --mode wireguard` | Import the printed WireGuard config in the guest. All guest traffic goes through the tunnel, including raw TCP and UDP, which mitmproxy passes through. |
| A single known backend you can redirect by DNS or hosts file | `reverse` | `mitmdump --mode reverse:https://api.example.test@8443` | Point the client at the proxy as if it were the server. Good for a sample whose server you mock. |
| Supports SOCKS only (some CLI tools, Tor-aware clients) | `socks5` | `mitmdump --mode socks5 -p 1080` | |
| Must chain to a corporate or lab upstream proxy | `upstream` | `mitmdump --mode upstream:http://10.0.0.1:3128` | |
| Gateway or router you control | `transparent` | `mitmdump --mode transparent` | Needs pf or iptables redirection. Prefer `wireguard` in labs. |

Several modes can run together: `--mode regular@8080 --mode wireguard@51820`.

If the proxy sees no connection at all, the problem is routing, not TLS. Fix the mode before you trust the CA or hook anything.

## Trust the proxy CA

Start `mitmdump` once to create `~/.mitmproxy/mitmproxy-ca-cert.pem`. With the proxy running, `http://mitm.it` on the client serves the CA for each platform.

| Client | Install trust |
|---|---|
| macOS system | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem` |
| Windows | `certutil -addstore -f Root mitmproxy-ca-cert.cer` (elevated) |
| Debian/Ubuntu | Copy to `/usr/local/share/ca-certificates/mitmproxy.crt`, then `sudo update-ca-certificates` |
| Fedora/RHEL | Copy to `/etc/pki/ca-trust/source/anchors/`, then `sudo update-ca-trust` |
| Python `requests` / `httpx` | `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE` pointing at the PEM |
| Node.js / Electron main process | `NODE_EXTRA_CA_CERTS=/path/mitmproxy-ca-cert.pem` |
| Java | `keytool -importcert -cacerts -alias mitmproxy -file mitmproxy-ca-cert.pem` (per JRE; bundled JREs keep their own `cacerts`) |
| Go | Uses the OS store on macOS and Windows; `SSL_CERT_FILE` on Linux. A pinned `tls.Config` ignores both. |
| curl / OpenSSL tools | `--cacert`, or `CURL_CA_BUNDLE` |
| Docker container | Mount the PEM and run the distro's CA update in the image, or set the runtime variable above |
| Android / iOS | See the mobile sections below. A user-added CA is not enough on Android 7 and later. |

Proxy environment variables for CLI clients:

```bash
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 NO_PROXY=localhost,127.0.0.1
```

In a lab VM, use the host address on the VM network (`192.168.64.1` on UTM Shared Network, `10.0.2.2` on Emulated VLAN or the Android Emulator). Windows guests: `netsh winhttp set proxy 192.168.64.1:8080` covers WinHTTP clients. WinINet apps read the per-user setting in Internet Options. macOS guests: `networksetup -setsecurewebproxy "Ethernet" 192.168.64.1 8080`. When a guest app ignores all of these, use `wireguard` mode.

## Run the proxy

Record everything to a flow file and decide what to read afterwards:

```bash
mitmdump -p 8080 --set block_global=false \
  --save-stream-file /tmp/session.mitm \
  --set hardump=/tmp/session.har
```

`block_global=false` is needed when the client is on another host or VM. Keep the listener on the lab interface, not on a public one.

| Need | Option |
|---|---|
| Only one app's hosts | `--allow-hosts '(^|\.)api\.example\.test$'` |
| Leave pinned or irrelevant hosts untouched (TLS passthrough) | `--ignore-hosts 'apple\.com|googleapis\.com'` |
| Read a saved file with a filter | `mitmdump -nr /tmp/session.mitm '~d api.example.test & ~m POST'` |
| Filter expressions | `~d` domain, `~u` URL regex, `~m` method, `~c` status, `~t` content type, `~websocket`, `~b` body, combined with `&`, `|`, `!` |
| Serve a local file for a URL | `--map-local '|~d api.example.test|/v1/config|/lab/config.json'` |
| Rewrite a body or header in flight | `--modify-body '/~s/"enabled":false/"enabled":true'`, `--modify-headers '/~q/User-Agent/lab'` |
| Refuse a host | `--set block_list='|~d telemetry.example.test|444'` (444 closes the connection) |
| Offline mock from an earlier capture | `--server-replay /tmp/session.mitm --set server_replay_extra=404` (unmatched requests get 404, nothing leaves the lab) |
| Decrypt the same session in Wireshark | `MITMPROXY_SSLKEYLOGFILE=/tmp/mitm.keys mitmdump ...`, then `tshark -o tls.keylog_file:/tmp/mitm.keys` |
| Interactive UI | `mitmweb --web-host 127.0.0.1 --web-port 8081 -p 8080` |

`server_replay_extra=kill` or `404` is the safe default whenever the client is a malware sample. `forward` sends unmatched requests to the internet.

## Mobile targets: pre-flight gate

Skip this section for desktop, VM, container, and CLI targets.

**For a mobile app, pass this gate before spawning the application or applying an SSL pinning bypass.** If the target is absent or not rooted, do not fail the analysis and do not try blind hooks. Bridge to [host and lab setup](../05-environment/host-and-lab-setup.md), provision the environment, and repeat the checks.

### Android

Run:

```bash
adb devices
adb shell "su -c id"
adb shell "test -e /system/bin/ksu || which su"
```

Proceed only when the intended target is in the `device` state, `su -c id` contains `uid=0(root)`, and KernelSU/Magisk or another functional `su` is present.

Automatic remediation:

```bash
uv run scripts/setup_android_emulator.py setup-all
adb wait-for-device
adb shell "su -c id"
uv run scripts/setup_proxy_ca.py install-android
```

The tool-setup path uses an official Google Play ARM64 image, replaces `kernel-ranchu` with a matching KernelSU GKI `Image`, cold-boots the emulator, installs `KernelSU_Next_*.apk`, and verifies `uid=0(root)`. The current script expects a compatible system image to be installed; if none exists, install it before rerunning:

```bash
sdkmanager "system-images;android-36;google_apis_playstore;arm64-v8a"
uv run scripts/setup_android_emulator.py setup-all
```

### iOS

Run:

```bash
frida-ls-devices
ssh -o BatchMode=yes -o ConnectTimeout=5 -p 2222 root@localhost id
xcrun simctl list
```

A Simulator entry proves only simulator availability. Device-class analysis requires a rooted research guest whose SSH result is `uid=0` and whose Frida server is reachable.

If no rooted target is active, use [`macos-vm-ansible-setup.md`](../05-environment/macos-vm-ansible-setup.md) and [`ipsw.md`](../04-tool-usage/ipsw.md) to provision the Apple Silicon `vphone-cli` guest:

```bash
# Enable this once from macOS Recovery.
csrutil allow-research-guests enable

# Continue from a vphone-cli checkout on the normal host.
make
sudo VPhoneEscalator allow "$PWD/build/vphone-vm"
make fw_patch_jb
vphone-cli host preflight
vphone-cli vm start iOS-Research-VM
ssh -p 2222 root@localhost "/usr/bin/frida-server -D"
frida-ps -H 127.0.0.1:27042 -ai
```

The jailbreak firmware path applies the 112-patch set and provides root SSH on port 2222, Sileo, TrollStore, and guest `frida-server`. For a booted Simulator, install the proxy CA with the actual tool-setup subcommand:

```bash
uv run scripts/setup_proxy_ca.py install-ios-sim
```

For the research guest, transfer the CA profile into the guest, install it, and enable full trust in **Settings > General > About > Certificate Trust Settings**. `install-ios-sim` changes only the Simulator keychain.

## Interception Architecture

TLS interception has four independent stages:

```text
application request
    -> proxy routing
    -> TLS trust-chain validation
    -> application pin comparison
    -> protocol capture and decoding
```

Diagnose the failing stage instead of applying every bypass:

| Evidence | Working stage | Failing stage |
|---|---|---|
| No proxy connection | None | Routing or target connectivity |
| CONNECT request, TLS alert | Routing | CA trust or pinning |
| Decrypted HTTP but one SDK fails | Routing and platform trust | SDK-specific pinning |
| Hook logs but no proxy connection | Pin callback reached | Proxy routing |
| TCP capture only, no HTTP | Network path | TLS or non-HTTP application protocol |

## Mobile CA preparation

With `mitmdump` running as above, in a second terminal:

```bash
uv run scripts/setup_proxy_ca.py status
uv run scripts/setup_proxy_ca.py export-ca \
  --out-dir /tmp/mitmproxy-ca
```

`setup_proxy_ca.py` computes Android's legacy OpenSSL subject hash and writes the required hash-derived `.0` certificate filename. On Android 7 and later, production applications normally reject user-added CAs, so the rooted workflow installs the CA in a system-visible trust path. On API levels with EROFS, the helper uses a KernelSU/Magisk module or mount overlay.

## Android End-to-End Workflow

### 1. Install trust and configure routing

```bash
uv run scripts/setup_proxy_ca.py install-android
uv run scripts/setup_proxy_ca.py set-android-proxy \
  --host 10.0.2.2 --port 8080
adb shell settings get global http_proxy
```

`10.0.2.2` is the Android Emulator route to the host loopback. Use the reachable host address for a physical device or a different VM network.

### 2. Select the rejection boundary

| Android client | Why the CA alone is insufficient | Bypass |
|---|---|---|
| OkHttp 3/4 | `CertificatePinner` compares leaf/intermediate SPKI hashes after normal trust succeeds | Return early from `check(String, List<Certificate>)`, certificate-array overloads, and OkHttp 4 `check$okhttp` |
| Conscrypt / Network Security Config | Custom trust manager or XML pin set rejects the proxy chain | No-op `TrustManagerImpl.checkServerTrusted(X509Certificate[], String)` and `NetworkSecurityTrustManager.checkPins`; newer releases may also require `checkTrustedRecursive` |
| WebView | Chromium reports an `SslError` to the application delegate | Hook `WebViewClient.onReceivedSslError` and call `handler.proceed()` |
| Cronet | Native Chromium networking uses configured PKP and a Java certificate-verification callback | Suppress `CronetEngine.Builder.addPublicKeyPins`, enable local-anchor bypass, and hook `AndroidNetworkLibrary.verifyServerCertificates` when platform verification still rejects |
| Flutter | Dart traffic terminates in statically linked BoringSSL | Hook `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so`; Java hooks do not reach it |

Use the runnable `ssl_unpin_android.js` from [`frida.md`](../04-tool-usage/frida.md), then spawn before a networking singleton builds its client:

```bash
PACKAGE_ID="$(apkanalyzer manifest application-id target.apk)"
test -n "$PACKAGE_ID"
frida -U -f "$PACKAGE_ID" -l ssl_unpin_android.js
```

The script reports each class and overload it actually hooks. A successful Frida attach with zero relevant hooks is not a successful bypass.

### 3. Preserve proxy traffic

Use the recording command from "Run the proxy". Add `--flow-detail 2` to see headers live. An app that ignores the global proxy setting still reaches the proxy through `wireguard` mode with the WireGuard app in the emulator.

## iOS End-to-End Workflow

### 1. Establish trust and routing

For a booted Simulator:

```bash
uv run scripts/setup_proxy_ca.py install-ios-sim
xcrun simctl openurl booted http://mitm.it
```

Configure the Simulator's HTTP and HTTPS proxy to the host's reachable address and port `8080`. For the `vphone-cli` guest, install and fully trust the CA profile in the guest, then configure its active Wi-Fi interface's HTTP and HTTPS proxy. Do not assume the host macOS proxy setting automatically applies inside the guest.

### 2. Select the rejection boundary

| iOS client | Pinning or trust boundary | Bypass |
|---|---|---|
| Security.framework | `SecTrustEvaluateWithError` or legacy trust result APIs | Set `*error = NULL`, return Boolean `1`; for `SecTrustEvaluate` / `SecTrustGetTrustResult`, write `kSecTrustResultProceed` and return `errSecSuccess` |
| `NSURLSession` | Delegate consumes a server-trust challenge | Hook `URLSession:didReceiveChallenge:completionHandler:` and task variant; pass `NSURLCredential credentialForTrust:` with `UseCredential` |
| AFNetworking | `AFSecurityPolicy evaluateServerTrust:forDomain:` | Return `YES` |
| Alamofire 5 | Swift `ServerTrustEvaluating.evaluate(_:forHost:) throws` | Suppress the throwing evaluator at its recovered symbol/RVA; `evaluateServerTrust` is usually an app wrapper |
| TrustKit | `TSKPinningValidator evaluateTrust:forHostname:` | Return enum value `TSKTrustDecisionShouldAllowConnection` |
| Flutter iOS | BoringSSL in `Flutter.framework/Flutter` | Apply the matching native verifier hook or a matching offline engine patch |

Use the runnable `ssl_unpin_ios.js` from [`frida.md`](../04-tool-usage/frida.md):

```bash
frida-ps -H 127.0.0.1:27042 -ai
frida -H 127.0.0.1:27042 -f com.apple.mobilesafari -l ssl_unpin_ios.js
```

For a target IPA, replace the process identifier only after obtaining it from the installed bundle metadata. The iOS script handles Security.framework, both Foundation challenge selectors, AFNetworking, TrustKit, and symbol-bearing Alamofire builds.

## Flutter BoringSSL Workflow

Flutter's Android engine contains its own statically linked BoringSSL code in `libflutter.so`. Consequently:

- adding the mitmproxy CA to Android's system store does not alter BoringSSL's verifier;
- Java `X509TrustManager`, Network Security Config, and OkHttp hooks do not observe Dart `HttpClient` handshakes; and
- the effective trust decision is the native `ssl_crypto_x509_session_verify_cert_chain` return value.

Use the executable-range scanner in [`flutter-dart.md`](../01-static-architectures/flutter-dart.md). It first attempts the export, then scans the Flutter executable ranges for a version/architecture signature and refuses ambiguous matches. Its `Interceptor.attach` callback forces the ARM64 `X0` return register to `1`.

For offline repackaging, `re-flutter` replaces the engine with a snapshot-compatible patched build. After any engine replacement, rebuild, align, sign, install, and preserve the exact original engine and package hashes as evidence.

## Network Layer With Wireshark And tshark

mitmproxy starts at HTTP. Wireshark starts at the frame. Use a capture when the proxy is blind: pinning you have not broken, raw TCP or UDP, DNS, a beacon you can see only as sizes and timers, or a fallback that never becomes HTTP. The display filter and the `tshark -Y` filter are the same language. Prefer `tshark -T fields` over the GUI so the session stays batchable. Framing of a custom payload, once you have the bytes, stays in [`protocol-recovery.md`](../03-objectives/protocol-recovery.md).

Capture the guest interface, not every interface on the host. A capture filter drops noise before it hits disk. A display filter only hides it.

```bash
dumpcap -i <guest-bridge> -f "host <target-ip>" -w /tmp/session.pcapng
# Android emulator: the host sees the guest as 10.0.2.15, or use the VM bridge.
```

Write one hypothesis before reading frames. "This process beacons every N seconds to one address" is testable. "Decode the whole pcap" is not.

### Walk the stack downward only as far as the question needs

1. **Conversations.** Who talks to whom, on which port, who sent more bytes, and whether the client or the peer opened the socket.
2. **Names.** DNS queries from the guest, and whether a connection follows them.
3. **Handshake.** TCP completion, or a UDP flow with no handshake. TLS metadata if the payload is still opaque.
4. **Rhythm.** Inter-arrival time and payload length. A beacon is a clock plus a size class.
5. **Bytes.** Only the streams that survived the first four steps. Export one stream. Do not paste the pcap into the notes.

```bash
tshark -r /tmp/session.pcapng -q -z conv,ip
tshark -r /tmp/session.pcapng -q -z conv,tcp
tshark -r /tmp/session.pcapng -Y "dns.flags.response == 0" \
  -T fields -e frame.time_relative -e ip.src -e dns.qry.name -e dns.qry.type
tshark -r /tmp/session.pcapng -Y "tls.handshake.type == 1" \
  -T fields -e frame.time_relative -e ip.dst -e tcp.dstport \
  -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str
```

A conversation with no DNS name is an address hardcoded in the client, or a name resolved before the capture started. Say which. Re-anchor a destination to `getaddrinfo`, `connect`, or the string in the binary before you call it the backend.

### What each layer can prove

| Observation | Hypothesis it supports | It does not prove |
|---|---|---|
| One repeated TCP conversation, small payloads, stable gap | A poll or beacon | The command inside the payload |
| SYN with no SYN-ACK, then a second destination | A dead primary and a fallback | That the second host is the real operator |
| DNS query, no following connection | The name was blocked, sinkholed, or unused | That the sample has no network capability |
| Many unique subdomains, long labels, TXT or NULL replies | A DNS channel worth carving | The decoded message. Export the names first |
| TLS ClientHello SNI differs from the HTTP `Host` you later decrypt | Fronting or a CDN | The operator's identity |
| TLS 1.3 with no key log | You have SNI and ALPN only if the ClientHello still carries them | The certificate. It is encrypted. ECH encrypts SNI too |
| Short client payload, then a much larger server payload | Config or a module after check-in | What the bytes mean |
| One long TCP stream, data both ways | A session, often a task channel | That it is a WebSocket. Check the bytes or the proxy |

TLS 1.2 still shows the certificate in the handshake. Read the subject and the SAN. A certificate for a parked or lookalike name is a lead. It is not attribution.

When the stack writes NSS key logs, decrypt in place and stop at HTTP fields. Do not assume a statically linked stack honors `SSLKEYLOGFILE`.

```bash
tshark -r /tmp/session.pcapng \
  -o "tls.keylog_file:/tmp/tls.keys" \
  -Y "http.request or http.response or http2.headers" \
  -T fields -e frame.time_relative -e ip.dst -e http.host -e http.request.uri \
  -e http.response.code -e http2.header.value
```

If there is no key log, stay on metadata and the exported ciphertext. Hooking a key-log callback requires the library and the ABI identified first.

### Beacon, fallback, and a stream you cannot read

Sort client payloads by `frame.time_relative` for one `tcp.stream`. The gap between payloads of the same size class is the sleep. Jitter is the spread of those gaps, not a second protocol. A gap that changes after a larger server payload is the server telling the client a new interval. Confirm that write in the client. The timer alone is a candidate.

```bash
tshark -r /tmp/session.pcapng -Y "tcp.stream == 0 && tcp.len > 0" \
  -T fields -e frame.time_relative -e ip.src -e tcp.len -e tcp.payload
```

Export that stream once, then hand the bytes to the framing procedure. `tcp.payload` in the index is enough to see repetition. A hex dump of every frame is not.

```bash
tshark -r /tmp/session.pcapng -q -z follow,tcp,raw,0 > /tmp/stream0.hex
```

DNS fallback is the same measurement on names. A query that appears only after the TCP handshake fails is the next transport. Carve the label or the TXT rdata in the lab file. Do not resolve that name from the analysis host. High-entropy labels are a channel. A single normal A query is looking up a host.

UDP with no DNS and no RTP/QUIC ALPN is a custom datagram protocol until the ports and the first bytes say otherwise. QUIC is UDP `443` with a long header. Treat it as a TLS-class tunnel: without keys you have connection IDs and lengths, not the API.

### Pair the pcap with the proxy

When both files exist, the pcap explains what the proxy never saw, and the proxy explains the one stream whose TLS you broke. Match them on timestamp, destination, and size. A host present only in the pcap is bypassing the proxy. That is the next pinning or raw-socket question, not a reason to ignore it.

Keep the conversation table, the DNS names, the SNI list, the beacon gap, and the stream hash. The pcap stays on disk.

## Passive Structured Logging Addon

The following addon records metadata and bodies without mutating traffic:

```python
# flow_log.py
from mitmproxy import http


class FlowRecorder:
    def request(self, flow: http.HTTPFlow) -> None:
        print(
            f"REQUEST {flow.request.method} {flow.request.pretty_url} "
            f"bytes={len(flow.request.raw_content or b'')}"
        )

    def response(self, flow: http.HTTPFlow) -> None:
        assert flow.response is not None
        print(
            f"RESPONSE {flow.response.status_code} {flow.request.pretty_url} "
            f"bytes={len(flow.response.raw_content or b'')}"
        )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket is not None
        message = flow.websocket.messages[-1]
        direction = "client-to-server" if message.from_client else "server-to-client"
        print(f"WEBSOCKET {direction} bytes={len(message.content)}")


addons = [FlowRecorder()]
```

Run it with a serialized flow capture:

```bash
mitmdump -p 8080 --set block_global=false \
  --scripts flow_log.py \
  --save-stream-file /tmp/session.mitm
```

## Reading Flows As Backend Logic

A decrypted `.mitm` file is an oracle for the contract the client implements. It is not the server's source. Write one hypothesis per campaign: which request is registration, which field selects the next client branch, which response code means "sleep". Confirm it by a second action in the client, or by a lab response you injected. A single pretty JSON body is a candidate.

### Separate noise before naming an API

Drop hosts that never carry the feature you are reversing: OCSP, certificate transparency, crash reporters, font CDNs, connectivity checks, and analytics beacons. Keep a host when its path, body, or timing changes as you use one feature. Group the rest by registrable host, then by path template (`/v1/users/{id}`), not by the raw URL of one call.

### Build the map

For each remaining exchange record only what the next reversing step needs:

| Field | What it tells you |
|---|---|
| Method and path template | The operation. `GET` that repeats on a timer is a poll. `POST` once at launch is registration or login. |
| Request content type | JSON, form, protobuf, or an opaque blob. An opaque blob inside TLS is still encrypted at the application layer. |
| Auth material | `Authorization`, cookie, `x-api-key`, or a header that changes every call (nonce, timestamp, signature). |
| Response status and one stable field | The branch the client will take. Do not paste tokens or personal data into notes. Record a hash and the field name. |
| Who built it | The client function, found by the path string, the OkHttp/URLSession/`WinHttpSendRequest` caller, or the JS function that assembles the body. |

Export a compact index instead of scrolling the UI:

```bash
mitmdump -nr /tmp/session.mitm -s map_flows.py
```

```python
# map_flows.py — index only. Bodies stay in the flow file.
import hashlib
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    body = flow.request.raw_content or b""
    digest = hashlib.sha256(body).hexdigest()[:12]
    status = flow.response.status_code if flow.response else "-"
    ctype = flow.request.headers.get("content-type", "-")
    print(f"{flow.request.method} {status} {ctype} sha={digest} {flow.request.pretty_url}")
```

WebSocket and HTTP/2 streams are part of the same map. A socket that stays open and receives server frames is a task channel, not a failed request. gRPC is HTTP/2 with `content-type: application/grpc` and a `:path` of `/package.Service/Method`. Carve the protobuf with the method in [`protocol-recovery.md`](../03-objectives/protocol-recovery.md). Do not guess field names the wire did not carry.

### What a capture can prove about the backend

You can validate a client-side hypothesis. You cannot read server-side authorization out of a client.

- The same request twice, with only a nonce changed, shows whether the call is idempotent.
- A field echoed from the response into the next request is a session or a cursor. Break that echo in a lab response and see which client function fails.
- A status or an enum that selects a different follow-up request is a state machine. Name the states from the sequence you observed: register, poll, post result, sleep.
- An error string or a JSON key that appears in the client binary is the client's name for that outcome. The server may use it differently. Re-anchor the string before you rename the endpoint.
- A signature header means the body is authenticated. Find the signer in the client (HMAC or an asymmetric sign over a canonical string). Replaying a captured request at a live server does not explain the signer, and it is not allowed here.

Encrypted bodies, custom binary POSTs, and base64 blobs are not "the API". Hook the function that produces the plaintext, or decrypt offline with the key schedule from [`algorithm-recovery.md`](../03-objectives/algorithm-recovery.md), then put the plaintext back into the map. The TLS decode only removed the transport.

### Test the client, not the live server

To see which branch a response selects, answer that one flow inside mitmproxy on the lab path. Change one field. Watch the client. Restore the original bytes after the trial.

```python
def response(flow: http.HTTPFlow) -> None:
    if flow.request.path.startswith("/v1/poll") and flow.response is not None:
        # Lab hypothesis: status "wait" selects the sleep branch.
        flow.response.content = b'{"status":"wait","sleep":30}'
```

Do this only against the intercepted client in the lab. Do not forward the modified call, or any replay, to a production host or to a server a malware sample talks to. For a whole mocked backend, record once and serve it with `--server-replay` and `server_replay_extra=404`.

## Multi-stage and long-lived channels

Some clients do more than request and response: they register, poll for work, download modules, or switch transport when one fails. Updaters, sync agents, game clients, and malware samples all do this. Build the same map, and add a state machine. When the client is untrusted, use a stricter egress rule: it stays on a sinkhole or a local mock (`--server-replay`, `--map-local`, or an addon), and the goal is the state machine, not a conversation with whoever runs the server.

Walk the capture in order and label each flow as one of: bootstrap, key or config, check-in, task poll, task result, module download, or idle. A flow you cannot label stays unknown.

Shapes that hide that machine:

| What you see | What it usually is | Next measurement |
|---|---|---|
| One POST on a timer, small body, short JSON or empty 200 | Heartbeat or poll | Vary the interval across two runs. Jitter around a constant is the sleep from the last response or a hardcoded range. |
| First response is large, later requests shrink | Config or a task list delivered once | Diff the two responses. The stable object is config. The object that disappears is a one-shot task. |
| JSON or cookie wraps a base64 or hex blob | Framing around a custom payload | Decode one layer. If entropy stays high, the blob is the cipher. Find the encrypt call in the client. |
| `Host` is a CDN or a benign site, SNI and `Host` disagree, or a fronted domain | The visible host is not the application host | Record both names. The inner `Host` or the path is the real channel. |
| Image, profile, or paste-site body | Data hidden in a benign-looking resource | Extract the stego or the paste body in the lab. Do not fetch the live URL again from the analysis host. |
| HTTPS fails and the sample then uses DNS TXT, DoH, or raw TCP | A fallback transport | The HTTP failure is the trigger. Capture that next protocol separately. Its framing is [`protocol-recovery.md`](../03-objectives/protocol-recovery.md). |
| Long-lived WebSocket or gRPC stream | Tasking pushed by the server | Order the frames. A server frame followed by a client frame is a task and its result. |
| Several hosts, one succeeds | A proxy list | The winner is the active channel. The failures are backups, not separate features. |

A client that exits after check-in with no task has not shown that it does nothing. The tasking branch may simply not have been served. Say which states you observed and which response you never received.

Re-anchor every labeled flow to the function that builds it. A path string, a format string, or the caller of `HttpSendRequest` / `NSURLSession` / OkHttp is the static half. The flow is the dynamic half. Both are required before the state machine is `validated`.

## Verification and Cleanup

Minimum evidence for a completed interception:

1. The proxy saw the client's connections in the chosen mode. For mobile targets, the gate output proves the intended target and root state.
2. The CA helper reports the certificate hash and installation method.
3. The proxy setting resolves to the expected host and port.
4. The relevant pinning hook logs a callback for the target hostname.
5. The saved `.mitm` file contains a decrypted request and response.
6. The target no longer reports its original TLS failure.

Restore the environment after analysis:

```bash
uv run scripts/setup_proxy_ca.py clear-android-proxy
adb shell settings get global http_proxy
unset HTTP_PROXY HTTPS_PROXY        # CLI clients
netsh winhttp reset proxy           # Windows guest
```

Remove the test CA from any machine that is not disposable: `security delete-certificate -c mitmproxy` on macOS, `certutil -delstore Root mitmproxy` on Windows, and on Debian/Ubuntu delete the `.crt` and run `update-ca-certificates --fresh`.

Stop `frida-server`, remove temporary capture material according to the engagement's evidence policy, and remove the test CA from disposable targets before reusing or exporting them.

## Boundaries

- Intercept only applications and endpoints covered by explicit authorization.
- Never send traffic to a live server that a malware sample talks to. Use a sinkhole, `--server-replay` with `server_replay_extra=404`, or a response generated inside the lab proxy. A mocked body tests the client. It is not a server you put on the internet.
- A decrypted body does not prove what the backend authorizes. Client checks and server checks are different programs.
- Treat authentication tokens, session cookies, personal data, and captured bodies as sensitive evidence.
- Do not call a bypass successful from an attach message alone; require hook and decrypted-flow evidence.
- Do not install a test CA or disable trust evaluation on a personal or production device.
- A pcap without keys does not name the API. SNI, sizes, and timers are observations about the channel. The command inside a TLS record stays unknown until it is decrypted or carved from the client.
- Do not resolve, fetch, or replay a name or address taken from a malware capture. Read it from the pcap you already have.
