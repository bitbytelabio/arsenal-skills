# Mobile Network Traffic Interception and TLS Pinning

## Purpose

Use this reference to route authorized application traffic through `mitmproxy`, establish the proxy CA as a trust anchor, bypass framework and native certificate pinning, and turn the decrypted flows into an API map or a command-and-control state machine. Use [`frida.md`](../04-tool-usage/frida.md) for the complete Android and iOS hook scripts and [`flutter-dart.md`](../01-static-architectures/flutter-dart.md) for Flutter's BoringSSL verifier. Binary framing, protobuf, and gRPC wire layout stay in [`protocol-recovery.md`](../03-objectives/protocol-recovery.md).

## Mandatory Mobile Pre-Flight Environment Gate

**MUST pass this gate before starting `mitmdump`, spawning the application, or applying an SSL pinning bypass.** If the target is absent or not rooted, do not fail the analysis and do not try blind hooks. Bridge to [host and lab setup](../05-environment/host-and-lab-setup.md), provision the environment, and repeat the checks.

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
python3 scripts/setup_android_emulator.py setup-all
adb wait-for-device
adb shell "su -c id"
python3 scripts/setup_proxy_ca.py install-android
```

The tool-setup path uses an official Google Play ARM64 image, replaces `kernel-ranchu` with a matching KernelSU GKI `Image`, cold-boots the emulator, installs `KernelSU_Next_*.apk`, and verifies `uid=0(root)`. The current script expects a compatible system image to be installed; if none exists, install it before rerunning:

```bash
sdkmanager "system-images;android-36;google_apis_playstore;arm64-v8a"
python3 scripts/setup_android_emulator.py setup-all
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
python3 scripts/setup_proxy_ca.py install-ios-sim
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

## Proxy and CA Preparation

Start `mitmdump` once to create `~/.mitmproxy/mitmproxy-ca-cert.pem`, then verify and install the CA:

```bash
mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false \
  --save-stream-file /tmp/mobile-session.mitm
```

In a second terminal:

```bash
python3 scripts/setup_proxy_ca.py status
python3 scripts/setup_proxy_ca.py export-ca \
  --out-dir /tmp/mitmproxy-ca
```

`setup_proxy_ca.py` computes Android's legacy OpenSSL subject hash and writes the required hash-derived `.0` certificate filename. On Android 7 and later, production applications normally reject user-added CAs, so the rooted workflow installs the CA in a system-visible trust path. On API levels with EROFS, the helper uses a KernelSU/Magisk module or mount overlay.

## Android End-to-End Workflow

### 1. Install trust and configure routing

```bash
python3 scripts/setup_proxy_ca.py install-android
python3 scripts/setup_proxy_ca.py set-android-proxy \
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

```bash
mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false \
  --save-stream-file /tmp/android-session.mitm \
  --flow-detail 2
```

As an alternative to the headless command, start an interactive session with `mitmweb`:

```bash
mitmweb --web-host 127.0.0.1 --web-port 8081 \
  --listen-port 8080 \
  --set block_global=false
```

## iOS End-to-End Workflow

### 1. Establish trust and routing

For a booted Simulator:

```bash
python3 scripts/setup_proxy_ca.py install-ios-sim
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
# dump_mobile.py
from mitmproxy import http


class MobileRecorder:
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


addons = [MobileRecorder()]
```

Run it with a serialized flow capture:

```bash
mitmdump --listen-port 8080 \
  --set block_global=false \
  --scripts dump_mobile.py \
  --save-stream-file /tmp/mobile-session.mitm
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

Do this only against the intercepted client in the lab. Do not forward the modified call, or any replay, to a production host or a live command-and-control server.

## Complex Command And Control

Treat a suspected C2 channel as the same map, with a stricter egress rule. The sample stays on a sinkhole or a local mock. The first goal is the state machine, not a conversation with the operator.

Walk the capture in order and label each flow as one of: bootstrap, key or config, check-in, task poll, task result, module download, or idle. A flow you cannot label stays unknown.

Shapes that hide that machine:

| What you see | What it usually is | Next measurement |
|---|---|---|
| One POST on a timer, small body, short JSON or empty 200 | Beacon or poll | Vary the interval across two runs. Jitter around a constant is the sleep from the last response or a hardcoded range. |
| First response is large, later requests shrink | Config or a task list delivered once | Diff the two responses. The stable object is config. The object that disappears is a one-shot task. |
| JSON or cookie wraps a base64 or hex blob | Framing around a custom payload | Decode one layer. If entropy stays high, the blob is the cipher. Find the encrypt call in the client. |
| `Host` is a CDN or a benign site, SNI and `Host` disagree, or a fronted domain | The visible host is not the application host | Record both names. The inner `Host` or the path is the real channel. |
| Image, profile, or paste-site body | A dead drop | Extract the stego or the paste body in the lab. Do not fetch the live URL again from the analysis host. |
| HTTPS fails and the sample then uses DNS TXT, DoH, or raw TCP | A fallback transport | The HTTP failure is the trigger. Capture that next protocol separately. Its framing is [`protocol-recovery.md`](../03-objectives/protocol-recovery.md). |
| Long-lived WebSocket or gRPC stream | Tasking pushed by the server | Order the frames. A server frame followed by a client frame is a task and its result. |
| Several hosts, one succeeds | A proxy list | The winner is the active channel. The failures are backups, not separate features. |

A client that exits after check-in with no task is not "harmless". The tasking branch may simply not have been served. Say which states you observed and which response you never received.

Re-anchor every labeled flow to the function that builds it. A path string, a format string, or the caller of `HttpSendRequest` / `NSURLSession` / OkHttp is the static half. The flow is the dynamic half. Both are required before the state machine is `validated`.

## Verification and Cleanup

Minimum evidence for a completed interception:

1. The environment gate output proves the intended target and root state.
2. The CA helper reports the certificate hash and installation method.
3. The proxy setting resolves to the expected host and port.
4. The relevant pinning hook logs a callback for the target hostname.
5. The saved `.mitm` file contains a decrypted request and response.
6. The target no longer reports its original TLS failure.

Restore the environment after analysis:

```bash
python3 scripts/setup_proxy_ca.py clear-android-proxy
adb shell settings get global http_proxy
```

Stop `frida-server`, remove temporary capture material according to the engagement's evidence policy, and remove the test CA from disposable targets before reusing or exporting them.

## Boundaries

- Intercept only applications and endpoints covered by explicit authorization.
- Never send arbitrary traffic to live malware command-and-control infrastructure. Use a sinkhole or a response generated inside the lab proxy. A mocked body tests the client. It is not a server you put on the internet.
- A decrypted body does not prove what the backend authorizes. Client checks and server checks are different programs.
- Treat authentication tokens, session cookies, personal data, and captured bodies as sensitive evidence.
- Do not call a bypass successful from an attach message alone; require hook and decrypted-flow evidence.
- Do not install a test CA or disable trust evaluation on a personal or production device.
- A pcap without keys does not name the API. SNI, sizes, and timers are observations about the channel. The command inside a TLS record stays unknown until it is decrypted or carved from the client.
- Do not resolve, fetch, or replay a name or address taken from a malware capture. Read it from the pcap you already have.
