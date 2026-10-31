# Binary Protocol & Network Serialization Recovery

## Title & Overview
- **Domain**: Custom binary network protocols, serialization formats (Protocol Buffers, gRPC, FlatBuffers, Cap'n Proto, MessagePack, Thrift), and proprietary telemetry streams.
- **Scope**: Framing and length/TLV detection, varint and checksum recognition, state machines, Protobuf wire-format parsing and descriptor recovery from binaries, recognition of other serialization formats, TLS keylog decryption, authoring Wireshark Lua dissectors and Kaitai Struct specs, and replay/fuzz confirmation.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Captures or a client use non-standard binary TCP/UDP framing that Wireshark shows as raw data.
- Strings include `.proto`, `google.protobuf.*`, `grpc-status`, `flatbuffers`, `capnp`, `MessagePack`, or `Thrift`.
- The binary has manual serialization loops with shifts and masks: `buf[i++] = (val >> 24) & 0xff`, or varint loops (`while (b & 0x80)`).
- A command or telemetry protocol needs its message schema and opcodes recovered.

---

## Tooling & CLI Actions

### Protobuf / gRPC
- `protoc --decode_raw` — schema-free parser; reads a raw message from stdin:
  ```bash
  protoc --decode_raw < payload.bin
  ```
- `blackboxprotobuf` — Python decode/re-encode of schema-free messages (verified):
  ```bash
  uv run --with blackboxprotobuf python -I -c \
    "import blackboxprotobuf,sys; m,t=blackboxprotobuf.decode_message(open('payload.bin','rb').read()); print(m)"
  ```
- `protodump` — extracts embedded `FileDescriptorProto` definitions to `.proto` files:
  ```bash
  go install github.com/arkadiyt/protodump/cmd/protodump@latest
  protodump -file target.bin -output ./recovered_proto/
  ```
- `pbtk` — extracts `.proto` from binaries, JARs/APKs, and JS. Correct entry points are the console scripts, not a module path:
  ```bash
  uv tool install pbtk
  pbtk-from-binary target.bin ./recovered_proto/     # native binary
  pbtk-jar-extract app.apk ./recovered_proto/        # Java/Android (needs dex2jar, jad)
  ```
- `grpcurl` — if the server has reflection enabled, dump the full service schema live (lab endpoints only):
  ```bash
  grpcurl -plaintext localhost:50051 list
  grpcurl -plaintext localhost:50051 describe mypkg.MyService
  ```
- `buf` — lint/convert recovered `.proto` and regenerate descriptors.

### Capture & dissection
- `tshark` — slice, filter, and run a Lua dissector headlessly. Wireshark ships dissectors for `protobuf`, `grpc`, `thrift`, `tls`, `http2`, `quic`, and `msgpack` (confirmed in `tshark -G protocols`).
- `mitmdump` — intercept HTTP/2 and gRPC; decode-as needs the Protobuf dissector's search paths set.
- Kaitai Struct — declarative binary format spec; compile with `ksc` and parse with the runtime (`uv run --with kaitaistruct python -I ...`).
- Scapy — craft and replay frames in a lab (`uv run --with scapy python -I ...`).

---

## 1. Framing & Transport Boundary Identification

Every binary protocol must solve framing: where does one message end and the next begin?

```text
+-------------------+--------------------+--------------------+--------------------+
| Magic Bytes (2-4B)| Message Opcode(2B) | Payload Length(4B) | Body Data (N Bytes)|
+-------------------+--------------------+--------------------+--------------------+
0                   2                    4                    8                   8+N
```

### Framing categories
1. **Fixed header with length field**: fixed fields (magic, opcode, sequence) then a 16- or 32-bit length.
   - *Detect*: compare packets of different sizes; find a field whose value equals `payload_size` or `payload_size - header_size`.
   - *Endianness*: a 258-byte payload carries `01 02` (big-endian/network) or `02 01` (little-endian).
2. **Type-Length-Value (TLV)**: `type`, `length`, `value` triplets, often nested.
3. **Delimiter-framed**: messages split by a token (`00`, `\r\n`, SLIP `0xC0`).
4. **Varint-length-prefixed**: a LEB128 varint length prefix (common with Protobuf-over-stream and gRPC-Web).

### Length-field detection, mechanically
Collect several frames, then for each candidate offset/width test whether `read_int(offset,width,endian) + k == frame_len` for a constant `k` (the header size). The width/endian/`k` that holds across all frames is the length field.

### Varint (LEB128) recognition
Little-endian base-128: each byte carries 7 payload bits; the high bit (`0x80`) means "more bytes follow". A loop that masks `& 0x7F`, shifts by 7, and tests `& 0x80` is a varint decoder. ZigZag (`sint32/64`) maps `n` to `(n<<1) ^ (n>>31)`.

### Checksum / integrity fields
A trailing 1–4 byte field that changes with any body change is a checksum. Try CRC-16/CRC-32 (`0xEDB88320`), Adler-32 (two 16-bit sums mod 65521), Fletcher, or a simple sum/XOR. Confirm by recomputing over the covered range.

### State machines
A protocol with a handshake (hello → auth → session) is a state machine. Recover it from the dispatcher: the opcode switch plus a per-connection state variable gates which opcodes are legal in each state. Record the state variable address and the legal-opcode set per state.

---

## 2. Protobuf Wire Format Without `.proto`

Protobuf encodes `(tag, value)` pairs with no field names. The tag combines field number and wire type.

### Wire types
- **0 Varint**: `int32/64`, `uint32/64`, `sint32/64`, `bool`, `enum`.
- **1 I64**: `fixed64`, `sfixed64`, `double`.
- **2 LEN**: `string`, `bytes`, embedded messages, packed repeated.
- **5 I32**: `fixed32`, `sfixed32`, `float`.
- (Types 3/4 are the deprecated start/end-group markers.)

### Tag math
`tag = (field_number << 3) | wire_type`. Decode: `wire_type = tag & 0x07`, `field_number = tag >> 3`.
- `0x08` = field 1, wire 0 (varint). `0x12` = field 2, wire 2 (length-delimited).

### Decode
```bash
protoc --decode_raw < payload.bin
# 1: 1002
# 2: "session_token_xyz"
# 3 { 1: 1698574000  2: "192.168.1.50" }
```
A LEN field whose bytes themselves decode cleanly as protobuf is an embedded message; otherwise treat it as `bytes`/`string`. `blackboxprotobuf` keeps a type map you can edit and re-encode for replay.

---

## 3. Recovering `.proto` Descriptors From Binaries

Many builds keep the serialized `FileDescriptorProto` in `.rodata`:
```bash
strings -a target.bin | grep -E "\.proto$" || true
```
Then extract the full schema (not a module path — use the console script):
```bash
protodump -file target.bin -output ./recovered/      # Go descriptor extractor
pbtk-from-binary target.bin ./recovered/             # alternative
```
The output `.proto` files give real field names and message names, which upgrade `decode_raw`'s numbered fields to semantic ones.

---

## 4. gRPC Service Reconstruction

gRPC is Protobuf over HTTP/2:
1. **HTTP/2 headers**: `:path` = `/<package>.<Service>/<Method>`; `content-type` = `application/grpc` or `application/grpc+proto`.
2. **Length-prefixed message**: 1 byte compression flag (`00` none, `01` compressed) + 4-byte big-endian length, then the Protobuf payload.
3. Carve from byte 5 and feed to `protoc --decode_raw`, or let Wireshark's gRPC dissector split it.
4. If the server exposes reflection, `grpcurl ... describe` returns the schema directly (lab only).

---

## 5. Other Serialization Formats (Recognition)

| Format | Tell |
|---|---|
| **FlatBuffers** | No parse step on read; a root-table offset at the buffer start, a vtable of field offsets, `flatbuffers` / `.fbs` strings. Access is pointer-chasing, not sequential decode. |
| **Cap'n Proto** | Segment framing (4-byte segment count + sizes), `capnp` strings, pointer words with low-2-bit tags. |
| **MessagePack** | Self-describing type bytes: `0x80-0x8f` fixmap, `0x90-0x9f` fixarray, `0xa0-0xbf` fixstr, `0xc0` nil, `0xc2/0xc3` false/true. Wireshark has a `msgpack` dissector. |
| **Thrift** | Binary protocol: type byte + field id; compact protocol uses varints. `TBinaryProtocol`/`TCompactProtocol` strings; Wireshark `thrift` dissector. |
| **BSON** | 4-byte total length prefix, type-tagged elements, `\x00` terminator. |
| **ASN.1 DER** | TLV with type/length/value; `0x30` (SEQUENCE) is a common start. |

---

## 6. TLS Decryption via Keylog

When the client uses TLS and you control the process, export session keys instead of breaking crypto:
```bash
# Client process writes NSS keylog; point Wireshark/tshark at it.
SSLKEYLOGFILE=/tmp/keys.log <client>
tshark -r capture.pcapng -o tls.keylog_file:/tmp/keys.log -Y http2 -V
```
Many runtimes honor `SSLKEYLOGFILE` (OpenSSL 1.1.1+, Go, NSS, BoringSSL builds that enable it). If not, hook the TLS write/read with Frida and capture plaintext before encryption. Keylog is lab-only and respects the egress rule.

---

## 7. Code Examples

### 7.1 PCAP stream carver
```python
# uv run --with scapy python -I pcap_carver.py capture.pcap
import struct, sys
from scapy.all import rdpcap, TCP, Raw

MAGIC = 0x5052  # "PR"

def parse(raw: bytes):
    off, n = 0, 0
    while off + 8 <= len(raw):
        magic, opcode, length = struct.unpack_from(">HHI", raw, off)
        if magic != MAGIC:
            off += 1            # resync one byte at a time
            continue
        if off + 8 + length > len(raw):
            print(f"[-] incomplete message at {off}")
            break
        body = raw[off + 8: off + 8 + length]
        print(f"[+] #{n} op=0x{opcode:04x} len={length} body={body[:32].hex()}")
        off += 8 + length
        n += 1

if __name__ == "__main__":
    stream = b"".join(bytes(p[Raw].load) for p in rdpcap(sys.argv[1])
                      if p.haslayer(TCP) and p.haslayer(Raw))
    parse(stream)
```

### 7.2 Wireshark Lua dissector with TCP reassembly
`dissect_tcp_pdus` handles segmentation across TCP packets; a naive `buffer(8,length)` breaks on split frames. This template is verified against a split-frame capture.
```lua
-- custom_proto.lua  (run: tshark -X lua_script:custom_proto.lua -r cap.pcap -Y custom_proto)
local p = Proto("custom_proto", "Custom Protocol")
local f_magic  = ProtoField.uint16("custom_proto.magic",  "Magic",  base.HEX)
local f_opcode = ProtoField.uint16("custom_proto.opcode", "Opcode", base.HEX,
                   { [1] = "HELLO", [2] = "DATA", [3] = "BYE" })
local f_length = ProtoField.uint32("custom_proto.length", "Length", base.DEC)
local f_body   = ProtoField.bytes ("custom_proto.body",   "Body")
p.fields = { f_magic, f_opcode, f_length, f_body }
local HDR = 8

local function pdu_len(tvb, pinfo, offset)
  return HDR + tvb(offset + 4, 4):uint()       -- total PDU length for reassembly
end

local function dissect_pdu(tvb, pinfo, tree)
  pinfo.cols.protocol = "CUSTOM"
  local t = tree:add(p, tvb(), "Custom Protocol PDU")
  t:add(f_magic,  tvb(0, 2))
  t:add(f_opcode, tvb(2, 2))
  t:add(f_length, tvb(4, 4))
  local n = tvb(4, 4):uint()
  if n > 0 then t:add(f_body, tvb(HDR, n)) end
  pinfo.cols.info:append(string.format(" op=0x%04x len=%d", tvb(2, 2):uint(), n))
end

function p.dissector(tvb, pinfo, tree)
  if tvb:len() < 2 or tvb(0, 2):uint() ~= 0x5052 then return 0 end
  dissect_tcp_pdus(tvb, tree, HDR, pdu_len, dissect_pdu)
  return tvb:len()
end

DissectorTable.get("tcp.port"):add(9999, p)
```

### 7.3 Kaitai Struct spec
A `.ksy` spec documents the format once and compiles to many languages. Compile with `ksc -t python custom.ksy`, then parse with the runtime (`uv run --with kaitaistruct python -I`). Field types `u2be`/`u4be` are big-endian; `u2le`/`u4le` little-endian.
```yaml
# custom.ksy
meta:
  id: custom_proto
  endian: be
seq:
  - id: magic
    contents: [0x50, 0x52]
  - id: opcode
    type: u2
  - id: length
    type: u4
  - id: body
    size: length
```

---

## 8. Replay and Fuzz to Confirm

A recovered schema is a `candidate` until a round-trip confirms it:
- **Replay**: re-encode a parsed message (blackboxprotobuf or Scapy) and send it to a **lab** endpoint or local stub; a well-formed response confirms the framing and field meaning.
- **Fuzz**: mutate one field at a time against the stub and watch which fields the parser rejects; a strict length or type check confirms that field's role. See [fuzzing-for-reversing.md](../02-dynamic-instrumentation/fuzzing-for-reversing.md).

---

## Boundaries & Anti-Patterns
- **Do not invent field semantics.** Name a field only when a string literal, log line, descriptor, or decompiler variable backs it.
- **Do not assume little-endian.** Network order is big-endian. Check for `ntohl`/`be32toh`/`htons` in the disassembler.
- **Do not replay against production.** All replay and mutation go to contained local stubs or lab VMs; egress follows the Rule 6 ledger.
- **A silent dissector is not a negative.** No match may mean a wrong port or a split frame; confirm with `-V` on a known-good frame.
