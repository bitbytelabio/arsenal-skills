# Binary Protocol & Network Serialization Recovery

## Title & Overview
- **Domain**: Custom binary network protocols, serialization formats (Protocol Buffers, gRPC, MessagePack, FlatBuffers), and proprietary telemetry streams.
- **Scope**: Reverse engineering packet framing, header fields, TLV structures, Protobuf wire format parsing without `.proto` definitions (`varint`, `length-delimited`), gRPC service reconstruction, PCAP packet stream carving, and Wireshark Lua dissector authoring.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Network traffic captures or client binaries utilize non-standard binary TCP/UDP communications displayed as raw data in Wireshark.
- String references include `.proto` file descriptors, `google.protobuf.*`, `grpc-status`, or `flatbuffers`.
- Binary contains manual serialization loops using shifts and masks: `buf[i++] = (val >> 24) & 0xff`.
- High-level telemetry or command-and-control protocols require reverse engineering to extract message schemas and command opcodes.

---

## Tooling & CLI/MCP Actions

### Primary Decompilers & Analyzers
- **Headless IDA Pro / Ghidra**: Disassemble and decompile packet serialization, parsing, and dispatch routines.
- **Protobuf & gRPC Recovery**:
  - `protoc --decode_raw`: Native Protobuf schema-free parser.
  - `pbtk` (Protobuf Toolkit): Extracts `.proto` definitions directly from compiled binaries.
  - `blackboxprotobuf`: Python library for decoding and editing schema-free Protobuf messages.
- **Traffic Inspection & Dissection**:
  - `tshark` (Wireshark CLI): Packet slicing, payload extraction, and Lua dissector testing.
  - `mitmproxy`: Intercepting gRPC and HTTP/2 WebSocket streams.

---

## Core Methodologies & Step-by-Step Technical Workflow

### 1. Packet Framing & Transport Boundary Identification

Every binary protocol must solve the framing problem: how does the receiver determine where one message ends and the next begins?

```text
+-------------------+--------------------+--------------------+--------------------+
| Magic Bytes (2-4B)| Message Opcode(2B) | Payload Length(4B) | Body Data (N Bytes)|
+-------------------+--------------------+--------------------+--------------------+
0                   2                    4                    8                   8+N
```

#### Framing Categories
1. **Fixed Header with Length Field**:
   - Header contains fixed fields (Magic, Opcode, Sequence) followed by a 16-bit or 32-bit length integer indicating the size of the following payload.
   - *Detection*: Compare packets of differing sizes. Look for a field whose integer value matches either `packet_size` or `packet_size - header_size`.
   - *Endianness*: Check whether a 258-byte packet carries `0x01, 0x02` (big-endian/network order) or `0x02, 0x01` (little-endian).
2. **Type-Length-Value (TLV) Streams**:
   - Sequential triplets where each field declares its Type tag, Length in bytes, and Value data.
   - Allows flexible variable-length records and nested hierarchical objects.
3. **Delimiter-Framed Messages**:
   - Messages separated by specific boundary tokens (e.g., `0x00`, `\r\n`, or SLIP framing `0xC0`).

### 2. Protocol Buffers Wire Format Parsing Without `.proto`

Protobuf encodes structured messages as sequences of key-value pairs without transmitting field names. Each field consists of a **tag** (which combines field number and wire type) followed by the field value.

#### Wire Types
- **Type 0 (Varint)**: `int32`, `int64`, `uint32`, `uint64`, `sint32`, `sint64`, `bool`, `enum`.
- **Type 1 (64-bit)**: `fixed64`, `sfixed64`, `double`.
- **Type 2 (Length-delimited)**: `string`, `bytes`, embedded messages, packed repeated fields.
- **Type 5 (32-bit)**: `fixed32`, `sfixed32`, `float`.

#### Tag Calculation
The tag byte is calculated as:
$$\text{Tag} = (\text{Field Number} \ll 3) \mid \text{Wire Type}$$

To decode a tag byte:
$$\text{Wire Type} = \text{Tag} \ \& \ 0x07, \quad \text{Field Number} = \text{Tag} \gg 3$$

*Example*:
If byte is `0x08`: `0x08 = (1 << 3) | 0` $\rightarrow$ Field Number 1, Wire Type 0 (Varint).
If byte is `0x12`: `0x12 = (2 << 3) | 2` $\rightarrow$ Field Number 2, Wire Type 2 (Length-delimited).

#### Schema-Free Decoding with `protoc`
```bash
# Decode raw binary protobuf payload directly from CLI
cat payload.bin | protoc --decode_raw

# Output format:
# 1: 1002
# 2: "session_auth_token_xyz"
# 3 {
#   1: 1698574000
#   2: "192.168.1.50"
# }
```

### 3. Recovering Embedded `.proto` Descriptors from Binaries
Many production binaries compiled with standard Protobuf libraries retain the compiled descriptor data in `.rodata`:
- Scan the binary strings for `.proto` filenames:
  ```bash
  strings target_binary | grep -E "\.proto$"
  ```
- Look for `FileDescriptorProto` structures containing serialized metadata (package names, message names, field names).
- Use `pbtk` to extract the full schema:
  ```bash
  python3 -m pbtk.extractor.extract target_binary /tmp/recovered_proto/
  ```

### 4. gRPC Service Reconstruction
gRPC runs over HTTP/2 framing using binary Protobuf payloads:
1. **HTTP/2 Headers**:
   - `:path`: Follows the standard pattern `/<package>.<ServiceName>/<MethodName>`.
   - `content-type`: `application/grpc` or `application/grpc+proto`.
2. **gRPC Frame Header (5 Bytes)**:
   - Byte 0: Compression Flag (`0x00` = uncompressed, `0x01` = compressed).
   - Bytes 1–4: 32-bit big-endian length of the Protobuf payload.
3. Carve the Protobuf payload starting at byte 5 and pass to `protoc --decode_raw` or Wireshark gRPC dissector.

---

## Concrete Code / Script Examples

### 1. Python Stream Carver for PCAPs
```python
#!/usr/bin/env python3
"""
pcap_carver.py - Extract TCP streams and parse binary message framing.
"""
import struct
import sys

def parse_custom_protocol(raw_bytes):
    offset = 0
    msg_count = 0
    
    while offset + 8 <= len(raw_bytes):
        # Header: Magic(2B) = 0x5052 ("PR"), Opcode(2B), Length(4B big-endian)
        magic, opcode, length = struct.unpack_from(">HHI", raw_bytes, offset)
        
        if magic != 0x5052:
            # Re-synchronize stream by sliding 1 byte
            offset += 1
            continue
            
        header_len = 8
        if offset + header_len + length > len(raw_bytes):
            print(f"[-] Incomplete message at offset {offset}")
            break
            
        payload = raw_bytes[offset + header_len : offset + header_len + length]
        print(f"[+] Message #{msg_count}: Opcode=0x{opcode:04x}, Length={length}")
        print(f"    Payload: {payload[:32].hex()}...")
        
        offset += header_len + length
        msg_count += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <raw_stream.bin>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        parse_custom_protocol(f.read())
```

### 2. Wireshark Lua Dissector Template (`custom_proto.lua`)
```lua
-- custom_proto.lua - Wireshark dissector for proprietary TCP protocol
local custom_proto = Proto("custom_proto", "Custom Proprietary Protocol")

local f_magic   = ProtoField.uint16("custom_proto.magic", "Magic", base.HEX)
local f_opcode  = ProtoField.uint16("custom_proto.opcode", "Opcode", base.HEX)
local f_length  = ProtoField.uint32("custom_proto.length", "Payload Length", base.DEC)
local f_payload = ProtoField.bytes("custom_proto.payload", "Payload Data")

custom_proto.fields = { f_magic, f_opcode, f_length, f_payload }

function custom_proto.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()
    if buf_len < 8 then return end

    local magic = buffer(0, 2):uint()
    if magic ~= 0x5052 then return end

    pinfo.cols.protocol = "CUSTOM_PROTO"

    local subtree = tree:add(custom_proto, buffer(), "Custom Protocol Frame")
    subtree:add(f_magic, buffer(0, 2))
    subtree:add(f_opcode, buffer(2, 2))
    
    local length = buffer(4, 4):uint()
    subtree:add(f_length, buffer(4, 4))

    pinfo.cols.info = string.format("Opcode: 0x%04X, Len: %d", buffer(2, 2):uint(), length)

    if buf_len >= 8 + length then
        subtree:add(f_payload, buffer(8, length))
    end
end

-- Register dissector on target TCP port
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9999, custom_proto)
```

Run Wireshark or `tshark` with the Lua dissector:
```bash
tshark -X lua_script:custom_proto.lua -r capture.pcap -Y "custom_proto"
```

---

## Boundaries & Anti-Patterns
- **Do not invent field semantics without binary evidence**: Document field names only when backed by string literals, log output, or decompiler variable references.
- **Do not assume network integers are little-endian**: Standard network wire formats use big-endian (network byte order). Always verify whether conversion functions (`ntohl`, `be32toh`) are called in the disassembler.
- **Do not replay extracted messages against unauthorized live endpoints**: All protocol testing and mutation must occur against contained local stubs or isolated lab VMs.
