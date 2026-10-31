# Cryptographic Identification & Algorithm Recovery

## Title & Overview
- **Domain**: Cryptographic routines, custom encryption schemes, key scheduling, hashing, and PRNG streams inside compiled binary artifacts.
- **Scope**: Algorithm identification from constants and instruction shapes, AES-NI / ARMv8 crypto-instruction recognition, key and IV recovery, mode detection, custom XOR/stream-cipher recovery, symbolic recovery of unknown transforms, and verification by reimplementation against published test vectors.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Target holds encrypted configuration blocks, encrypted strings, or an encrypted command channel.
- Triage reports high-entropy data segments or cryptographic constant hits.
- Substitution boxes (S-boxes), permutation tables, or initialization vectors appear in `.rodata`/`.rdata`.
- Loops with heavy bitwise work (`xor`, `rol`/`ror`, `shl`/`shr`, modular add) that look like a primitive.
- Dedicated crypto instructions (`aesenc`, `aese`, `sha256rnds2`, `pclmulqdq`) show up in the disassembly.

---

## Tooling & CLI Actions

### Constant & Signature Scanners
- **FindCrypt is a YARA ruleset, not a binary.** Run the published rules with the installed scanner:
  ```bash
  yr scan findcrypt.yar target.bin          # yara-x, installed here as `yr`
  yara findcrypt.yar target.bin             # classic yara
  ```
- **`capa`** flags crypto capabilities from its rule set: `capa target.bin` (install `uv tool install flare-capa`).
- **`signsrch`** matches thousands of constant/S-box patterns (build from source).
- In-tool: IDA `findcrypt` plugin, Ghidra `findcrypt`/`FindCrypt` script.
- **radare2** has a quick scanner: `rabin2 -g target` plus `rafind2 -x <hexpattern> target` to locate a known table by bytes.

### Verification Libraries
- `pycryptodome` (`from Crypto.Cipher import AES, ChaCha20`), `cryptography`, stdlib `hashlib`/`hmac`. Run throwaway checks with `uv run --with pycryptodome python -I ...`.
- CyberChef for fast recipe trials (`npx cyberchef` or the web app).
- `z3-solver` for recovering unknown byte transforms (`uv run --with z3-solver python -I ...`).

---

## 1. Algorithm Identification: Constants & S-Boxes

Fixed mathematical constants are the fastest fingerprint. Match the first bytes of a table, then confirm by reimplementation. All constants below are verified.

### 1.1 Block Ciphers & Hashes

| Algorithm | Characteristic constants | Shape |
|---|---|---|
| **AES (Rijndael)** | Forward S-box starts `63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76`. Inverse S-box starts `52 09 6A D5 30 36 A5 38`. Rcon: `01 02 04 08 10 20 40 80 1B 36`. T-tables (`Te0..Te3`, `Td0..Td3`) start `C6 63 63 A5 ...` (1 KiB each) | 256-byte S-box, four 1 KiB T-tables in table-driven builds |
| **DES / 3DES** | IP table `58 50 42 34 26 18 10 02 ...`; eight 64-entry S-boxes; PC-1/PC-2 key schedule tables | Permutation + substitution arrays |
| **Blowfish** | P-array seeded from π: `0x243F6A88 0x85A308D3 0x13198A2E 0x03707344 ...` (18 words) plus four 256-entry S-boxes | 18-word P-array + 4×256 S-boxes |
| **MD5** | IV `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476`; T-table `0xD76AA478 0xE8C7B756 0x242070DB 0xC1BDCEEE ...` (64 `floor(2^32·abs(sin(i)))` words) | 4 IV words + 64 round constants |
| **SHA-1** | IV `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0`; round K `0x5A827999 0x6ED9EBA1 0x8F1BBCDC 0xCA62C1D6` | 5 IV words + 4 K words |
| **SHA-256** | IV `0x6A09E667 0xBB67AE85 0x3C6EF372 0xA54FF53A 0x510E527F 0x9B05688C 0x1F83D9AB 0x5BE0CD19`; 64 K words start `0x428A2F98 0x71374491 0xB5C0FBCF 0xE9B5DBA5 ...` | 8 IV words + 64 K words |
| **SHA-512 / SHA-384** | 64-bit IV `0x6A09E667F3BCC908 0xBB67AE8584CAA73B ...` (SHA-512); SHA-384 differs only in IV; 80 K words start `0x428A2F98D728AE22 0x7137449123EF65CD ...` | 8 + 80 64-bit words |
| **CRC-32** | Reflected poly `0xEDB88320`, normal poly `0x04C11DB7`; 256-entry (1 KiB) table | Lookup table or bit-by-bit loop |
| **CRC-32C (Castagnoli)** | Reflected poly `0x82F63B78`; often via `crc32` SSE4.2 instruction | Table or `crc32` opcode |

### 1.2 Stream Ciphers & Lightweight Primitives

| Algorithm | Constants / shape |
|---|---|
| **ChaCha20** | `"expand 32-byte k"` = little-endian words `0x61707865 0x3320646E 0x79622D32 0x6B206574`; 16-word state, quarter-round `a+=b; d^=a; d<<<=16; ...` with rotations 16,12,8,7 |
| **Salsa20** | Same `"expand 32-byte k"` words, different word layout; rotations 7,9,13,18 |
| **TEA / XTEA / XXTEA** | delta `0x9E3779B9`, 32 (or 64) Feistel rounds, shifts by 4 and 5 |
| **RC4** | KSA: 256-byte S filled `S[i]=i` for i in 0..255, then `j=(j+S[i]+key[i%len])&0xFF; swap`. PRGA swaps and emits `S[(S[i]+S[j])&0xFF]`. No constants — recognize the 0..255 fill and swaps |
| **xorshift64\*** | multiplier `0x2545F4914F6CDD1D`, shifts 12/25/27 |
| **xorshift32/128** | shift triples such as 13,17,5 or 11,8,19 |
| **splitmix64** | increment / golden-ratio constant `0x9E3779B97F4A7C15` (also used as a mix constant; not an algorithm by itself) |
| **LCG (glibc/MSVC)** | glibc `rand`: `*1103515245 + 12345`; MSVC `rand`: `*214013 + 2531011`, output `(seed>>16)&0x7FFF` |
| **MurmurHash3** | `0xCC9E2D51`, `0x1B873593`; finalizer `0x85EBCA6B`, `0xC2B2AE35` |
| **FNV-1a** | offset `0x811C9DC5` (32), `0xCBF29CE484222325` (64); prime `0x01000193` / `0x100000001B3` |
| **GHASH (AES-GCM)** | reduction poly `0xE1000000...` (`R = 0xE1 << 120`), or `pclmulqdq` for carryless multiply |

### 1.3 Base64 & Encoding Alphabets
Base64 is encoding, not encryption. Recognize the alphabet, then check for a **custom** one:
- Standard: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
- URL-safe: `...+/` replaced by `-_`.
- A reordered or substituted 64-char table in `.rodata` is a custom alphabet. Carve the exact 64 bytes and feed them to CyberChef's "From Base64" with the custom alphabet, or `base64.b64decode` after `str.maketrans`.

### 1.4 AES-NI and ARMv8 Crypto Instructions
Hardware crypto removes the constant tables, so scan for the opcodes instead:
- **x86 AES-NI**: `aesenc`, `aesenclast`, `aesdec`, `aesdeclast`, `aesimc`, `aeskeygenassist`. Ten `aesenc` + one `aesenclast` per block means AES-128; fourteen means AES-256.
- **x86 SHA extensions**: `sha1rnds4`, `sha1nexte`, `sha256rnds2`, `sha256msg1/2`.
- **x86 carryless multiply**: `pclmulqdq` signals GHASH/GCM or CRC.
- **ARMv8 (AArch64)**: `aese`/`aesd` (+ `aesmc`/`aesimc`), `sha256h`/`sha256h2`/`sha256su0/1`, `pmull`/`pmull2` for GHASH.
- The round key schedule still lives in memory. Set a read watchpoint on the key buffer, or dump the expanded key, even when the rounds run on hardware.

---

## 2. Key Schedule, IV, and Mode Recovery

### 2.1 Key length from round count
- AES: 10 rounds → AES-128 (16-byte key), 12 → AES-192 (24), 14 → AES-256 (32). The expanded key is 176 / 208 / 240 bytes.

### 2.2 Mode identification
- **ECB**: each 16-byte block transformed independently; identical plaintext blocks produce identical ciphertext (visible as repeats).
- **CBC**: plaintext XORed with the previous ciphertext block (IV for block 0) before the block transform. Look for a 16-byte XOR feeding the cipher input.
- **CTR**: a counter block is encrypted, then XORed with the stream. Look for `counter++` and no feedback from ciphertext.
- **GCM**: CTR plus GHASH (`pclmulqdq`/`pmull` or the `0xE1...` reduction), a 12-byte nonce, and a 16-byte tag compared at the end.

### 2.3 Recovering key and IV
- Hardcoded: carve from `.rodata`/`.rdata` at the address the cipher init reads. Record the VMA and file offset.
- Derived: find the KDF (PBKDF2 = HMAC loop with an iteration count; scrypt/argon2 = large memory buffer). Record salt, iteration count, and output length.
- Runtime-only: set a breakpoint or Frida hook on the cipher-init call and read the key/IV arguments. A runtime key stays `runtime-only` until re-anchored to a static buffer (Rule 4).

---

## 3. Custom XOR & Stream-Cipher Recovery

Adversaries prefer custom rolling XOR or bitwise loops to dodge signature scans.

### Common shapes
- **Single-byte XOR with rolling add**:
  ```c
  for (int i = 0; i < len; i++)
      out[i] = in[i] ^ (uint8_t)(key + i * 0x13);
  ```
- **Rotate-and-XOR**:
  ```c
  for (int i = 0; i < len; i++)
      out[i] = (uint8_t)((in[i] << 3) | (in[i] >> 5)) ^ key[i % key_len];
  ```
- **LCG-keystream XOR** (MSVC `rand` shape):
  ```c
  uint32_t seed = 0x12345678;
  for (int i = 0; i < len; i++) {
      seed = seed * 214013 + 2531011;
      out[i] = in[i] ^ ((seed >> 16) & 0xFF);
  }
  ```

Watch the integer width: a `movsx`/`cdqe` on the key index changes the arithmetic. Take the width from the instruction, not the decompiler type (see case-patterns section 6).

---

## 4. Verify By Reimplementation (Test Vectors)

A classification is a `candidate` until a reimplementation reproduces a known input/output pair. Use published test vectors.

### 4.1 Confirm an AES identification (FIPS-197 vector)
```python
# uv run --with pycryptodome python -I check_aes.py
from Crypto.Cipher import AES
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
ct  = AES.new(key, AES.MODE_ECB).encrypt(pt)
assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
print("AES-128 matches FIPS-197")
```
If the sample's table-driven routine produces this vector, the identification is confirmed, not guessed.

### 4.2 AES-CBC decryptor with recovered key/IV
```python
# uv run --with pycryptodome python -I decrypt_blob.py encrypted_config.bin
import sys
from Crypto.Cipher import AES

def decrypt(ct, key, iv):
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    # Validate PKCS#7 before stripping; do not blindly trust pt[-1].
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    return pt

if __name__ == "__main__":
    KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")  # .rodata 0x403000
    IV  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # .rodata 0x403020
    data = open(sys.argv[1], "rb").read()
    out = decrypt(data, KEY, IV)
    print(out.decode("utf-8", "replace"))
```

### 4.3 Custom rolling-XOR decoder
```python
# uv run python -I decode_custom.py
def decode(enc: bytes, seed: int) -> bytes:
    out = bytearray()
    state = seed & 0xFFFFFFFF
    for b in enc:
        state = (state * 214013 + 2531011) & 0xFFFFFFFF  # MSVC LCG
        k = (state >> 16) & 0xFF
        rot = ((b >> 3) | (b << 5)) & 0xFF               # ror 3
        out.append(rot ^ k)
    return bytes(out)

if __name__ == "__main__":
    cipher = bytes.fromhex("7c4e892bf10d9a33")  # VMA 0x405080
    print(decode(cipher, 0xDEADBEEF))
```
Validate against one known plaintext (a magic header, a URL prefix, a JSON `{`). Bit-for-bit match promotes the decoder; anything less stays `candidate` (Rule 11).

---

## 5. Recovering an Unknown Transform with Z3

When the check is `transform(input) == stored` and the transform is a chain of bitwise ops too tangled to invert by hand, model it symbolically.

```python
# uv run --with z3-solver python -I solve_input.py
from z3 import BitVec, Solver, sat
# Example: the binary computes (in[i] ^ 0x5A) + i and compares to `target`.
target = [0x3a, 0x2f, 0x30, 0x31, 0x40, 0x41, 0x42, 0x43]
b = [BitVec(f"b{i}", 8) for i in range(len(target))]
s = Solver()
for i, t in enumerate(target):
    s.add((b[i] ^ 0x5A) + i == t)
    s.add(b[i] >= 0x20, b[i] < 0x7f)         # printable-ASCII constraint
assert s.check() == sat
m = s.model()
print(bytes(m[x].as_long() for x in b))
```
For whole functions, lift with angr/Triton and let the SMT backend solve for the input that reaches the accepting block. Z3 is the right tool when brute force is the wrong scale (a 4-byte group is `256^4`); see case-patterns section 1 (lattice/CVP and boolean-circuit rows).

---

## Boundaries & Anti-Patterns
- **Do not name an algorithm from a symbol alone.** A routine called `EncryptData` may be XOR or Base64. Ground every classification in a verified constant, an instruction sequence, or a reproduced test vector.
- **Do not confuse compression with encryption.** zlib/gzip/LZMA also look high-entropy. Check headers first: zlib `78 9C` (also `78 01`/`78 DA`), gzip `1F 8B`, zstd `28 B5 2F FD`, LZMA `5D 00 00`, bzip2 `42 5A 68`.
- **Do not ship an unverified decoder.** Reproduce one known plaintext before promoting (Rule 11, "decoder or checker").
- **A hardware-crypto build has no tables.** Absence of an S-box is not absence of AES; scan for `aesenc`/`aese` and dump the expanded key.
