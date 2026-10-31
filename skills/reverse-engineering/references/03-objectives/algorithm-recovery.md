# Cryptographic Identification & Algorithm Recovery

## Title & Overview
- **Domain**: Cryptographic routines, custom encryption schemes, key scheduling, and hashing algorithms inside compiled binary artifacts.
- **Scope**: Cryptographic algorithm identification (FindCrypt, YARA rules, S-box constants for AES/DES/RC4, IVs), custom XOR/stream cipher recovery, key schedule analysis, and writing Python equivalence decoders.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Target contains encrypted configuration blocks, encrypted strings, or encrypted C2 traffic.
- Static screening reveals high-entropy data segments or cryptographic constants.
- Presence of substitution boxes (S-boxes), permutation tables, or initialization vectors (IVs).
- Code contains loops with extensive bitwise operations (`xor`, `rol`/`ror`, `shl`/`shr`, modular additions) characteristic of cryptographic primitives.

---

## Tooling & CLI/MCP Actions

### Primary Scanning & Triage Tools
- **Constant & Signature Scanners**:
  - `findcrypt-yara`: Scans binaries for hundreds of known cryptographic constant signatures.
  - Ghidra `FindCrypt` plugin / IDA Pro `FindCrypt3` plugin.
  - `signsrch`: Pattern matching tool for signatures and S-boxes.
- **Python Verification & Cryptographic Libraries**:
  - `cryptography`: High-performance Python library for AES, DES, ChaCha20, RSA.
  - `hashlib`, `hmac`: Standard hash algorithms.
  - CyberChef: Rapid recipe validation.

---

## Core Methodologies & Step-by-Step Technical Workflow

### 1. Cryptographic Algorithm Identification: Constants & S-Boxes

Standard ciphers and hashes rely on fixed mathematical constants that can be identified via signature scanning or binary search:

#### Cryptographic Constants Quick-Reference Table

| Algorithm | Key Characteristic Constants | Data Type / Representation |
|---|---|---|
| **AES (Rijndael)** | Forward S-Box: `0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5...`<br>Inverse S-Box: `0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38...`<br>Round Constants (Rcon): `0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80` | 256-byte substitution table |
| **DES / 3DES** | Initial Permutation (IP): `58, 50, 42, 34, 26, 18, 10, 2...`<br>S-Boxes (S1 - S8): 64-byte lookup tables | Fixed permutation / substitution arrays |
| **MD5** | Initial Constants: `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`<br>Sine table constants: `0xD76AA478`, `0xE8C7B756`... | Four 32-bit words |
| **SHA-1** | Initial Constants: `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`, `0xC3D2E1F0` | Five 32-bit words |
| **SHA-256** | Initial Hash: `0x6A09E667`, `0xBB67AE85`, `0x3C6EF372`, `0xA54FF53A`, `0x510E527F`, `0x9B05688C`, `0x1F83D9AB`, `0x5BE0CD19`<br>Round Constants: 64 constants (`0x428A2F98`, `0x71374491`...) | Eight 32-bit words |
| **ChaCha20 / Salsa20** | "expand 32-byte k" (`0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574`) | Four 32-bit constant words |
| **RC4** | S-Box initialization loop: `for i from 0 to 255: S[i] = i` | 256 sequential bytes `0x00` through `0xFF` |
| **CRC-32** | Polynomials: `0xEDB88320` (reversed) or `0x04C11DB7` | 1024-byte lookup table |

#### YARA Rule for Detecting AES S-Box
```yara
rule Detect_AES_SBox {
    meta:
        description = "Detects standard AES forward S-Box"
    strings:
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
    condition:
        $aes_sbox
}
```

### 2. Key Schedule & Mode Identification

Once the underlying algorithm is recognized from constants:
1. **Determine Key Length**:
   - For AES: Count the number of transformation rounds in the encryption loop.
     - 10 rounds $\rightarrow$ AES-128 (16-byte key)
     - 12 rounds $\rightarrow$ AES-192 (24-byte key)
     - 14 rounds $\rightarrow$ AES-256 (32-byte key)
2. **Determine Cipher Mode**:
   - **ECB Mode**: Encrypts 16-byte blocks independently with zero IV or feedback. Vulnerable to pattern leaks.
   - **CBC Mode**: Look for an XOR operation between the plaintext block and the previous ciphertext block (or IV for the first block) before the AES block transform.
   - **CTR Mode**: Look for an incrementing counter block (`counter++`) encrypted with AES, followed by XOR with the plaintext stream.
   - **GCM Mode**: Includes CTR mode encryption combined with GHASH (Galois field multiplication with polynomial `0xE100000000000000`).

### 3. Custom XOR & Stream Cipher Recovery

Adversaries frequently eschew standard cryptography in favor of custom rolling XOR or bitwise substitution loops to evade static signature detection.

#### Common Custom Transformation Patterns
- **Single-Byte XOR with Rolling Add**:
  ```c
  for (int i = 0; i < len; i++) {
      out[i] = in[i] ^ (key + (i * 0x13));
  }
  ```
- **Rotate-and-XOR (ROL/ROR)**:
  ```c
  for (int i = 0; i < len; i++) {
      out[i] = ((in[i] << 3) | (in[i] >> 5)) ^ key[i % key_len];
  }
  ```
- **Custom PRNG Stream Cipher (Linear Congruential Generator)**:
  ```c
  uint32_t seed = 0x12345678;
  for (int i = 0; i < len; i++) {
      seed = seed * 214013 + 2531011;
      out[i] = in[i] ^ ((seed >> 16) & 0xFF);
  }
  ```

---

## Concrete Code / Script Examples: Writing Python Equivalence Decoders

### Example 1: AES-CBC Decryptor with Hardcoded Key & IV Extraction
```python
#!/usr/bin/env python3
"""
decrypt_aes_blob.py - Decrypts extracted configuration buffer using AES-CBC.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

def decrypt_payload(ciphertext_bytes, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    
    # Strip PKCS#7 padding if present
    pad_len = plaintext[-1]
    if pad_len <= 16:
        plaintext = plaintext[:-pad_len]
        
    return plaintext

if __name__ == "__main__":
    # Key and IV recovered from .rodata at 0x403000 and 0x403020
    KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    IV  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    
    with open("encrypted_config.bin", "rb") as f:
        encrypted_data = f.read()
        
    decrypted = decrypt_payload(encrypted_data, KEY, IV)
    print(f"[+] Decrypted {len(decrypted)} bytes:")
    print(decrypted.decode("utf-8", errors="replace"))
```

### Example 2: Reversing a Custom Multi-Byte Rolling XOR Cipher
```python
#!/usr/bin/env python3
"""
decrypt_custom_xor.py - Equivalence decoder for proprietary rolling cipher.
Recovered from decompiler function at 0x00401820.
"""

def decode_rolling_xor(enc_bytes: bytes, seed: int) -> bytes:
    dec = bytearray()
    state = seed & 0xFFFFFFFF
    
    for b in enc_bytes:
        # State update: LCG step
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        key_byte = (state >> 16) & 0xFF
        # Bitwise rotation before XOR
        rotated = ((b >> 3) | (b << 5)) & 0xFF
        dec_byte = rotated ^ key_byte
        dec.append(dec_byte)
        
    return bytes(dec)

if __name__ == "__main__":
    # Sample ciphertext extracted from VMA 0x405080
    cipher_bytes = bytes.fromhex("7c 4e 89 2b f1 0d 9a 33")
    SEED = 0xDEADBEEF
    
    plain = decode_rolling_xor(cipher_bytes, SEED)
    print(f"[+] Recovered plaintext: {plain}")
```

---

## Boundaries & Anti-Patterns
- **Do not guess encryption algorithms based on naming alone**: A routine named `EncryptData` may implement a simple XOR or even Base64 encoding. Ground all algorithm classifications in verified mathematical constants and instruction sequences.
- **Do not confuse compression with encryption**: Formats like zlib/gzip or LZMA exhibit high entropy (> 7.5) and pseudo-random byte distributions. Check for standard compression headers (`0x78 0x9c` for zlib, `0x1f 0x8b` for gzip) before attempting cryptanalysis.
- **Do not deliver unverified decoders**: Always validate the Python equivalence decoder against a known sample ciphertext to ensure exact bit-for-bit equivalence.
