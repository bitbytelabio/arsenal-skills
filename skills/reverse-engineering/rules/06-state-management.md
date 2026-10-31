# Rule 6: State Ledger Management (`re_state.json`)

## Mandate
Maintain an authoritative, structured JSON state file (`re_state.json`) in the project or scratch directory throughout the reverse engineering lifecycle. Analysis progress, hypotheses, and recovered types must be committed to this state ledger rather than relying on transient conversational context.

## Schema & Required Fields
`re_state.json` must contain the following core structures:
```json
{
  "triage": {
    "target_path": "sample.bin",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "format": "ELF64",
    "architecture": "x86_64",
    "toolchain": "Go 1.21",
    "is_packed": false,
    "entry_point": "0x452000",
    "egress": "offline"
  },
  "hypotheses": [
    {
      "id": "H-001",
      "statement": "sub_401120 performs AES-256-CBC decryption of the configuration payload.",
      "confidence": 0.85,
      "status": "confirmed",
      "evidence": "Rijndael S-box constant 0x637c777b referenced at 0x401145; key schedule loop matches AES expanded key size."
    }
  ],
  "symbols": {
    "0x401120": {
      "name": "aes_decrypt_config",
      "type": "function",
      "prototype": "int __fastcall aes_decrypt_config(uint8_t *in, size_t len, uint8_t *key, uint8_t *out)"
    }
  },
  "structs": {
    "ConfigHeader": {
      "size": 32,
      "fields": [
        {"offset": 0, "name": "magic", "type": "uint32_t"},
        {"offset": 4, "name": "payload_len", "type": "uint32_t"},
        {"offset": 8, "name": "iv", "type": "uint8_t[16]"},
        {"offset": 24, "name": "checksum", "type": "uint32_t"}
      ]
    }
  },
  "critical_addresses": {
    "oep": "0x401000",
    "main_dispatch": "0x402500"
  },
  "findings": [
    {
      "id": "F-001",
      "status": "candidate",
      "statement": "Configuration blob at file offset 0x2000 decrypts with the key at 0x403000.",
      "evidence": ["E-sbox-0x401145"]
    }
  ],
  "dead_ends": [
    {
      "id": "D-001",
      "tried": "angr explore from 0x401120",
      "why_stopped": "Path explosion in the dispatcher; no new observation."
    }
  ],
  "artifacts": {
    "scratch_files": [
      ".re_scratch/sub_401120.c",
      ".re_scratch/cfg_dispatch.dot"
    ],
    "memory_dumps": [
      ".re_scratch/payload_unpacked_0x400000.bin"
    ]
  }
}
```

## Ledger Synchronization Rules
1. **Immediate Writeback**: Persist updates to `re_state.json` immediately upon completing an analytical step, recovering a symbol, or refuting/confirming a hypothesis.
2. **Deterministic Context Reloading**: When resuming an analytical track or delegating to subagents, load context directly from `re_state.json` to guarantee continuity across turns.
3. **Stage Handoff**: A stage change records a one-line `decision_delta` (what changed the next action) and the ledger paths that still apply. Do not restate unchanged triage, scope, or hypotheses.
4. **Finding Status**: Hypothesis `status` is `open`, `confirmed`, or `refuted`. Finding `status` is defined only in [Rule 11](11-evidence-sufficiency.md). A confirmed hypothesis is not automatically a validated finding. `egress` is `offline`, `lab_only`, or `authorized_target_only`, and it is set before any command that can emit a packet.
