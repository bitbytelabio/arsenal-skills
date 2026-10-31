# Rule 4: The Static ↔ Dynamic Loop

## Mandate
Static analysis is the foundational analytical phase and must precede dynamic execution. Dynamic instrumentation must not be invoked as an alternative to reading accessible static code. Transition from static to dynamic analysis is permitted **ONLY** under three specific conditions:
1. **Heavy Packing or Encryption**: Binary sections are compressed, encrypted, or virtualized (entropy > 7.2), preventing meaningful static decompilation until the code is unpacked or dumped at the Original Entry Point (OEP).
2. **Ephemeral Runtime Values**: Required program states cannot be computed statically within reasonable time bounds (e.g. dynamically resolved jump tables, runtime-decrypted configuration blobs, ephemeral session keys, dynamically resolved API addresses).
3. **Falsifiable Hypothesis Verification**: Validating an explicit input/output transformation, cryptographic routine behavior, or state machine transition where dynamic hooking or test vector validation proves or disproves a specific hypothesis faster than static symbolic execution.

## Loop Discipline & Return to Static Analysis
Dynamic analysis is an ephemeral probe, not a permanent working state. Upon capturing the required runtime values or validating the target hypothesis:
1. **Immediate Teardown**: Terminate dynamic tracing and detach debuggers or instrumentation hooks.
2. **Re-anchor to Static Base**: Map captured runtime addresses, resolved APIs, and decrypted strings back to the static disassembly/decompilation database.
3. **Persist Findings**:
   - Rename functions and global variables in IDA Pro / Ghidra.
   - Define and apply recovered structs to static operands.
   - Update `re_state.json` with recovered symbols, keys, and memory offsets.
4. **Resume Static Tracing**: Continue static path analysis using the newly enriched symbol and type definitions.

A runtime value that cannot be re-anchored to the static image stays `runtime-only` and cannot be validated. Promotion rules are in [Rule 11](11-evidence-sufficiency.md).
