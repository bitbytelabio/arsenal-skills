# Rule 10: Subagent Delegation Boundaries

## Mandate
Complex, high-volume analytical sub-tasks must be delegated to dedicated, bounded subagents to protect the main reasoning thread from context saturation and distraction.

## Delegation Triggers
The lead agent must delegate analysis to a subagent when encountering any of the following conditions:
1. **Large Subroutines**: Functions where decompiler pseudocode or assembly exceeds 400 lines.
2. **Complex Data Structure Recovery**: Recovering multi-tier nested structures, C++ class hierarchies with multiple inheritance, or complex virtual method tables (vtables).
3. **Heavy Algorithmic Analysis**: Reconstructing custom cryptographic implementations, virtual machine (VM) bytecode dispatchers, obfuscated state machines, or control-flow flattened functions.

## Delegation Contract Requirements
When initiating a subagent delegation, the dispatch prompt must define:
1. **Target Artifact Reference**: Exact file path (e.g. `.re_scratch/<func_name>.c`) and virtual address range.
2. **Specific Objective**: Precise question to answer (e.g. "Identify the encryption algorithm and extract the key schedule initialization parameters").
3. **Explicit Non-Goals**: Constraints preventing scope creep (e.g. "Do not analyze callers or subsequent network transmission routines").
4. **Authoritative Context**: Essential struct layouts or confirmed types from `re_state.json`.

## Subagent Output & Reporting Contract
Subagents must return a crisp, structured analytical summary and are **FORBIDDEN** from spilling massive blocks of raw code or full disassembly back into the lead context.
Subagent output must consist solely of:
- Recovered function prototype and calling convention.
- Concise summary of core logic and control flow.
- Extracted cryptographic constants, magic numbers, or hardcoded strings.
- Formally confirmed or refuted hypothesis.
- Recommended struct and symbol definitions for inclusion in `re_state.json`.
