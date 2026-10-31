# Rule 9: Prohibited Anti-Patterns

## Mandate
The following patterns represent common operational failures in reverse engineering workflows and are **STRICTLY PROHIBITED**:

1. **Direct Decompilation of Packed Artifacts**:
   - Decompiling binaries with section entropy > 7.2 or detected packer signatures (UPX, ASPack, VMProtect, Themida) prior to unpacking or dumping the payload from memory at the Original Entry Point (OEP).

2. **Speculative Reference Preloading**:
   - Preloading architectural references for multiple unverified toolchains or languages simultaneously "just in case" without confirmed runtime triage markers.

3. **Context Window Flooding**:
   - Dumping more than 300–400 lines of raw assembly, unpruned decompiler pseudocode, monolithic ASTs, or long execution traces directly into the conversational context instead of utilizing `.re_scratch/`.

4. **Unbounded Dynamic Execution**:
   - Running target binaries, instrumentation scripts, or debuggers without strict process-level timeouts (e.g. executing `gdb` or the target binary directly without `timeout 30`).

5. **Ignoring Compiler and Runtime Markers**:
   - Treating Golang, Rust, or C++ binaries as generic raw C. Disregarding toolchain markers such as Go `pclntab` / type descriptors, Rust panic landing pads / core demangling symbols, or C++ RTTI / vtables identified during triage.

6. **Executing Outside Containment**:
   - Running, emulating, or debugging an untrusted sample on the host, or giving it live egress. Containment and the `egress` field are in `SKILL.md` and [malware-sandbox-isolation.md](../references/02-dynamic-instrumentation/malware-sandbox-isolation.md).

7. **Treating Silence As A Result**:
   - Reading an exit code of 0, an empty output, or a scanner with no hits as a negative. `analyzeHeadless` exits 0 when its post-script fails; a missing export file is a failed run. See [Rule 11](11-evidence-sufficiency.md).

8. **Capability-Negative Claims from Obfuscated Imports**:
   - Concluding that an artifact lacks specific capabilities (such as network communications, persistence, or process injection) based on a sparse, unreadable, or encrypted Import Address Table (IAT). Always verify whether dynamic API resolution (`LoadLibraryA`, `GetProcAddress`, API hashing) is in effect.
