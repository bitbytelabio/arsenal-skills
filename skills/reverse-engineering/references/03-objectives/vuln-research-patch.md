# Vulnerability Research, Patch Analysis & Binary Diffing

## Title & Overview
- **Domain**: Binary diffing, 1-day vulnerability analysis, patch reversal, and symbol/type propagation across binary revisions.
- **Scope**: Structural and graph-based diffing with BinDiff and Ghidra BSim, Control Flow Graph (CFG) matching, 1-day patch diffing (distinguishing security fixes from routine refactoring), CVE root cause analysis, and symbol porting from debug/analyzed builds to stripped production binaries.

---

## Trigger Conditions & Detection Indicators
When to open this reference:
- Task involves analyzing two versions of a binary (e.g., pre-patch vs post-patch releases, Patch Tuesday updates, security hotfixes).
- Need to locate the exact vulnerability fix described vaguely in a CVE advisory or vendor bulletin.
- Need to understand root causes of memory corruption, logic flaws, integer overflows, or improper input validation.
- Need to port function names, type libraries, and structure definitions from an unstripped build or older analyzed IDB/GZF database to a new, stripped target binary.

---

## Tooling & CLI/MCP Actions

### Primary Binary Diffing Engines
- **BinDiff (Google)**:
  - Industry-standard graph-based diffing tool.
  - Generates `.BinExport` databases from IDA Pro or Ghidra and executes isomorphism and heuristic graph matching.
  - Command: `bindiff --primary=<unpatched.BinExport> --secondary=<patched.BinExport> --output_dir=<diff_out>`.
- **Ghidra BSim**:
  - Feature vector and semantic LSH (Locality Sensitive Hashing) matching engine built into Ghidra.
  - Matches functions across large corpora without requiring full 1:1 binary alignment.
- **Diaphora**:
  - Open-source pure-Python diffing engine for IDA Pro; provides deep AST-level and decompiled C-code diffing.
- **Radare2 `radiff2`**:
  - Rapid CLI-based binary delta, graph diffing, and opcode distance comparison.
  - Commands: `radiff2 -c file1 file2` (count differences), `radiff2 -g main file1 file2` (CFG diff).

---

## Core Methodologies & Step-by-Step Technical Workflow

### 1. Database Preparation & Binary Normalization
Binary diffing quality depends strictly on the quality and normalization of the underlying decompilation databases:
1. **Match Compiler & Environment Constraints**:
   - Verify that both samples share the same architecture, bitness, and calling conventions.
   - Address space shifts (ASLR) are normalized away by graph algorithms, but different compiler optimization flags (`-O2` vs `-O0`) will introduce substantial false positives.
   - **Windows updates are deltas, not whole files.** An MSU/MSP/cab since Windows 10 contains forward or reverse deltas. Reconstruct the full patched binary from the delta plus a baseline of the same file before diffing. Diffing the raw delta, or a baseline of a different build, produces garbage.
2. **Export BinExport Databases**:
   - In IDA Pro: Run auto-analysis to completion, then invoke `File -> Produce file -> Create BinExport file...`.
   - In Ghidra: Use the Ghidra BinExport extension exporter.

### 2. Control Flow Graph (CFG) Matching Algorithms
BinDiff and Diaphora employ a sequence of heuristic passes to correlate functions and basic blocks:

```text
Pre-Patch Binary                               Post-Patch Binary
+-------------------------+                    +-------------------------+
| Function sub_401100     |                    | Function sub_401200     |
| [Block A]               |                    | [Block A']              |
|   mov rdi, [rbx+8]      | -- Exact Hash ---> |   mov rdi, [rbx+8]      |
|   call sub_402000       |                    |   call sub_402000       |
+-------------------------+                    +-------------------------+
            |                                               |
            v                                               v
+-------------------------+                    +-------------------------+
| [Block B: Unbounded]    |                    | [Block B': Added Check] |
|   mov rsi, rax          |                    |   cmp rax, 0x1000       |
|   call memcpy           |                    |   ja error_handler      |
+-------------------------+                    +-------------------------+
                                                            | (False path)
                                                            v
                                               +-------------------------+
                                               | [Block C': Guarded]     |
                                               |   mov rsi, rax          |
                                               |   call memcpy           |
                                               +-------------------------+
```

1. **Exact Matching**: Identical instruction byte hashes.
2. **Call Graph Isomorphism**: Correlating functions based on identical incoming and outgoing caller/callee graphs.
3. **Control Flow Graph Isomorphism**: Matching block topology, edge counts, and cyclomatic complexity.
4. **Instruction Count & Register Flow Heuristics**: Scoring basic block similarity between 0.0 (completely dissimilar) and 1.0 (identical).

### 3. 1-Day Patch Diffing: Security Fixes vs Compiler Refactoring

When diffing vendor updates, dozens or hundreds of functions may show slight differences. Sort by similarity just below 1.0 first: a security fix is usually one added check in a function that otherwise matches, not a function that is entirely new or gone. Entirely new functions stay leads until a reachable path says otherwise. Then apply heuristic filtering:

#### Heuristic Indicators of Security Fixes

| Patch Pattern | Added Code Signs (Post-Patch) | Identified Bug Class |
|---|---|---|
| **New Bounds / Length Check** | `cmp reg, imm; jbe / jae` or `test reg, reg; js` before `memcpy`, array indexing, or buffer reads | Buffer Overflow / Out-Of-Bounds (OOB) Write |
| **Integer Arithmetic Validation** | `add reg, reg; jc overflow_exit` or `mul` followed by `jo` | Integer Overflow / Underflow leading to tiny allocation |
| **Pointer Validation / Null Check** | `test reg, reg; jz error_exit` or checking object state flags | Null Pointer Dereference / Use-After-Free (UAF) |
| **Safe API Substitution** | Call to `strcpy` / `sprintf` replaced with `strcpy_s` / `snprintf_s` / `StringCchCopyW` | Classic String Buffer Overflow |
| **Reference Count / Lifetime Change** | Added calls to `AddRef()` / `Release()`, or zeroing out pointers immediately after `free()` | Double-Free / Use-After-Free |
| **Input Parsing Validation** | Added type checks, enum range checks, or sanity checks on packet headers | Deserialization Flaw / Type Confusion |

#### Filtering Out Benign Refactoring Noise
- Ignore functions where changes consist solely of register reallocation (`mov rbx, rax` vs `mov r12, rax`).
- Ignore changes caused by compiler inlining (a function disappears because the compiler inlined its 3 instructions into callers).
- Ignore relocation base address changes or timestamp updates in PE headers.

### 4. CVE Root Cause Analysis Workflow

Once the patched function and basic block are identified:
1. **Analyze the Added Check**:
   - Determine what state or value is rejected by the new branch.
   - Example: If the new code adds `if (size > 0x1000) return E_INVALIDARG;`, the unpatched binary allowed `size > 0x1000`.
2. **Trace Backwards to Sources (Taint Analysis)**:
   - Identify where the unguarded variable originates: Is it parsed from network packet data? Read from an untrusted file header? Passed via an IPC interface?
   - Trace backwards through callers using cross-references (`xrefs_to`) until the untrusted input source is reached.
3. **Verify Reachability**:
   - Prove that untrusted input can reach the vulnerable basic block without encountering prior sanitizing checks.
   - If no untrusted path can reach the unpatched instruction, the change may represent defensive dead-code hardening rather than an exploitable vulnerability.

### 5. Symbol & Type Porting Pipeline

Porting symbols from an analyzed or debug build into a stripped production binary:
1. In BinDiff:
   - Match functions between the source IDB (with symbols/types) and target IDB (stripped).
   - Filter for functions with **Similarity ≥ 0.95** and **Confidence ≥ 0.90**.
   - Select matched functions, right-click -> `Import Symbols and Comments`.
2. In Ghidra:
   - Use the **Version Tracking** tool (`Tools -> Version Tracking`).
   - Create a Version Tracking session pairing the two binaries.
   - Run Exact Symbol Name Match, Exact Function Bytes Match, and BSim Function Match correlators.
   - Apply Markup Items (Function Names, Signatures, Parameter Names, Local Variables).
3. **Migrate outward from a reliable anchor, one function at a time.** Exports first, then unchanged strings, then rare constants. A renamed callee becomes the next anchor. Do not submit a whole binary to a matcher or a model in one pass. Spot-check a sample of renames against the anchor's call before trusting the batch. A wrong anchor poisons every name derived from it. This is symbol migration. A security conclusion still has to pass section 4.

---

## Concrete Script Example: Automated radiff2 Delta Screening

```python
#!/usr/bin/env python3
"""
radiff_triage.py - Quick CLI triage of function changes between two binaries.
"""
import subprocess
import json
import sys

def triage_diff(bin_old, bin_new):
    print(f"[*] Comparing {bin_old} and {bin_new}...")
    
    # Run radiff2 in JSON mode
    cmd = ["radiff2", "-c", bin_old, bin_new]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[*] Byte delta count: {res.stdout.strip()}")

    # Compare functions
    cmd_funcs = ["radiff2", "-C", bin_old, bin_new]
    res_funcs = subprocess.run(cmd_funcs, capture_output=True, text=True)
    
    print("\n[*] Changed Functions Summary:")
    for line in res_funcs.stdout.splitlines():
        if "UNMATCH" in line or "DIFF" in line:
            print(f"  {line}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <unpatched_bin> <patched_bin>")
        sys.exit(1)
    triage_diff(sys.argv[1], sys.argv[2])
```

---

## Boundaries & Anti-Patterns
- **Do not assume every diff is a security vulnerability**: Compilers frequently reorder functions, inline tiny subroutines, or adjust alignment padding across builds. Focus strictly on functional branch changes and validations.
- **Do not analyze patches in isolation from input reachability**: A bug is only a security vulnerability if untrusted external input can trigger the unpatched condition.
- **Do not diff binaries compiled with disparate toolchains or debug flags**: Diffing Release vs Debug builds generates overwhelming noise that obscures real security patches.
- **A vulnerability is four located facts**: a source the attacker controls, a sink that misbehaves, the guard that should have stopped it and why that guard fails, and who is harmed. Anything less stays a hypothesis. "Safe" means you named that guard: which variable, which bound, signed or unsigned, on every path. If you cannot name it, the answer is unresolved.
- **A silent tool is not a clean result**: capa, a decompiler, and an empty dynamic run over-report or under-report. A hit is a candidate. Silence is an unasked question. A target with no input channel cannot produce dynamic evidence. A `likely` defect reported as `confirmed` is a false promotion even when the defect is real.
