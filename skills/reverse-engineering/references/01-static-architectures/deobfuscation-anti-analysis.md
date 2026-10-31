# Deobfuscation & Anti-Analysis Countermeasures

## Title & Overview
- **Domain**: Deobfuscation architectures, compiler-level obfuscator countermeasures (OLLVM variants), Mixed Boolean-Arithmetic (MBA) simplification, and systemic anti-analysis bypasses across Linux and Windows.
- **Scope**: Modern reverse engineering techniques against Hikari, goron/Arkari, Pluto/Polaris, O-MVLL, amice, and Tigress. Automated MBA simplification using SMT/Z3, Arybo, and Triton. Comprehensive bypasses for anti-debugging, anti-VM, anti-DBI (Frida), and timing evasion.

---

## 0. Recover At The API Boundary Before Lifting

Identify the protector, then take the cheapest layer that answers the question. Order: decrypted strings, then control flow, then a VM lift. A runtime dump beats a static devirtualizer that was built for one version. When the lift is blocked, recover the logic by staged fuzzing of input/output and handler coverage. That procedure is [fuzzing-for-reversing.md](../02-dynamic-instrumentation/fuzzing-for-reversing.md).

Hook the function that consumes the secret, not the decryptor. `strcmp`, `dlsym`, `GetProcAddress`, JNI `FindClass` / `GetMethodID` / `NewStringUTF`, and file opens receive plaintext no matter which packer produced it. Filter by return address so only calls from the target module are kept. An unqualified export match with zero hits is ambiguous. Retry as `Module!symbol`.

On Android, unpacking often finishes inside `JNI_OnLoad`. A legitimate `.so` almost never has an `RWX` segment. Watch `mprotect`: `r-x` to `rwx` and back to `r-x` is the dump point. Identify the module by an export at a known offset, not by a filename the packer can change. Section names `.vmp0`, `.themida`, `.cv0` select the protector. The lift, if you still need it, is section 3 below.

## 1. Modern OLLVM Variant Ecosystem

Obfuscator-LLVM has evolved from simple legacy passes into commercial and advanced adversarial hardening frameworks. Identifying the specific compiler pass variant is mandatory before selecting an automated deobfuscator:

### OLLVM Variant Taxonomy
| Variant | Base LLVM | Core Obfuscation Primitives | Vulnerability & Countermeasure Strategy |
|---|---|---|---|
| **Hikari** | LLVM 6–8 | Anti-Class-Dump, Function Call Obfuscation, Function Wrapper, Indirect Branching, Basic Block Splitting, String Encryption. | Decrypt string tables first using emulation (Unicorn); trace wrapper trampolines back to real target addresses. |
| **Hikari-LLVM15+** | LLVM 15–19 | Constant Encryption, Anti-Debugging, Anti-Hooking, Function Splitting. | Dynamic execution of decryption stubs; patch anti-debug routines in memory. |
| **goron / Arkari** | LLVM 7–14+ | Indirect Jump / Indirect Call via `BR x8` / `jmp [rax]`, Global Variable encryption. | **Data Section Read-Only Counter**: Mark the data section read-only; forces indirect jump targets to resolve statically or deterministically. Use `DeObfBR`. |
| **Pluto / Polaris** | LLVM 14–16 | MBA Obfuscation, Random CF, **Trap Angr** (designed to trigger path explosion in symbolic execution engines), Dirty Bytes, Linear MBA. | **Trap Angr Bypass**: Avoid bare `angr` path exploration. Use `d810-ng` Z3 rules or Unicorn micro-emulation to evaluate target blocks directly. |
| **O-MVLL** | LLVM / Python | Python-driven pass manager: Anti-Hooking, Arithmetic MBA, Basic Block Duplicate, CF Breaking, Indirect Call, Opaque Constants. | Common in modern Android/iOS security modules. Profile Python configuration patterns; strip dead CF blocks with peephole microcode rules. |
| **amice** | Rust LLVM | VM Flatten, Instruction Virtualization, Delayed Offset Loading, Parameter Aggregation. | **VM Flatten Counter**: Do not treat as basic switch flattening. Reverse the bytecode interpreter, decode virtual opcode dispatch tables, and lift virtual handlers. |

---

## 2. De-flattening Decision Matrix

When confronting Control Flow Flattening (CFF) exhibiting central dispatcher loops and state variables:

```text
Control Flow Flattening Detected (while/switch loop)
  │
  ├── IDA Pro Hex-Rays Environment Available?
  │     ├── YES (Microcode-level approach):
  │     │     ├── Cloud service acceptable & max fidelity required:
  │     │     │     └── obpo-plugin (Microcode + program slicing + concolic execution)
  │     │     └── Local, offline requirement (Air-gapped / confidential):
  │     │           └── d810-ng (Microcode rules + Z3 SMT solver, Tigress/Hodur support)
  │     │
  │     └── NO (Alternative or script environment):
  │           ├── Binary Ninja Environment:
  │           │     └── ollvm-breaker (Tailored for mobile ELF/shared objects)
  │           ├── Pure CLI / Python Script:
  │           │     ├── x86/x64 Binaries:
  │           │     │     └── ollvm-unflattener (Miasm symbolic execution + BFS propagation)
  │           │     ├── ARM64 Android .so:
  │           │     │     └── deollvm (Unicorn-engine emulator deflat)
  │           │     └── CTF / Custom Pipeline:
  │           │           └── angr Deobfuscator (with path explosion bounding)
```

### Tool Execution Guides

#### 1. d810-ng (IDA Pro Plugin)
- Install into IDA plugins directory. Press `Ctrl+Shift+D` inside Hex-Rays view.
- Select rule categories:
  - `Unflattener`: Standard OLLVM switch/state variable machines.
  - `UnflattenerSwitchCase` & `UnflattenerTigressIndirect`: Tigress `m_jtbl` and `m_ijmp`.
  - `HodurUnflattener`: PlugX nested `while(1)` without central switch.
  - `Predicate Simplification`: Strips opaque predicates (`setz`, `setnz`).

#### 2. Binary Ninja ollvm-breaker
```bash
# In Binary Ninja Python console or standalone script
from ollvm_breaker import Deflattener
deflat = Deflattener(bv, func_addr=0x10040)
deflat.run()
```

#### 3. Miasm ollvm-unflattener
```bash
python3 unflattener.py -i obfuscated_elf -o cleaned_elf -t 0x401200 -a
# Flag -a recursively processes nested call targets via Breadth-First Search
```

---

## 2.1 Complete OLLVM Control Flow Flattening (CFF / `fla`) Recovery Algorithm

Control Flow Flattening transforms normal hierarchical and loop control structures into an iterative state machine with a centralized dispatcher. Recovering the original control flow requires a deterministic 4-phase algorithm.

### 1. Basic Block Categorization
In flattened functions, basic blocks fall into five strict structural classes:

```text
                [ Prologue Block ] (Initializes state_var = S0)
                        │
                        ▼
        ┌──────►[ Dispatcher Block ] ◄─────────────────────────────────┐
        │               │                                              │
        │               ▼                                              │
        │       [ Sub-Dispatchers ] (Binary decision trees / switch)   │
        │         │             │                                      │
        │         ▼             ▼                                      │
        │   [Relevant BB 1]  [Relevant BB 2]                           │
        │   (Original code)  (Original code)                           │
        │   (state = S1)     (if cond: state=S2; else: state=S3)       │
        │         │             │                                      │
        └─────────┴─────────────┴──────────────────────────────────────┘
                                │
                                ▼ (terminal state)
                         [ Return Block ]
```

1. **Prologue Block**:
   - Function entry point that performs stack setup, saves callee-saved registers, initializes local variables, and assigns the initial state constant to `state_var`.
   - Terminates with an unconditional branch to the Main Dispatcher.
2. **Main Dispatcher Block**:
   - The head of the state machine loop.
   - Receives inbound edges from the Prologue and all non-terminating Relevant Blocks.
   - Compares `state_var` against target constants directly or branches into a tree of sub-dispatchers.
3. **Sub-Dispatcher Blocks**:
   - Intermediate decision nodes synthesized by LLVM switch-lowering (binary search trees or jump table stubs).
   - Only perform comparisons or index arithmetic on `state_var` and route execution deeper into the switch tree or directly to Relevant Blocks. Contain no original business logic.
4. **Relevant (Original) Blocks**:
   - Contain the actual semantic logic of the original program before obfuscation.
   - Identified by: executing operations other than pure state routing, possessing outbound edges back to the dispatcher loop, and updating `state_var` before exit.
   - Form 1: *Unconditional Transition* — Computes a static constant update `state_var = NEXT_STATE; jmp dispatcher`.
   - Form 2: *Conditional Transition* — Computes `state_var = condition ? STATE_TRUE : STATE_FALSE; jmp dispatcher` (often lowered using conditional moves `cmov` / `csel` or branch splits).
5. **Return Block**:
   - Terminal basic block(s) executing `ret` / `bx lr`, reached when `state_var` matches function termination criteria.

### 2. State Variable (`state_var`) Identification & Transition Tracking
1. **Locating `state_var`**:
   - Parse the Prologue block's last written register or stack slot prior to branching into the Main Dispatcher.
   - Trace memory accesses inside the Main Dispatcher: the variable read in the primary conditional comparison or switch index calculation is `state_var`.
2. **State Transition Extraction**:
   - Within each Relevant Block, slice forward from the block entry to locate writes targeting `state_var`.
   - For blocks ending in conditional branches or `cmov` instructions, identify both candidate values `(state_true, state_false)` and the condition flag/register.

### 3. Symbolic Execution & State Solving with `angr`
For each Relevant Block $B_i$, use symbolic execution to resolve the mapping $(B_i, \text{condition}) \to B_{\text{next}}$ without manual path reconstruction:

```python
import angr
import claripy

def resolve_state_transitions(project, func_addr, dispatcher_addr, relevant_blocks):
    """
    Symbolically executes each relevant block until reaching the next relevant block,
    bypassing dispatcher and sub-dispatcher blocks.
    """
    transitions = {}
    cfg = project.analyses.CFGFast()
    
    for src_bb in relevant_blocks:
        # Initialize symbolic state at the start of the relevant basic block
        state = project.factory.blank_state(addr=src_bb)
        # Constrain stack pointer and execution state
        simgr = project.factory.simulation_manager(state)
        
        # Explore until hitting another relevant block or the return block
        def is_target(s):
            return s.addr in relevant_blocks and s.addr != src_bb
            
        def is_step(s):
            # Step through dispatcher and sub-dispatchers, stop if looping indefinitely
            return True

        simgr.explore(find=is_target)
        
        resolved_targets = []
        for found_state in simgr.found:
            target_addr = found_state.addr
            # Check feasibility and extract condition if branch was split
            resolved_targets.append(target_addr)
            
        transitions[src_bb] = list(set(resolved_targets))
    return transitions
```

### 4. Control Flow Graph Reassembly & Binary Patching
Once transitions are resolved:
1. **Direct Jumps**:
   - For blocks with a single resolved successor $B_{\text{target}}$, overwrite the terminal jump targeting the dispatcher with an unconditional jump directly to $B_{\text{target}}$ (`jmp relative_offset` on x86, `B label` on ARM64).
2. **Conditional Jumps**:
   - For blocks with two successors $(B_{\text{true}}, B_{\text{false}})$, replace the state variable computation and `jmp dispatcher` with a native conditional branch (`jcc B_true; jmp B_false` on x86, `B.cond B_true; B B_false` on ARM64).
3. **NOP Padding**:
   - Fill slack bytes resulting from eliminated dispatcher assignments and indirect jumps with `NOP` (`0x90` on x86, `0x1F2003D5` on ARM64).
4. **Dispatcher Decoupling**:
   - The entire dispatcher loop and sub-dispatcher tree become dead code and are unreachable in the cleaned CFG, allowing IDA Pro / Ghidra / Binary Ninja decompilers to reconstruct clean control flow graphs.

---

## 2.2 Bogus Control Flow (BCF / `bcf`) Elimination

Bogus Control Flow injects opaque predicates that evaluate deterministically to true or false at runtime, nesting original basic blocks within artificial conditional checks and dead junk blocks.

### Common Mathematical Opaque Predicates
OLLVM and its downstream variants generate invariants based on number theory:
1. **Consecutive Integer Parity**:
   $$y \cdot (y + 1) \pmod 2 = 0 \quad (\forall y \in \mathbb{Z})$$
   - Obfuscated check: `if ((y * (y + 1)) % 2 == 0)` always branches to the true path. The false path contains mutant instructions or infinite traps.
2. **Quadratic Residue Invariant**:
   $$7y^2 - 1 \neq x^2 \quad (\forall x, y \in \mathbb{Z})$$
   - In modulo 7 arithmetic, squares are quadratic residues $\{0, 1, 2, 4\}$. $7y^2 - 1 \equiv -1 \equiv 6 \pmod 7$, which is never a square modulo 7.
   - The conditional branch guarding $7y^2 - 1 == x^2$ is an invariant false path.

### Pruning & Patching Workflow
1. **Dead Block Identification**:
   - Query Z3 or SMT solvers to test the satisfiability of both branch conditions:
     $$\text{Is } (7 \cdot y^2 - 1 == x^2) \text{ SAT for bit-vectors of size } W? \to \text{UNSAT}$$
2. **Branch Conversion**:
   - Locate the conditional jump (`jz`, `jnz`, `beq`, `b.ne`) corresponding to the opaque predicate.
   - If the condition is always True: Patch `jcc target_true` to `jmp target_true` (or remove fall-through branch).
   - If the condition is always False: Replace conditional jump with `NOP` instructions or invert to unconditional jump to the real target.
3. **Dead Code Elimination**:
   - Fill the dead/bogus basic block with `NOP` or `INT3` (`0xCC`) bytes to prevent decompilers from processing junk code.

---

## 2.3 Instruction Substitution (`sub`) & Arithmetic Normalization

Instruction Substitution replaces standard arithmetic instructions with equivalent complex multi-instruction sequences.

### Inverse Pattern Replacement Table
| Operation | Obfuscated Sequence | Inverse Deobfuscation Rewrite |
|---|---|---|
| `a = b + c` | `a = b - (-c)` | `ADD a, b, c` |
| `a = b + c` | `a = (b ^ c) + 2 * (b & c)` | `ADD a, b, c` |
| `a = b - c` | `a = b + (~c) + 1` | `SUB a, b, c` |
| `a = b ^ c` | `a = (b \| c) - (b & c)` | `XOR a, b, c` |
| `a = b ^ c` | `a = (b & ~c) \| (~b & c)` | `XOR a, b, c` |
| `a = b \| c` | `a = (b & c) + (b ^ c)` | `OR a, b, c` |
| `a = b & c` | `a = (b \| c) - (b ^ c)` | `AND a, b, c` |

Reversing substitution requires AST expression simplification (Hex-Rays microcode filters, Binary Ninja MLIL passes, or D810 rules) to match the canonical identity trees and rewrite them to single operations.

---

## 2.4 Goron / Arkari Indirect Branch Deobfuscation

Goron and Arkari obfuscate control flow by replacing direct branches and calls with indirect jumps (`BR x8` on ARM64, `jmp [rax]` on x86_64) using targets loaded from global memory tables encrypted or initialized at runtime.

### Read-Only Data Section Technique
1. **Vulnerability**:
   - Goron relies on static relocations and data arrays initialized by constructors (`.init_array`) or loaded as constants from `.data` / `.got`.
2. **Countermeasure (`DeObfBR` Pattern)**:
   - Mark the data section as strictly Read-Only in the analysis context or emulator.
   - In IDA Pro / Binary Ninja: Inspect the instructions immediately preceding `BR x8`:
     ```assembly
     ADRP    X8, #page_table_offset
     LDR     X8, [X8, #elem_offset]
     ADD     X8, X8, X9
     BR      X8
     ```
   - SMT / Constant Propagation: Evaluate the offset equations symbolically with memory contents frozen. Because the table indices are fixed constants for each control branch, the destination address simplifies to a single constant pointer.
   - Patch `BR x8` with direct branch `B target_func`.

---

## 2.5 Trap Angr Bypass (Pluto / Polaris)

Obfuscators such as Pluto and Polaris deliberately incorporate "Trap Angr" routines: high-complexity loop traps, recursive hash loops, and unsolvable branch dependencies designed to cause memory exhaustion, path explosion, and timeouts in symbolic engines like `angr`.

### Countermeasure & Micro-Emulation Strategies
1. **Bypassing Full-Path Exploration**:
   - Never invoke `simgr.explore()` across entire functions containing Trap Angr primitives.
2. **Selective Micro-Emulation (Unicorn Engine)**:
   - Confine emulation strictly to basic block state variable transformations.
   - Isolate CPU register state, map only code pages and the local stack frame, execute single basic blocks for a maximum instruction count threshold (e.g., 200 instructions), and inspect output state variables directly.
3. **Path Pruning Hooks**:
   - Hook known trap blocks (e.g., recursive cycles with no external state modification) using `project.hook(trap_addr, hook_function)` to immediately terminate or drop states entering dead-end traps.

---

## 3. Mixed Boolean-Arithmetic (MBA) Simplification

Obfuscators replace elementary arithmetic operations with complex combinations of bitwise logic and arithmetic expressions.

### Theory of Linear and Non-Linear MBA Expressions
- **Linear MBA**: Expressions composed of bitwise operations (AND, OR, NOT, XOR) and modular arithmetic (addition, subtraction, multiplication by constants) where variables do not multiply with each other:
  $$f(x_1, \dots, x_n) = \sum_{i} a_i \cdot \text{bit\_op}_i(x_1, \dots, x_n) \pmod{2^w}$$
  Every linear MBA expression can be transformed into a linear combination over a vector space of truth-table basis functions, making them solvable in polynomial time using linear algebra or coefficient matching.
- **Non-Linear MBA**: Expressions containing variable-by-variable multiplications (e.g., $(x \land y) \cdot (x \lor y)$) or high-degree polynomials over bitwise terms. Non-linear MBAs cannot be directly mapped to a linear basis and require algebraic simplification, Term Rewriting Systems (TRS), or synthesis via SMT solvers.

### Canonical Linear & Non-Linear MBA Identities
```text
Elementary Operation        Obfuscated MBA Identity
----------------------------------------------------------------------------------
x + y                 <==>  (x ^ y) + 2 * (x & y)
x + y                 <==>  (x | y) + (x & y)
x - y                 <==>  (x ^ ~y) + 2 * (~x & y) + 1
x ^ y                 <==>  (x | y) - (x & y)
x ^ y                 <==>  (x & ~y) | (~x & y)
~x                    <==>  -x - 1
x * y                 <==>  (x & y) * (x | y) + (x & ~y) * (~x & y)
```

### SMT-Based Synthesis & Algebraic Simplification Script
The following production-ready Python script uses Z3 to simplify arbitrary MBA expressions into elementary operations, combining candidate equivalence verification with SMT synthesis:

```python
#!/usr/bin/env python3
"""
Mixed Boolean-Arithmetic (MBA) Simplification Engine using Z3.
Simplifies linear and non-linear MBA formulas into canonical elementary operations.
"""

import sys
from z3 import BitVec, BitVecVal, Solver, simplify, unsat, sat, substitute


class MBASimplifier:
    def __init__(self, bit_width=32):
        self.bit_width = bit_width

    def prove_equivalence(self, expr1, expr2):
        """
        Proves that expr1 is mathematically equivalent to expr2 for all bit-vector inputs.
        Returns True if (expr1 != expr2) is UNSATISFIABLE.
        """
        solver = Solver()
        solver.add(expr1 != expr2)
        return solver.check() == unsat

    def simplify_binary_expression(self, raw_expr_fn):
        """
        Tests the target expression against canonical arithmetic and bitwise candidates.
        Falls back to linear basis synthesis and Z3 algebraic rewriting.
        """
        x = BitVec('x', self.bit_width)
        y = BitVec('y', self.bit_width)
        target_expr = raw_expr_fn(x, y)

        # 1. Direct Elementary Candidate Matching
        elementary_candidates = [
            ("x + y", x + y),
            ("x - y", x - y),
            ("y - x", y - x),
            ("x ^ y", x ^ y),
            ("x & y", x & y),
            ("x | y", x | y),
            ("~(x ^ y)", ~(x ^ y)),
            ("~(x & y)", ~(x & y)),
            ("~(x | y)", ~(x | y)),
            ("x", x),
            ("y", y),
            ("-x", -x),
            ("-y", -y),
            ("~x", ~x),
            ("~y", ~y),
            ("0", BitVecVal(0, self.bit_width)),
        ]

        for name, cand in elementary_candidates:
            if self.prove_equivalence(target_expr, cand):
                return name

        # 2. Linear MBA Basis Synthesis
        # Basis vector for 2-variable linear MBA: [x, y, x & y, x | y, x ^ y, 1]
        basis = [x, y, x & y, x | y, x ^ y, BitVecVal(1, self.bit_width)]
        basis_names = ["x", "y", "(x & y)", "(x | y)", "(x ^ y)", "1"]
        coeffs = [BitVec(f"c_{i}", self.bit_width) for i in range(len(basis))]

        # Sample concrete vectors to rapidly solve for candidate coefficients
        samples = [
            (0, 0), (1, 0), (0, 1), (1, 1),
            (0xFFFFFFFF, 0), (0, 0xFFFFFFFF),
            (0x12345678, 0x9ABCDEF0), (0x55555555, 0xAAAAAAAA)
        ]

        synth_solver = Solver()
        for sx, sy in samples:
            pt_map = [(x, BitVecVal(sx, self.bit_width)), (y, BitVecVal(sy, self.bit_width))]
            target_val = substitute(target_expr, *pt_map)
            
            sum_expr = BitVecVal(0, self.bit_width)
            for i, b in enumerate(basis):
                sum_expr = sum_expr + coeffs[i] * substitute(b, *pt_map)
            synth_solver.add(target_val == sum_expr)

        if synth_solver.check() == sat:
            model = synth_solver.model()
            solved_coeffs = [
                model[c].as_long() if model[c] is not None else 0 
                for c in coeffs
            ]
            
            # Validate synthesized candidate globally
            candidate_expr = BitVecVal(0, self.bit_width)
            for i, b in enumerate(basis):
                candidate_expr = candidate_expr + BitVecVal(solved_coeffs[i], self.bit_width) * b

            if self.prove_equivalence(target_expr, candidate_expr):
                terms = []
                for i, val in enumerate(solved_coeffs):
                    if val != 0:
                        term_str = basis_names[i]
                        terms.append(f"{val} * {term_str}" if val != 1 else term_str)
                return " + ".join(terms) if terms else "0"

        # 3. Fallback to Algebraic Z3 Simplification
        return str(simplify(target_expr))


if __name__ == "__main__":
    simplifier = MBASimplifier(bit_width=32)

    test_cases = [
        ("Linear Addition MBA", lambda x, y: (x ^ y) + 2 * (x & y)),
        ("Alternative Addition MBA", lambda x, y: (x | y) + (x & y)),
        ("Subtraction MBA Identity", lambda x, y: (x ^ ~y) + 2 * (~x & y) + 1),
        ("XOR Difference MBA", lambda x, y: (x | y) - (x & y)),
        ("Complex Synthesizable Linear MBA", lambda x, y: 3 * (x ^ y) + 2 * (x & y) + (x | y) - 5),
    ]

    print("[*] Running SMT Mixed Boolean-Arithmetic Simplification:")
    for name, expr_fn in test_cases:
        simplified_str = simplifier.simplify_binary_expression(expr_fn)
        print(f"  [-] {name:<35} -> {simplified_str}")
```

### Tooling Integration: Arybo, SSPAM, and Triton
1. **Arybo**:
   - Python library that models bit-vector expressions over boolean rings and polynomials.
   - Transforms MBA trees into canonical polynomial representations, collapsing redundant terms automatically.
2. **SSPAM (Symbolic Simplification with Pattern Matching)**:
   - Specializes in Term Rewriting Systems (TRS) for non-linear MBAs.
   - Normalizes arithmetic and bitwise expressions through associative-commutative (AC) pattern replacement rules.
3. **Triton**:
   - Lifts native instructions directly to Triton AST representation.
   - Integrates custom SMT simplification callbacks on instruction emulation to simplify MBA registers before committing state.

---

## 3.1 VM-Protected Code Devirtualization (VMProtect, Themida, Code Virtualizer)

Instruction virtualization compilers translate native architecture instructions (x86/x64/ARM) into proprietary bytecode executed by an embedded software interpreter (virtual machine).

### Theoretical Architecture of Instruction Virtualization Protectors
A virtualized binary execution environment comprises five core structural components:

```text
     Native Program Flow
             │
             ▼
      [ VM Entry Stub ] (Pushes native registers, initializes VSP/VPC, transitions to VM)
             │
             ▼
      ┌─►[ Dispatcher Loop ] (Reads bytecode via VPC, decodes opcode)
      │      │
      │      ▼
      │  [ Handler Table / Dynamic Jump ] (Routes to handler address based on opcode)
      │      │
      │      ▼
      │  [ Virtual Handler ] (Executes virtualized instruction: e.g., vADD, vREAD_MEM)
      │      │ (Updates VSP, increments VPC)
      └──────┘
             │
             ▼
      [ VM Exit Stub ] (Restores native registers from VSP, jumps back to native OEP)
```

1. **Bytecode Container**:
   - Encrypted or obfuscated memory buffer containing custom variable-length bytecode streams that encode virtual instructions, operands, and immediate data.
2. **Virtual Program Counter (VPC)**:
   - Register or memory pointer (e.g., `rsi`, `rbx`, or stack slot) tracking the current position within the bytecode container.
3. **Virtual Stack Pointer (VSP)**:
   - Dedicated CPU register (e.g., `rbp` or `rdi`) pointing to a private stack frame where operands, intermediate calculations, and virtual registers are stored.
4. **Dispatcher Loop**:
   - Central interpreter loop that fetches bytecode bytes via `*VPC++`, applies decoding transformations (XOR/ROL/SUB decryption keys), and indexes into the Handler Table.
5. **Virtual Handler Table & Virtual Handlers**:
   - Table of function pointers or dynamic indirect jumps (`jmp [rax + rbx*8]`) resolving to small code blocks ("handlers").
   - Each handler performs a single primitive: arithmetic (`vADD`, `vSUB`, `vMUL`), bitwise logic (`vNAND`, `vNOR`), memory operations (`vLOAD`, `vSTORE`), stack management (`vPUSH`, `vPOP`), or control branching (`vJMP`, `vJCC`).

### 5-Step Devirtualization Workflow

#### Step 1: Trace Acquisition
Record a full dynamic instruction trace of the VM execution from VM Entry to VM Exit:
- **Tracer Options**:
  - Triton: Fine-grained symbolic trace logging with memory and register tainting.
  - QEMU / TCG plugins: Full-system, evasion-resistant execution trace.
  - GDB / LLDB scripts: Breakpoint-driven single-stepping tracing handlers and memory accesses.
  - Frida Stalker: Fast userland dynamic block and instruction tracing (`Stalker.follow()`).

#### Step 2: Context Normalization & Handler Classification
1. **Context Normalization**:
   - Identify and strip interpreter noise: instruction loops calculating rolling decryption keys, register swapping (`xchg`), and junk instructions inserted between real semantics.
2. **Handler Classification**:
   - Group handler code blocks by semantic operation based on their stack effect ($\Delta \text{VSP}$) and memory/register mutations:
     - **Arithmetic / Logic**: Reads top $N$ elements from VSP, computes result, writes back to VSP.
     - **Memory Read / Write**: Dereferences target address and reads/writes guest memory.
     - **Conditional Branch**: Calculates condition code, conditionally updates VPC to target bytecode offset.

#### Step 3: Bytecode Disassembly & Lifting to Intermediate Representation (IR)
1. **Bytecode Disassembly**:
   - Map each opcode byte back to its classified semantic handler name and operand format.
2. **IR Lifting**:
   - Lift decoded virtual handlers into an explicit Intermediate Representation:
     - **VTIL (Virtual Technology Intermediate Language)**: Ideal for deobfuscation and VM devirtualization.
     - **LLVM IR**: Enables standard LLVM compiler optimization passes.

#### Step 4: Optimization & Dead-Code Elimination on IR
Perform optimization passes over the lifted IR:
1. **Stack Elimination**:
   - Eliminate redundant VSP pushes and pops by mapping virtual stack slots back to virtual registers (`vreg0`, `vreg1`).
2. **Dead-Code Elimination (DCE)**:
   - Strip handler flags calculations, opaque predicates within the VM interpreter, and unreferenced temporary variables.
3. **Peephole Rewriting & Pattern Recombination**:
   - Recombine multi-handler decompositions back into single high-level operations (e.g., replace `vPUSH a; vPUSH b; vNOR; vPUSH a; vNOR; vAND` with canonical bitwise logic).

#### Step 5: Decompilation or Native Re-emission
1. **Clean C Decompilation**:
   - Export the cleaned, optimized IR to Ghidra or IDA Pro Hex-Rays as High-Level IR / Microcode to decompile into readable C pseudo-code.
2. **Native Assembly Patching**:
   - Recompile the optimized IR back into native x86_64 or ARM64 instructions.
   - Overwrite the original VM Entry trampoline with an unconditional jump to the newly generated native code section, completely decoupling the protected binary from the virtual machine runtime.

### Devirtualization Tooling Ecosystem
- **NoVmp**: Automated static and dynamic devirtualization tool specifically tailored for VMProtect 3.x architectures.
- **VTIL (Virtual Technology Intermediate Language)**: Complete IR toolkit featuring stack analysis, register propagation, and dead-code elimination pipelines designed for VM lifting.
- **Triton**: Pin/C++ dynamic symbolic execution framework supporting complete taint analysis and AST representation of VM dispatchers.
- **Miasm**: Python-based reverse engineering framework providing symbolic execution, intermediate representation lifting, and binary rewriting for VM unpacking.

---

## 4. Comprehensive Anti-Analysis Bypass Catalog

### 4.1 Linux Anti-Analysis & Bypass Recipes

| Detection Vector | Mechanism / Trigger | Bypass Countermeasure | Evidence ID |
|---|---|---|---|
| **ptrace Self-Attach** | `ptrace(PTRACE_TRACEME, 0, 1, 0)` returns `-1` if debugger attached. | Preload hook or patch syscall to return `0`: `LD_PRELOAD=./hook_ptrace.so`. | `E-anti-debug-ptrace` |
| **Double ptrace Fork** | Parent forks child; child attaches to parent to prevent external GDB attachment. | Intercept `fork()` via GDB: `set follow-fork-mode child`, or patch `PTRACE_ATTACH` call. | `E-anti-debug-doubleptrace` |
| **TracerPid Inspection**| Reads `/proc/self/status`, parses `TracerPid:` (non-zero indicates tracer). | Mount fake `/proc` filesystem or hook `read()` / `open()` to substitute `TracerPid:\t0\n`. | `E-anti-debug-tracerpid` |
| **wchan Kernel Wait** | Reads `/proc/self/wchan`; string `ptrace_stop` confirms debugger pause. | Hook `open` / `read` syscalls for `wchan` path to return `sys_poll` or `0`. | `E-anti-debug-wchan` |
| **RDTSC Timing Check** | Executes `rdtsc` before and after instructions; delta exceeding threshold indicates tracing. | Set Hardware Breakpoint directly past comparison, zero out delta register, or patch `cmp` / `jge`. | `E-anti-debug-rdtsc` |
| **Signal Trapping** | Issues `raise(SIGTRAP)` or triggers deliberate `SIGSEGV`; registers handler to execute code. | In GDB: Configure signal forwarding: `handle SIGTRAP nostop noprint pass`. | `E-anti-debug-signal` |

### 4.2 Windows Anti-Analysis & Bypass Recipes

| Detection Vector | Mechanism / Trigger | Bypass Countermeasure | Evidence ID |
|---|---|---|---|
| **PEB Flags** | `PEB.BeingDebugged` (offset `0x02`), `NtGlobalFlag` (`0x68`/`0xBC` = `0x70`), `HeapFlags`. | In x64dbg: Use ScyllaHide plugin. Manual GDB: `set *(char*)(PEB + 2) = 0`, `set *(int*)(PEB + 0x68) = 0`. | `E-anti-debug-peb` |
| **NtQueryInformationProcess** | Calls `NtQueryInformationProcess` with classes `ProcessDebugPort` (7), `ProcessDebugFlags` (0x1F), or `ProcessDebugObjectHandle` (0x1E). | Hook API via ScyllaHide or Frida: Force `ReturnLength = 0`, `DebugPort = 0`, `DebugFlags = 1`. | `E-anti-debug-ntqip` |
| **ThreadHideFromDebugger** | Calls `NtSetInformationThread(ThreadHandle, 0x11, 0, 0)` to detach thread from debugger. | Hook `NtSetInformationThread`; when `ThreadInformationClass == 0x11`, return `STATUS_SUCCESS` without invoking kernel. | `E-anti-debug-thide` |
| **Hardware Breakpoints** | Inspects `CONTEXT.Dr0-Dr3` via `GetThreadContext` or SEH/VEH exception records. | In debugger: Hide hardware debug registers via ScyllaHide hook on `GetThreadContext` / `NtGetContextThread`. | `E-anti-debug-hwbp` |
| **Software Breakpoints** | Scans memory sections for `0xCC` (`int 3`) bytes or verifies CRC32 of `.text`. | Use Hardware Breakpoints exclusively (`ba e 1 <addr>`); do not insert `0xCC` breakpoints into scanned sections. | `E-anti-debug-swbp` |
| **VEH / SEH Abuse** | Registers exception handler (`AddVectoredExceptionHandler`), forces `int 3` or invalid page access, executes in handler. | Step into the exception dispatcher; set breakpoint at registered VEH handler address instead of swallowing exception. | `E-anti-debug-veh` |

### 4.3 Anti-VM & Hypervisor Detection

| Detection Vector | Mechanism / Target Artifacts | Bypass Countermeasure | Evidence ID |
|---|---|---|---|
| **CPUID Hypervisor Bit**| Leaf `0x1`: ECX bit 31 set (`1` = Hypervisor present). | In QEMU: Add `-cpu host,-hypervisor`. In x64dbg: Enable ScyllaHide CPUID hook. | `E-anti-vm-cpuid` |
| **Vendor String Leaf** | Leaf `0x40000000`: Returns strings `"VMwareVMware"`, `"Microsoft Hv"`, `"KVMKVMKVM"`. | Hook CPUID instructions in hypervisor to return authentic `"GenuineIntel"` or `"AuthenticAMD"`. | `E-anti-vm-vendor` |
| **MAC Address OUIs** | Checks network interface MAC prefixes: `00:05:69`, `00:0C:29`, `00:50:56` (VMware); `08:00:27` (VirtualBox). | Change virtual NIC MAC address to standard physical vendor OUI (e.g., `3C:D9:2B` HP/Intel). | `E-anti-vm-mac` |
| **Resource Starvation** | Queries cores (`<4`), RAM (`<4GB`), disk size (`<60GB`), mouse movement/tick count. | Provision analysis VM with 4+ vCPUs, 8GB+ RAM, 120GB+ disk image. Run synthetic mouse/cursor simulation script. | `E-anti-vm-resources` |

### 4.4 Anti-Dynamic Binary Instrumentation (Anti-DBI / Frida)

| Detection Vector | Mechanism / Trigger | Bypass Countermeasure | Evidence ID |
|---|---|---|---|
| **Frida Port Scan** | Connects to `127.0.0.1:27042` to detect active `frida-server`. | Launch `frida-server` on custom randomized port: `./frida-server -l 0.0.0.0:41921`. | `E-anti-dbi-port` |
| **Named Pipes Scan** | Windows/Android scans for named pipes matching `\pipe\frida-*` or `/data/local/tmp/frida-*`. | Patch Frida binary to rename default pipe prefix, or deploy custom GumJS inject library. | `E-anti-dbi-pipe` |
| **Memory Map Scanning**| Scans `/proc/self/maps` for strings `"frida"`, `"gadget"`, `"gum-js-loop"`, or executable anonymous pages. | Hook `open` / `read` on `/proc/self/maps` using Frida itself (early spawn) to filter out strings. | `E-anti-dbi-maps` |
| **Inline Trampoline Scan**| Inspects function prologues for hooked trampolines: `jmp <remote>` or `ldr x16, ...; br x16`. | Use hardware breakpoints for instrumentation, or use Frida Stalker (instruction tracing) instead of inline interception. | `E-anti-dbi-trampoline` |
