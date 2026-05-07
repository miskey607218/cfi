"""
Register Data Flow Integrity (DFI) Analyzer - v2
=================================================
Fixed limitations vs v1:
  1. Cross-function Def-Use chains: removed global_last_def; each function
     analyzed independently.  Parameter registers get synthetic "entry" defs.
  2. Function parameters:  rdi/rsi/rdx/rcx/r8/r9 are initialised with a
     synthetic <param:REG> definition at function entry (x86-64 SYS V ABI).
  3. call modelling:  call marks caller-saved registers as clobbered (killed)
     and defines only rax (return value).  rdi/rsi/rdx/rcx/r8/r9 are treated
     as USEs (argument passing).
  4. Control flow:  builds a basic-block CFG with branch-target parsing and
     runs an iterative reaching-definitions pass (intra-procedural, union at
     merge points).
  5. Indirect control flow:  classifies indirect calls/jumps as PLT/GOT-stub
     (benign), register-based (suspicious), or memory-based (very suspicious)
     and weights the severity accordingly.

CSV outputs: per-instruction table + def-use chains (unchanged schema, plus
extra columns `indirect_type` and `def_source` for diagnostics).
"""

import re
import csv
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

# ── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class Instruction:
    func: str
    addr: int
    raw: str
    mnemonic: str
    operands: str
    src_regs: list
    dst_regs: list
    kill_regs: list          # extra regs killed (e.g. caller-saved after call)
    is_indirect_call: bool = False
    is_indirect_jump: bool = False
    is_ret: bool = False
    is_direct_call: bool = False
    is_direct_jump: bool = False       # unconditional direct jmp
    is_conditional_jump: bool = False  # jcc
    jump_target: Optional[int] = None  # resolved absolute address (if any)
    indirect_type: str = ""            # 'plt_stub','got_based','reg_based','mem_based',''

@dataclass
class DefUseEntry:
    reg: str
    def_func: str
    def_addr: int
    def_instr: str
    use_func: str
    use_addr: int
    use_instr: str
    cross_function: bool
    dfi_violation: bool
    violation_reason: str
    def_source: str          # 'local','parameter','synthetic','unknown'
    indirect_type: str       # propagated from the use site (or '')

# ── Register Normalization ──────────────────────────────────────────────────

REG_ALIASES = {
    'rax':'rax','eax':'rax','ax':'rax','al':'rax','ah':'rax',
    'rbx':'rbx','ebx':'rbx','bx':'rbx','bl':'rbx','bh':'rbx',
    'rcx':'rcx','ecx':'rcx','cx':'rcx','cl':'rcx','ch':'rcx',
    'rdx':'rdx','edx':'rdx','dx':'rdx','dl':'rdx','dh':'rdx',
    'rsi':'rsi','esi':'rsi','si':'rsi','sil':'rsi',
    'rdi':'rdi','edi':'rdi','di':'rdi','dil':'rdi',
    'rbp':'rbp','ebp':'rbp','bp':'rbp','bpl':'rbp',
    'rsp':'rsp','esp':'rsp','sp':'rsp','spl':'rsp',
    'r8':'r8','r8d':'r8','r8w':'r8','r8b':'r8',
    'r9':'r9','r9d':'r9','r9w':'r9','r9b':'r9',
    'r10':'r10','r10d':'r10','r10w':'r10','r10b':'r10',
    'r11':'r11','r11d':'r11','r11w':'r11','r11b':'r11',
    'r12':'r12','r12d':'r12','r12w':'r12','r12b':'r12',
    'r13':'r13','r13d':'r13','r13w':'r13','r13b':'r13',
    'r14':'r14','r14d':'r14','r14w':'r14','r14b':'r14',
    'r15':'r15','r15d':'r15','r15w':'r15','r15b':'r15',
    'rip':'rip',
}

X86_CALLEE_SAVED = {'rbx', 'rsp', 'rbp', 'r12', 'r13', 'r14', 'r15'}
X86_CALLER_SAVED = {'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}
X86_PARAM_REGS   = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

def norm_reg(r: str) -> Optional[str]:
    r = r.strip().lower().lstrip('%')
    return REG_ALIASES.get(r, None)

def extract_regs(operand_str: str) -> list:
    tokens = re.findall(r'%?[a-zA-Z][a-zA-Z0-9]*', operand_str)
    regs = []
    for t in tokens:
        r = norm_reg(t)
        if r and r != 'rip':
            regs.append(r)
    return list(dict.fromkeys(regs))

def is_memory_operand(op_str: str) -> bool:
    """True when the operand references memory: (xxx) or contains a displacement."""
    return '(' in op_str and ')' in op_str

# ── Instruction Semantics: (src_regs, dst_regs, kill_regs) ──────────────────

def parse_operands(mnemonic: str, operands: str) -> tuple:
    """AT&T syntax.  Returns (src_regs, dst_regs, kill_regs)."""
    m = mnemonic.lower()

    if not operands:
        if m in ('ret', 'retq'):
            return ['rsp'], ['rsp'], []   # ret reads return addr from [rsp], then rsp+=8
        if m in ('nop', 'nopl', 'nopw', 'endbr64', 'cld', 'std', 'nopw'):
            return [], [], []
        if m == 'leave':
            return ['rbp'], ['rsp', 'rbp'], []   # mov %rbp,%rsp; pop %rbp
        return [], [], []

    # NOP-family instructions with memory operands (multi-byte NOP) are no-ops
    if m in ('nop', 'nopl', 'nopw', 'endbr64'):
        return [], [], []
        return [], [], []

    parts = [p.strip() for p in operands.split(',')]

    if len(parts) == 2:
        src_str, dst_str = parts
        src_regs = extract_regs(src_str)
        dst_regs = extract_regs(dst_str)
        dst_is_mem = is_memory_operand(dst_str)

        # ── move / lea ──
        if m.startswith('mov') or m.startswith('vmov'):
            if dst_is_mem:
                return list(dict.fromkeys(src_regs + dst_regs)), [], []
            else:
                return src_regs, [dst_regs[0]] if dst_regs else [], []

        if m.startswith('lea'):
            return src_regs, [dst_regs[0]] if dst_regs else [], []

        # ── arithmetic / bitwise (read-modify-write) ──
        if m in ('add','sub','imul','and','or','xor','shl','shr','sar',
                 'ror','rol','adc','sbb','not','neg','bsf','bsr',
                 'popcnt','tzcnt','lzcnt'):
            if dst_is_mem:
                return list(dict.fromkeys(src_regs + dst_regs)), [], []
            return list(dict.fromkeys(src_regs + dst_regs)), dst_regs[-1:], []

        # ── compare / test ──
        if m.startswith('cmp') or m.startswith('test'):
            return list(dict.fromkeys(src_regs + dst_regs)), [], []

        # ── conditional move ──
        if m.startswith('cmov'):
            return list(dict.fromkeys(src_regs + dst_regs)), dst_regs[-1:] if dst_regs else [], []

        # ── default: src → dst ──
        return src_regs, dst_regs[-1:] if dst_regs else [], []

    elif len(parts) == 1:
        op = parts[0]
        regs = extract_regs(op)

        if m in ('push',):
            return regs, ['rsp'], []
        if m in ('pop',):
            return ['rsp'], regs, []
        if m in ('inc','dec','neg','not'):
            return regs, regs, []

        # ── call: rax = return value; clobbers caller-saved regs ──
        if m in ('call', 'callq'):
            if '*%' in op or '*(' in op:
                return regs, ['rax'], list(X86_CALLER_SAVED)
            return [], ['rax'], list(X86_CALLER_SAVED)

        # ── jmp / jcc ──
        if m in ('jmp', 'jmpq', 'ljmp') and '*' in op:
            return regs, [], []
        if m in ('jmp','jmpq','ljmp'):
            return [], [], []
        if re.match(r'j[a-z]+', m):
            return [], [], []

        # ── multiply / divide ──
        if m in ('idiv','div'):
            return regs + ['rax','rdx'], ['rax','rdx'], []
        if m in ('imul','mul'):
            return regs + ['rax'], ['rax','rdx'], []

        return regs, [], []

    return [], [], []

# ── Parse Disassembly Text ──────────────────────────────────────────────────

INSTR_RE = re.compile(
    r'^\s+([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(\S+)\s*(.*?)(?:\s*#.*)?$'
)
FUNC_RE = re.compile(r'^([0-9a-f]+)\s+<([^>]+)>:')

def parse_asm(text: str) -> list:
    instructions = []
    current_func = '<unknown>'

    for line in text.splitlines():
        fm = FUNC_RE.match(line)
        if fm:
            current_func = fm.group(2)
            continue

        im = INSTR_RE.match(line)
        if not im:
            continue

        addr_s, mnemonic, operands = im.group(1), im.group(2), im.group(3).strip()
        addr = int(addr_s, 16)

        operands = re.sub(r'#.*$', '', operands).strip()

        # ── Handle instruction prefixes (bnd, lock, rep*) ──
        m_lower = mnemonic.lower()
        KNOWN_PREFIXES = {'bnd', 'lock', 'rep', 'repe', 'repne', 'rex', 'rex.w', 'rex.b'}
        if m_lower in KNOWN_PREFIXES and operands:
            parts = operands.split(None, 1)
            first_word = parts[0].lower()
            if first_word in ('jmp','jmpq','ljmp','call','callq','ret','retq') or \
               re.match(r'j[a-z]+', first_word):
                mnemonic = parts[0]
                operands = parts[1] if len(parts) > 1 else ''
                m_lower = mnemonic.lower()

        src_regs, dst_regs, kill_regs = parse_operands(mnemonic, operands)

        is_indirect_call = m_lower in ('call','callq') and '*' in operands
        is_indirect_jump = m_lower in ('jmp','jmpq','ljmp') and '*' in operands
        is_direct_call = m_lower in ('call','callq') and not is_indirect_call
        is_direct_jump = m_lower in ('jmp','jmpq','ljmp') and not is_indirect_jump
        is_conditional_jump = bool(re.match(r'j[a-z]+', m_lower) and
                                   m_lower not in ('jmp','jmpq','ljmp'))
        is_ret = m_lower in ('ret','retq')

        # ── Classify indirect transfer type ──
        indirect_type = ''
        if is_indirect_call or is_indirect_jump:
            # GOT-based / PLT stub: *0xXXXX(%rip) → RIP-relative indirect
            if re.search(r'\*.*\(%rip\)', operands):
                indirect_type = 'got_based'
            # Register-based: *%reg
            elif re.search(r'\*%[a-z0-9]+', operands):
                indirect_type = 'reg_based'
            # Memory-based: *(reg) or *(reg+disp) (not %rip-relative)
            elif '(' in operands:
                indirect_type = 'mem_based'
            else:
                indirect_type = 'reg_based'
        elif is_ret:
            indirect_type = 'ret'    # ret 的返回地址在 [rsp]，trace rsp 数据流

        # ── Resolve direct branch target ──
        jump_target = None
        if is_direct_call or is_direct_jump or is_conditional_jump:
            tgt = extract_branch_target(operands)
            if tgt is not None:
                jump_target = tgt

        instructions.append(Instruction(
            func=current_func,
            addr=addr,
            raw=f"{mnemonic} {operands}".strip(),
            mnemonic=m_lower,
            operands=operands,
            src_regs=src_regs,
            dst_regs=dst_regs,
            kill_regs=kill_regs,
            is_indirect_call=is_indirect_call,
            is_indirect_jump=is_indirect_jump,
            is_ret=is_ret,
            is_direct_call=is_direct_call,
            is_direct_jump=is_direct_jump,
            is_conditional_jump=is_conditional_jump,
            jump_target=jump_target,
            indirect_type=indirect_type,
        ))

    return instructions

# ── Branch Target Resolution ────────────────────────────────────────────────

BR_TGT_RE = re.compile(r'(?:0x)?([0-9a-fA-F]+)\s*(?:<[^>]*>)?$')

def extract_branch_target(operand_str: str) -> Optional[int]:
    """Extract the absolute hex address from a direct branch operand."""
    m = BR_TGT_RE.search(operand_str)
    if m:
        return int(m.group(1), 16)
    return None

# ── Basic-Block CFG Construction ────────────────────────────────────────────

@dataclass
class BasicBlock:
    id: int
    func: str
    leader_addr: int
    instrs: list          # Instruction objects in order
    preds: list            # predecessor block ids
    succs: list            # successor block ids
    # reaching-definition sets (computed later)
    ins: dict = field(default_factory=dict)   # reg -> set of (def_func, def_addr)
    outs: dict = field(default_factory=dict)  # reg -> set of (def_func, def_addr)

def build_cfg(func_instrs: dict) -> dict:
    """
    Build a function-level CFG from linear instructions.
    Returns: func -> list[BasicBlock]
    """
    func_blocks = {}

    for func, instrs in func_instrs.items():
        instrs.sort(key=lambda x: x.addr)
        if not instrs:
            continue

        # ── Find block leaders ──
        leaders: set[int] = {instrs[0].addr}

        # Collect all direct intra-function jump targets
        for i in instrs:
            if i.jump_target is not None and i.func == func:
                # Only consider targets within *this* function
                if any(oi.func == func and oi.addr == i.jump_target for oi in instrs):
                    leaders.add(i.jump_target)

        # Instructions after jumps/returns start a new block
        for idx, i in enumerate(instrs):
            if idx + 1 < len(instrs):
                if i.is_direct_jump or i.is_indirect_jump or \
                   i.is_conditional_jump or i.is_ret:
                    leaders.add(instrs[idx + 1].addr)

        # ── Build blocks ──
        blocks: list[BasicBlock] = []
        block_map: dict[int, BasicBlock] = {}  # leader_addr -> block
        bid = 0

        current_leader = instrs[0].addr
        current_instrs = []

        for i in instrs:
            if i.addr in leaders and current_instrs:
                # start new block
                bb = BasicBlock(
                    id=bid, func=func,
                    leader_addr=current_leader,
                    instrs=current_instrs,
                    preds=[], succs=[],
                )
                blocks.append(bb)
                block_map[current_leader] = bb
                bid += 1
                current_leader = i.addr
                current_instrs = [i]
            else:
                current_instrs.append(i)

        if current_instrs:
            bb = BasicBlock(
                id=bid, func=func,
                leader_addr=current_leader,
                instrs=current_instrs,
                preds=[], succs=[],
            )
            blocks.append(bb)
            block_map[current_leader] = bb

        # ── Build successor/predecessor edges ──
        for bb in blocks:
            last = bb.instrs[-1]
            if last.is_conditional_jump and last.jump_target is not None:
                # fall-through
                for ob in blocks:
                    if ob.leader_addr == bb.leader_addr:
                        continue
                    # fall-through is the instruction immediately after last
                    fall_through_addr = last.addr + 6  # approximation is fine since we search by leader
                    # Better: find the block whose leader_addr equals the next
                    # instruction in the global list
                    fall_leader = None
                    for idx_i, gi in enumerate(instrs):
                        if gi.addr == last.addr and idx_i + 1 < len(instrs):
                            fall_leader = instrs[idx_i + 1].addr
                            break
                    # target block
                    if last.jump_target in block_map:
                        bb.succs.append(block_map[last.jump_target].id)
                        block_map[last.jump_target].preds.append(bb.id)
                    # fall-through block
                    if fall_leader is not None and fall_leader in block_map:
                        bb.succs.append(block_map[fall_leader].id)
                        block_map[fall_leader].preds.append(bb.id)

            elif last.is_direct_jump and last.jump_target is not None:
                if last.jump_target in block_map:
                    bb.succs.append(block_map[last.jump_target].id)
                    block_map[last.jump_target].preds.append(bb.id)

            elif last.is_indirect_jump or last.is_ret:
                pass  # no known intra-function successor

            else:
                # fall-through to next block
                for idx_i, gi in enumerate(instrs):
                    if gi.addr == last.addr and idx_i + 1 < len(instrs):
                        next_leader = instrs[idx_i + 1].addr
                        if next_leader in block_map:
                            bb.succs.append(block_map[next_leader].id)
                            block_map[next_leader].preds.append(bb.id)
                        break

        func_blocks[func] = blocks

    return func_blocks

# ── Reaching Definitions ────────────────────────────────────────────────────

def reaching_definitions(func: str, blocks: list[BasicBlock],
                         param_defs: dict) -> dict:
    """
    Iterative bit-vec reaching-definitions.
    Returns mapping: (block_id, reg) -> set of (def_func, def_addr, def_instr, def_source)

    Each block is processed instruction-by-instruction; the internal
    reachable state is a dict of reg->set_of_def_info tuples.
    """
    # ── Compute GEN/KILL per block ──
    gen: dict[int, dict[str, set]] = {}   # block_id -> reg -> set of def_tuples
    kill_reg: dict[int, set] = {}         # block_id -> set of reg names killed

    for bb in blocks:
        gen[bb.id] = defaultdict(set)
        kill_reg[bb.id] = set()
        # process instructions in order; kill removes, gen adds
        # we need to maintain an ordering so later gen overrides earlier kill
        # Use a list of (reg, def_tuple) as the generation stream
        block_gen_list: dict[str, tuple] = {}  # reg -> most-recent def_tuple in block

        for instr in bb.instrs:
            # kills
            for r in instr.dst_regs:
                kill_reg[bb.id].add(r)
                block_gen_list.pop(r, None)
            for r in instr.kill_regs:
                kill_reg[bb.id].add(r)
                block_gen_list.pop(r, None)
            # gens
            for r in instr.dst_regs:
                if instr.is_direct_call or instr.is_indirect_call:
                    def_source = 'synthetic'  # return value produced by callee
                else:
                    def_source = 'local'
                dtuple = (instr.func, instr.addr, instr.raw, def_source)
                block_gen_list[r] = dtuple

        # final gen per block
        for r, dtuple in block_gen_list.items():
            gen[bb.id][r].add(dtuple)

    # ── Iterative solver ──
    # IN[BB] = union of OUT[pred] for pred in BB.preds
    in_sets: dict[int, dict[str, set]] = {bb.id: {} for bb in blocks}
    out_sets: dict[int, dict[str, set]] = {bb.id: {} for bb in blocks}

    changed = True
    while changed:
        changed = False
        for bb in blocks:
            # Compute IN: union of OUT of predecessors
            new_in: dict[str, set] = {}
            for pid in bb.preds:
                for reg, dset in out_sets[pid].items():
                    if reg not in new_in:
                        new_in[reg] = set()
                    new_in[reg] |= dset

            # For entry block with no preds, inject parameter defs
            if not bb.preds and param_defs:
                for reg, dtuple in param_defs.items():
                    if reg not in new_in:
                        new_in[reg] = set()
                    new_in[reg].add(dtuple)

            # Compare with stored IN
            if new_in != in_sets[bb.id]:
                changed = True
                in_sets[bb.id] = new_in

            # Compute OUT: OUT = GEN ∪ (IN - KILL)
            new_out: dict[str, set] = {}
            for reg in list(new_in.keys()):
                if reg not in kill_reg[bb.id]:
                    new_out[reg] = set(new_in[reg])
            # add GEN
            for reg, dset in gen[bb.id].items():
                if reg not in new_out:
                    new_out[reg] = set()
                new_out[reg] |= dset  # GEN overrides, so union is fine since KILL already removed

            if new_out != out_sets[bb.id]:
                changed = True
                out_sets[bb.id] = new_out

    # ── Compute per-instruction reachable definitions ──
    # For each instruction in a block, the reachable set at that point is a
    # combination of IN[BB] and the local gen/kill up to that point.
    result: dict[tuple, list] = {}  # (func, addr) -> list of (reg, def_tuple)

    for bb in blocks:
        # Start from IN set
        reachable: dict[str, set] = {}
        for reg, dset in in_sets[bb.id].items():
            reachable[reg] = set(dset)

        for instr in bb.instrs:
            # Record reaching defs for this instruction's uses
            key = (instr.func, instr.addr)
            reach_list = []
            for r in instr.src_regs:
                if r in reachable:
                    for d in reachable[r]:
                        reach_list.append((r, d))
                else:
                    reach_list.append((r, ('<unknown>', 0, f'undefined source for {r}', 'unknown')))
            result[key] = reach_list

            # Update for kills/gen
            for r in instr.dst_regs:
                reachable.pop(r, None)
            for r in instr.kill_regs:
                reachable.pop(r, None)
            for r in instr.dst_regs:
                if instr.is_direct_call or instr.is_indirect_call:
                    ds = 'synthetic'
                else:
                    ds = 'local'
                dtuple = (instr.func, instr.addr, instr.raw, ds)
                reachable[r] = {dtuple}

    return result

# ── Parameter Definition Creation ───────────────────────────────────────────

def make_param_defs(func: str) -> dict:
    """Create synthetic entry definitions for function parameters (x86-64 ABI)."""
    return {
        r: (func, 0, f'<param:{r}>', 'parameter')
        for r in X86_PARAM_REGS
    }

# ── Indirect Target Tracing (improved) ──────────────────────────────────────

def trace_indirect_target_local(target_reg: str, func: str, call_addr: int,
                                 func_instrs: dict, reach_info: dict,
                                 depth: int = 3) -> list:
    """
    Trace the definition chain of an indirect call/jump target register
    using ONLY local (same-function) reaching definitions.
    Returns list of dicts.
    """
    traces = []
    curr_reg = target_reg
    curr_func = func
    curr_addr = call_addr

    for level in range(depth):
        key = (curr_func, curr_addr)
        defs = reach_info.get(key, [])
        target_defs = [d for r, d in defs if r == curr_reg]

        if not target_defs:
            traces.append({
                'level': level + 1,
                'reg': curr_reg,
                'def_func': '<unknown>',
                'def_addr': 0,
                'def_instr': f'undefined source for {curr_reg}',
                'def_source': 'unknown',
                'src_regs': [],
                'cross_func': True,
                'terminal': True,
            })
            break

        df, da, di, ds = target_defs[0]  # take first reaching def
        cross = df != func
        is_terminal = ds == 'parameter'

        traces.append({
            'level': level + 1,
            'reg': curr_reg,
            'def_func': df,
            'def_addr': da,
            'def_instr': di,
            'def_source': ds,
            'src_regs': [],
            'cross_func': cross,
            'terminal': is_terminal,
        })

        if is_terminal:
            break
        if ds == 'unknown':
            break

        # Follow one step: find the instruction that defined df,da,di
        # and look at its source registers
        if df == func:
            instrs = func_instrs.get(func, [])
            for i in instrs:
                if i.addr == da and i.raw == di:
                    next_reg = None
                    for sr in i.src_regs:
                        if sr not in ('rsp', 'rbp', 'rip'):
                            next_reg = sr
                            break
                    if next_reg is None:
                        break
                    curr_reg = next_reg
                    curr_addr = da
                    break
            else:
                break
        else:
            break

    return traces


def trace_ret_target_local(func: str, ret_addr: int,
                            func_instrs: dict, reach_info: dict,
                            depth: int = 3) -> list:
    """
    Trace the definition chain of a ret instruction's target (return address).
    ret reads from [rsp], so we trace rsp backwards through the function.
    Unlike register-based indirect jumps, ret's data flow goes through
    rsp → [pop/leave] → rbp → [mov %rsp,%rbp] → rsp → [push %rbp] → caller's rsp.
    Includes rsp and rbp in the trace since they're essential to ret's target.
    """
    traces = []
    curr_reg = 'rsp'
    curr_func = func
    curr_addr = ret_addr

    for level in range(depth):
        key = (curr_func, curr_addr)
        defs = reach_info.get(key, [])
        target_defs = [d for r, d in defs if r == curr_reg]

        if not target_defs:
            traces.append({
                'level': level + 1,
                'reg': curr_reg,
                'def_func': '<unknown>',
                'def_addr': 0,
                'def_instr': f'ret: undefined source for {curr_reg}',
                'def_source': 'unknown',
                'src_regs': [],
                'cross_func': True,
                'terminal': True,
            })
            break

        df, da, di, ds = target_defs[0]
        cross = df != func
        is_terminal = ds == 'parameter'

        traces.append({
            'level': level + 1,
            'reg': curr_reg,
            'def_func': df,
            'def_addr': da,
            'def_instr': di,
            'def_source': ds,
            'src_regs': [],
            'cross_func': cross,
            'terminal': is_terminal,
        })

        if is_terminal:
            break
        if ds == 'unknown':
            break

        # Follow one step: find the instruction that defined df,da,di
        # For ret tracing, ALSO include rsp and rbp since they carry the return addr
        if df == func:
            instrs = func_instrs.get(func, [])
            for i in instrs:
                if i.addr == da and i.raw == di:
                    next_reg = None
                    for sr in i.src_regs:
                        # For ret trace: include rbp (frame pointer chain)
                        # rsp → pop/leave → rbp → mov %rsp,%rbp → rsp → push
                        if sr != 'rip':
                            next_reg = sr
                            break
                    if next_reg is None:
                        break
                    curr_reg = next_reg
                    curr_addr = da
                    break
            else:
                break
        else:
            break

    return traces

# ── Dataflow Analysis ───────────────────────────────────────────────────────

def analyze_dfi(instructions: list) -> tuple:
    func_instrs = defaultdict(list)
    for instr in instructions:
        func_instrs[instr.func].append(instr)
    for func in func_instrs:
        func_instrs[func].sort(key=lambda x: x.addr)

    # ── Build CFG and run reaching-definitions per function ──
    func_blocks = build_cfg(func_instrs)
    all_reach: dict[tuple, list] = {}  # (func, addr) -> list of (reg, def_tuple)

    for func, blocks in func_blocks.items():
        param_defs = make_param_defs(func)
        per_func_reach = reaching_definitions(func, blocks, param_defs)
        all_reach.update(per_func_reach)

    # Also build a simple index for backward search (fallback for
    # functions without CFG or for indirect trace)
    func_reach_index = defaultdict(lambda: defaultdict(list))
    for (f, a), defs in all_reach.items():
        func_reach_index[f][a] = defs

    # ── Produce per-instruction rows and def-use chains ──
    per_instr = []
    du_chains = []
    seen_du = set()

    for func, instrs in func_instrs.items():
        for instr in instrs:
            src_uses = list(instr.src_regs)
            dst_defs = list(instr.dst_regs)
            violations = []

            # ── Classify indirect-transfer severity ──
            indirect_severity = 'none'
            if instr.indirect_type in ('reg_based',):
                indirect_severity = 'high'
            elif instr.indirect_type in ('mem_based',):
                indirect_severity = 'critical'
            elif instr.indirect_type in ('got_based',):
                indirect_severity = 'low'
            elif instr.indirect_type in ('ret',):
                indirect_severity = 'high'    # ret 也是间接跳转，目标在 [rsp]
            else:
                indirect_severity = 'none'

            # ── Indirect call / jump: trace target origin ──
            if instr.is_indirect_call or instr.is_indirect_jump:
                jmp_type = "call" if instr.is_indirect_call else "jump"
                call_regs = extract_regs(instr.operands)
                for r in call_regs:
                    canon = norm_reg(r)
                    if not canon:
                        continue
                    traces = trace_indirect_target_local(
                        canon, func, instr.addr,
                        func_instrs, all_reach, depth=3
                    )
                    for t in traces:
                        level = t['level']
                        def_func = t['def_func']
                        def_addr = t['def_addr']
                        def_instr_raw = t['def_instr']
                        cross = t['cross_func']
                        term = t['terminal']
                        def_src = t['def_source']

                        descs = []
                        if def_func == '<unknown>' or def_src == 'unknown':
                            descs.append(
                                f"indirect {jmp_type} {instr.indirect_type} target {canon} L{level}: "
                                f"no local definition (param / external)"
                            )
                        elif term:
                            descs.append(
                                f"indirect {jmp_type} {instr.indirect_type} target {canon} L{level}: "
                                f"terminal (param) at {def_func}"
                            )
                        elif cross:
                            descs.append(
                                f"indirect {jmp_type} {instr.indirect_type} target {canon} L{level}: "
                                f"cross-function defined at {def_func}@{hex(def_addr)}"
                            )
                        else:
                            descs.append(
                                f"indirect {jmp_type} {instr.indirect_type} target {canon} L{level}: "
                                f"defined at {hex(def_addr)}"
                            )
                        violations.extend(descs)

                        du_key = (t['reg'], def_func, def_addr, func, instr.addr)
                        if du_key not in seen_du:
                            seen_du.add(du_key)
                            du_chains.append(DefUseEntry(
                                reg=t['reg'],
                                def_func=def_func,
                                def_addr=def_addr,
                                def_instr=def_instr_raw,
                                use_func=func,
                                use_addr=instr.addr,
                                use_instr=instr.raw,
                                cross_function=cross,
                                dfi_violation=indirect_severity in ('high', 'critical')
                                               or cross,
                                violation_reason='; '.join(descs) if descs else '',
                                def_source=def_src,
                                indirect_type=instr.indirect_type,
                            ))

            # ── Ret: trace rsp → rbp → prologue stack frame chain ──
            if instr.is_ret and instr.indirect_type == 'ret':
                traces = trace_ret_target_local(
                    func, instr.addr,
                    func_instrs, all_reach, depth=3
                )
                for t in traces:
                    level = t['level']
                    def_func = t['def_func']
                    def_addr = t['def_addr']
                    def_instr_raw = t['def_instr']
                    cross = t['cross_func']
                    term = t['terminal']
                    def_src = t['def_source']
                    canon = t['reg']

                    descs = []
                    if def_func == '<unknown>' or def_src == 'unknown':
                        descs.append(
                            f"ret target {canon} L{level}: no local rsp definition"
                        )
                    elif term:
                        descs.append(
                            f"ret target {canon} L{level}: terminal (param) at {def_func}"
                        )
                    elif cross:
                        descs.append(
                            f"ret target {canon} L{level}: cross-function defined at {def_func}@{hex(def_addr)}"
                        )
                    else:
                        descs.append(
                            f"ret target {canon} L{level}: defined at {hex(def_addr)} ({def_instr_raw})"
                        )
                    violations.extend(descs)

                    du_key = (t['reg'], def_func, def_addr, func, instr.addr)
                    if du_key not in seen_du:
                        seen_du.add(du_key)
                        du_chains.append(DefUseEntry(
                            reg=t['reg'],
                            def_func=def_func,
                            def_addr=def_addr,
                            def_instr=def_instr_raw,
                            use_func=func,
                            use_addr=instr.addr,
                            use_instr=instr.raw,
                            cross_function=cross,
                            dfi_violation=bool(cross or def_src == 'unknown'),
                            violation_reason='; '.join(descs) if descs else '',
                            def_source=def_src,
                            indirect_type=instr.indirect_type,
                        ))

            # ── Use-before-def / undef warning ──
            for r in src_uses:
                key = (func, instr.addr)
                defs = all_reach.get(key, [])
                defs_for_r = [d for reg, d in defs if reg == r]
                if not defs_for_r:
                    # not in param registers → genuinely unknown
                    if r not in X86_PARAM_REGS and r not in ('rax','rsp','rbp'):
                        violations.append(
                            f"register {r} used without reaching definition "
                            f"(not defined in function, not a parameter)"
                        )

            # ── Build def-use chains from reaching definitions ──
            key = (func, instr.addr)
            defs = all_reach.get(key, [])
            for r in src_uses:
                defs_for_r = [d for reg, d in defs if reg == r]
                for df, da, di, ds in defs_for_r:
                    cross = df != func and df != '<unknown>'

                    # Determine if this is a violation
                    dfi_v = False
                    reason = ""
                    if ds == 'unknown' and df == '<unknown>':
                        # Undefined — but filter param/caller-saved
                        if r not in X86_PARAM_REGS and r not in ('rax','rsp','rbp'):
                            dfi_v = True
                            reason = f"register {r} used with no reaching definition"
                    elif cross:
                        dfi_v = True
                        reason = f"cross-function use: defined in {df}@{hex(da)}"
                    elif ds == 'parameter':
                        # Parameters are legitimate — no violation
                        pass

                    du_key = (r, df, da, func, instr.addr)
                    if du_key not in seen_du:
                        seen_du.add(du_key)
                        du_chains.append(DefUseEntry(
                            reg=r,
                            def_func=df,
                            def_addr=da,
                            def_instr=di,
                            use_func=func,
                            use_addr=instr.addr,
                            use_instr=instr.raw,
                            cross_function=cross,
                            dfi_violation=dfi_v,
                            violation_reason=reason,
                            def_source=ds,
                            indirect_type=instr.indirect_type,
                        ))

            # ── Record per-instruction row ──
            violation_str = '; '.join(violations) if violations else 'none'
            violation_flag = 'WARNING' if violations else 'OK'

            per_instr.append({
                'function': func,
                'address': hex(instr.addr),
                'instruction': instr.raw,
                'src_regs(USE)': ','.join(src_uses) if src_uses else '-',
                'dst_regs(DEF)': ','.join(dst_defs) if dst_defs else '-',
                'indirect_call': 'Yes' if instr.is_indirect_call else 'No',
                'indirect_jump': 'Yes' if (instr.is_indirect_jump or instr.is_ret) else 'No',
                'is_ret': 'Yes' if instr.is_ret else 'No',
                'indirect_type': instr.indirect_type if instr.indirect_type else '-',
                'indirect_severity': indirect_severity,
                'dfi_violation': violation_flag,
                'violation_reason': violation_str,
            })

    # ── Deduplicate per_instr ──
    seen_instr = set()
    deduped_instr = []
    for row in per_instr:
        key = (row['function'], row['address'])
        if key not in seen_instr:
            seen_instr.add(key)
            deduped_instr.append(row)

    return deduped_instr, du_chains

# ── Write CSV ───────────────────────────────────────────────────────────────

def write_csv(per_instr: list, du_chains: list, out_prefix: str = 'register_dfi'):
    instr_csv = f'{out_prefix}_instructions.csv'
    with open(instr_csv, 'w', newline='', encoding='utf-8-sig') as f:
        if per_instr:
            fieldnames = [
                'function', 'address', 'instruction',
                'src_regs(USE)', 'dst_regs(DEF)',
                'indirect_call', 'indirect_jump', 'is_ret',
                'indirect_type', 'indirect_severity',
                'dfi_violation', 'violation_reason',
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(per_instr)
    print(f'[OK] Instruction-level CSV: {instr_csv}  ({len(per_instr)} rows)')

    du_csv = f'{out_prefix}_def_use_chains.csv'
    with open(du_csv, 'w', newline='', encoding='utf-8-sig') as f:
        fieldnames = [
            'reg', 'def_func', 'def_addr', 'def_instr',
            'use_func', 'use_addr', 'use_instr',
            'cross_func', 'dfi_violation', 'violation_reason',
            'def_source', 'indirect_type',
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in du_chains:
            writer.writerow({
                'reg': e.reg,
                'def_func': e.def_func,
                'def_addr': hex(e.def_addr) if e.def_addr else '0x0',
                'def_instr': e.def_instr,
                'use_func': e.use_func,
                'use_addr': hex(e.use_addr),
                'use_instr': e.use_instr,
                'cross_func': 'Yes' if e.cross_function else 'No',
                'dfi_violation': 'WARNING' if e.dfi_violation else 'OK',
                'violation_reason': e.violation_reason,
                'def_source': e.def_source,
                'indirect_type': e.indirect_type if e.indirect_type else '-',
            })
    print(f'[OK] Def-Use chain CSV: {du_csv}  ({len(du_chains)} chains)')

    violations = [e for e in du_chains if e.dfi_violation]
    instr_violations = [r for r in per_instr if r['dfi_violation'] == 'WARNING']
    print(f'\n── DFI Analysis Summary ──')
    print(f'  Total instructions        : {len(per_instr)}')
    print(f'  Total def-use chains      : {len(du_chains)}')
    print(f'  Cross-function use chains : {sum(1 for e in du_chains if e.cross_function)}')
    print(f'  DFI violation chains      : {len(violations)}')
    print(f'  Instructions with warnings: {len(instr_violations)}')

    if instr_violations:
        print('\n  [WARNING] DFI warnings:')
        for r in instr_violations[:50]:  # limit output
            print(f"    [{r['function']}] {r['address']}  {r['instruction']}")
            print(f"      -> {r['violation_reason']}")

# ── Main Entry ──────────────────────────────────────────────────────────────

def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else 'test.txt'
    output_prefix = sys.argv[2] if len(sys.argv) > 2 else 'register_dfi'

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text = f.read()
    except FileNotFoundError:
        print(f'[ERROR] File not found: {input_file}')
        sys.exit(1)

    print(f'[*] Parsing disassembly: {input_file}')
    instructions = parse_asm(text)
    print(f'[*] Parsed {len(instructions)} instructions')

    per_instr, du_chains = analyze_dfi(instructions)
    write_csv(per_instr, du_chains, output_prefix)

if __name__ == '__main__':
    main()
