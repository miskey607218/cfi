#!/usr/bin/env python3
"""
dfi_time.py - BPF/CFI Performance Timing Test
Measures execution overhead of BPF uprobe monitoring on test.so.
Runs test_all() in 100 forked processes with BPF attached,
then detaches BPF and runs 100 more forked processes without BPF.
Compares average execution time.
"""

from bcc import BPF
import ctypes
import os
import re
import sys
import time
import csv
import statistics

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

        # 计算 save level: 链条中第一次从内存读数据的层
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

# ======================== BPF 程序 (与 dfi.py 逻辑一致) ========================

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
    u64 saved_rax_val;           // 新增
    u64 saved_rsp_val;           // 新增
    u64 call_stack_hash;         // 调用栈哈希 (Call-Site Sensitivity)
    u64 ptr_origin;              // 函数指针起源指令偏移 (Origin Sensitivity)
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);
BPF_HASH(saved_rax, u32, u64); // key = pid, value = rax
BPF_HASH(saved_rsp, u64, u64); // key = (pid<<32)|depth, value = saved return address
BPF_HASH(ret_depth, u32, u32); // key = pid, value = current call depth

// ---- Call-Site Sensitivity & Origin Sensitivity ----
BPF_HASH(ptr_origin_map, u64, u64);      // key=func_ptr_addr, value=origin_instr_offset
BPF_HASH(call_stack_hash_map, u32, u64); // key=pid, value=rolling call stack hash

// ===== Three-Layer DFI Protection =====
struct dfi_layer_meta {
    u32 site_id;
    u32 reg_sel;   // 0=rax,1=rcx,2=rdx,3=rbx,5=rbp,6=rsi,7=rdi,8=r8,9=r9
    u32 instr_type; // 0=direct, 1=deref, 2=rip_rel, 3=rbp_rel
    s32 extra;      // displacement for rip_rel / rbp_rel
    u32 instr_len;  // instruction length (for rip_rel addr calc)
    u32 need_deref; // for type 2/3: 1=double-deref needed, 0=value IS target
    u32 save_target_to_saved_rax; // 1=this is the "first read from data segment" layer: store computed target into saved_rax map
    u32 save_target_to_saved_rsp; // L2: 1=store computed target into saved_rsp map
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

BPF_HASH(func_heads, u64, u32);
BPF_HASH(ret_targets, u64, u32);

// ---- unified layer probe: uses bpf_probe_read for ALL register/memory reads ----
static inline int dfi_do_probe(struct pt_regs *ctx, u32 layer,
                                struct dfi_layer_meta *meta, u64 offset) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ip = PT_REGS_IP(ctx);
    u64 reg_val = 0;
    u64 target = 0;

    switch (meta->instr_type) {
    case 0: // DIRECT: call/jmp *%reg  → reg_val IS the target
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

    case 1: // DEREF: mov (%reg),%reg → reg holds the pointer, *(reg) is target
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

    case 2: // RIP_REL: mov DISP(%rip),%reg → read ptr from ip+len+disp (memory)
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

    case 3: // RBP_REL: mov DISP(%rbp),%reg → read ptr from rbp+disp (memory)
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

    case 4: // RET: target = *(rsp) — return address on stack
        {
            u64 rsp_val = 0;
            bpf_probe_read(&rsp_val, sizeof(rsp_val), &ctx->sp);
            if (bpf_probe_read_user(&reg_val, sizeof(reg_val), (void *)rsp_val) == 0) {
                target = reg_val;  // return address IS the target
            }
        }
        break;
    }

    u64 key = ((u64)pid << 32) | ((u64)meta->site_id << 8) | layer;
    dfi_layer_vals.update(&key, &reg_val);

    // 在"首次从数据段/栈内存读取"的那一层（由 Python 端按 instr_type 选定并标记在
    // save_target_to_saved_rax 上）把计算出的正确目标存入 saved_rax，
    // 供 trace_all_jumps 在真正发生间接跳转时校验。注意这里不再硬编码 layer == 2,
    // 具体保存在哪一层由调用点的 meta 决定（哪一层先从内存读出指针，就在哪一层存）。
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

    if (meta->save_target_to_saved_rax && target == 0) {
        bpf_send_signal(9);
        return 0;
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

    // 获取并递增当前 PID 的调用深度
    u32 *dp = ret_depth.lookup(&pid);
    u32 depth = dp ? (*dp + 1) : 1;
    ret_depth.update(&pid, &depth);

    // 读取函数入口处 *(rsp) = 返回地址（这是 ret 目标"第一次出现"的位置：函数刚被
    // call 进入时，返回地址就已经被压在栈顶，因此在函数开头存一次即可）
    u64 rsp;
    bpf_probe_read(&rsp, sizeof(rsp), &ctx->sp);
    u64 ret_addr = 0;
    if (bpf_probe_read_user(&ret_addr, sizeof(ret_addr), (void *)rsp) != 0) {
        bpf_send_signal(9);
        return 0;
    }

    // 存入 saved_rsp，key = (pid<<32) | depth
    u64 key = ((u64)pid << 32) | depth;
    saved_rsp.update(&key, &ret_addr);

    // Update rolling call stack hash for Call-Site Sensitivity
    // hash = old_hash * 1103515245 + ret_addr (truncated to 16-bit for mix)
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

    u64 target;                         // 用于存放解引用后的值
    // 从用户空间地址 rax 读取 8 字节到 target
    if (bpf_probe_read_user(&target, sizeof(target), (void *)rax) == 0) {
        saved_rax.update(&pid, &target);  // 存储真正的目标地址
    } else {
        // 读取失败（例如地址非法），可设置为 0 或不清空
        u64 zero = 0;
        saved_rax.update(&pid, &zero);
    }
    return 0;
}

int trace_ptr_store(struct pt_regs *ctx) {
    // Origin Sensitivity: record function pointer assignment
    // Attach to store instructions like mov [rax], rbx or mov %rax, -0x8(%rbp)
    // Records: func_ptr_addr -> origin_instr_offset
    u64 ip = PT_REGS_IP(ctx);
    u64 zero = 0;
    u64 *bp = module_base.lookup(&zero);
    if (!bp) return 0;
    u64 origin_offset = ip - *bp;

    // Read the destination address (ptr being written to) from rbx (or other src reg)
    // For simplicity, use rbx as the "pointer being stored" address
    u64 ptr_addr = 0;
    bpf_probe_read(&ptr_addr, sizeof(ptr_addr), &ctx->bx);

    // Read the value being stored (the function address) from rax
    u64 func_val = 0;
    bpf_probe_read(&func_val, sizeof(func_val), &ctx->ax);

    if (ptr_addr != 0 && func_val != 0) {
        // Store origin: pointer_address -> instruction offset where assigned
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

    // ---- Call-Site Sensitivity: pass call stack hash ----
    u64 *csh = call_stack_hash_map.lookup(&pid);
    event.call_stack_hash = csh ? *csh : 0;

    // ---- Origin Sensitivity: check ptr origin ----
    event.ptr_origin = 0;
    if (entry->jump_type == 4 || entry->jump_type == 5) {
        // For indirect call/jump, try to find the origin of the function pointer
        // The function pointer is typically stored at a known location (e.g., indirect_call_ptr)
        // Look up ptr_origin for each of the register values that could be ptr addresses
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

    // 从 saved_rax 中取出记录的 rax 值
    u64 *saved = saved_rax.lookup(&pid);
    if (saved) {
        event.saved_rax_val = *saved;          // 传递到用户态
        if (*saved == event.reg_rax) {
            event.is_correct = 1;
        } else {
            event.is_correct = 0;
        }
    } else {
        event.saved_rax_val = 0;
    }

    if (entry->jump_type == 3) {  // RET
        u64 sp;
        bpf_probe_read(&sp, sizeof(sp), &ctx->sp);
        bpf_probe_read(&event.ret_addr, sizeof(event.ret_addr), (void *)sp);

        u32 *dp = ret_depth.lookup(&pid);
        u32 depth = dp ? *dp : 0;
        u64 rkey = ((u64)pid << 32) | depth;
        u64 *saved = saved_rsp.lookup(&rkey);

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

        // 递减深度 (出栈)
        if (depth > 0) {
            depth--;
            ret_depth.update(&pid, &depth);
        }

        // 更新 call stack hash on RET (remove last entry's contribution)
        u64 *csh_ret = call_stack_hash_map.lookup(&pid);
        if (csh_ret) {
            u64 rev_hash = *csh_ret * 1103515245; // reverse the hash contribution
            call_stack_hash_map.update(&pid, &rev_hash);
        }
    }

    jump_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""
# ======================== 辅助函数 ========================

def get_module_base_from_maps(so_name):
    with open('/proc/self/maps', 'r') as f:
        for line in f:
            if so_name in line:
                start_addr = int(line.split('-')[0], 16)
                return start_addr
    return None

def run_forked_test(lib):
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)
        try:
            t0 = time.perf_counter()
            lib.test_all()
            t1 = time.perf_counter()
            elapsed = t1 - t0
            os.write(w_fd, f"{elapsed:.9f}".encode())
        except Exception as e:
            os.write(w_fd, f"ERROR:{e}".encode())
        os.close(w_fd)
        os._exit(0)
    else:
        os.close(w_fd)
        data = b""
        while True:
            chunk = os.read(r_fd, 4096)
            if not chunk:
                break
            data += chunk
        os.close(r_fd)
        os.waitpid(pid, 0)
        result = data.decode().strip()
        if result.startswith("ERROR"):
            print(f"  [!] Child error: {result}")
            return None
        return float(result)

# ======================== BPF 初始化和挂载 ========================

def setup_bpf(so_path):
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print("\n" + "=" * 60)
    print("[Phase 1] 解析三层 DFI 数据流链")
    print("=" * 60)
    layer_chains, func_bases = parse_df1_layer_chains()
    print(f" 发现 {len(layer_chains)} 个间接跳转站点")

    print(f"\n{'='*60}")
    print("[Phase 2] 加载 CFI 规则表")
    print("=" * 60)
    csv_path = os.path.join(script_dir, "test_jump_analysis.csv")
    table = parse_cfi_table(csv_path)

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

    func_heads = set()
    ret_targets_set = set()
    for entry in table:
        head = entry['src_func_addr']
        if head != 0:
            func_heads.add(head)
        if entry['jump_type'] in (2, 4):
            ret_addr = entry['src_addr'] + entry['instr_len']
            ret_targets_set.add(ret_addr)
    for head in func_heads:
        b["func_heads"][ctypes.c_uint64(head)] = ctypes.c_uint32(1)
    for rt in ret_targets_set:
        b["ret_targets"][ctypes.c_uint64(rt)] = ctypes.c_uint32(1)
    print(f"  等价类: {len(func_heads)} 个函数入口, {len(ret_targets_set)} 个合法返回地址")

    # ---- Attach Origin Sensitivity probes ----
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

    # 加载三层 DFI 配置并挂载 uprobes
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
                existing_fn = attached[addr_key]
                if (level == 3 and existing_fn == "trace_df1_l2") or \
                   (level == 2 and existing_fn == "trace_df1_l3"):
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
            except Exception:
                pass

            if level == 1:
                try:
                    b.attach_uprobe(name=so_path, sym=sym_name, sym_off=sym_off, fn_name="trace_all_jumps")
                except Exception:
                    pass

    return b, lib, base, table

# ======================== 主程序 ========================

def print_stats(times, label):
    if not times:
        print(f"\n  [{label}] 无数据")
        return None
    avg = statistics.mean(times)
    med = statistics.median(times)
    mn = min(times)
    mx = max(times)
    sd = statistics.stdev(times) if len(times) > 1 else 0
    print(f"\n  [{label}]")
    print(f"    运行次数: {len(times)}")
    print(f"    平均:     {avg*1000:.3f}ms")
    print(f"    中位数:   {med*1000:.3f}ms")
    print(f"    最小:     {mn*1000:.3f}ms")
    print(f"    最大:     {mx*1000:.3f}ms")
    print(f"    标准差:   {sd*1000:.3f}ms")
    print(f"    总计:     {sum(times)*1000:.1f}ms")
    return avg

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    so_path = os.path.join(script_dir, "test.so")
    if not os.path.exists(so_path):
        print(f"错误：找不到 {so_path}")
        return

    NUM_RUNS = 100
    no_bpf_only = '--no-bpf' in sys.argv

    if no_bpf_only:
        lib = ctypes.CDLL(so_path)
        print(f"[*] test.so loaded (no BPF)")
        print(f"\n{'='*60}")
        print(f"[Timing] 无 BPF 挂载 - 运行 {NUM_RUNS} 次 (fork子进程)")
        print(f"{'='*60}")

        times_no_bpf = []
        for i in range(NUM_RUNS):
            elapsed = run_forked_test(lib)
            if elapsed is not None:
                times_no_bpf.append(elapsed)
            if (i + 1) % 10 == 0:
                avg = statistics.mean(times_no_bpf) if times_no_bpf else 0
                print(f"  [{i+1:3d}/{NUM_RUNS}] avg={avg*1000:.3f}ms")

        print(f"\n{'='*60}")
        print("                  TIMING RESULTS")
        print(f"{'='*60}")
        print_stats(times_no_bpf, "无BPF")
        print(f"{'='*60}")
        return

    b, lib, base, table = setup_bpf(so_path)

    print(f"\n{'='*60}")
    print(f"[Timing] 有 BPF 挂载 - 运行 {NUM_RUNS} 次 (fork子进程)")
    print(f"{'='*60}")

    times_with_bpf = []
    for i in range(NUM_RUNS):
        elapsed = run_forked_test(lib)
        if elapsed is not None:
            times_with_bpf.append(elapsed)
        if (i + 1) % 10 == 0:
            avg = statistics.mean(times_with_bpf) if times_with_bpf else 0
            print(f"  [{i+1:3d}/{NUM_RUNS}] avg={avg*1000:.3f}ms")

    print(f"\n[*] 卸载 BPF uprobes...")
    b.cleanup()
    time.sleep(1)
    print(f"[*] BPF 已卸载")

    print(f"\n{'='*60}")
    print(f"[Timing] 无 BPF 挂载 - 运行 {NUM_RUNS} 次 (fork子进程)")
    print(f"{'='*60}")

    times_no_bpf = []
    for i in range(NUM_RUNS):
        elapsed = run_forked_test(lib)
        if elapsed is not None:
            times_no_bpf.append(elapsed)
        if (i + 1) % 10 == 0:
            avg = statistics.mean(times_no_bpf) if times_no_bpf else 0
            print(f"  [{i+1:3d}/{NUM_RUNS}] avg={avg*1000:.3f}ms")

    print(f"\n{'='*60}")
    print("                  TIMING RESULTS")
    print(f"{'='*60}")

    if times_with_bpf and times_no_bpf:
        avg_with = statistics.mean(times_with_bpf)
        avg_without = statistics.mean(times_no_bpf)
        med_with = statistics.median(times_with_bpf)
        med_without = statistics.median(times_no_bpf)
        min_with = min(times_with_bpf)
        min_without = min(times_no_bpf)
        max_with = max(times_with_bpf)
        max_without = max(times_no_bpf)
        std_with = statistics.stdev(times_with_bpf) if len(times_with_bpf) > 1 else 0
        std_without = statistics.stdev(times_no_bpf) if len(times_no_bpf) > 1 else 0
        overhead_abs = avg_with - avg_without
        overhead_pct = (overhead_abs / avg_without) * 100

        print(f"")
        print(f"  {'指标':<16} {'有BPF':>14} {'无BPF':>14} {'差异':>14}")
        print(f"  {'─'*16} {'─'*14} {'─'*14} {'─'*14}")
        print(f"  {'平均耗时':<16} {avg_with*1000:>11.3f}ms {avg_without*1000:>11.3f}ms {overhead_abs*1000:>11.3f}ms")
        print(f"  {'中位数':<16} {med_with*1000:>11.3f}ms {med_without*1000:>11.3f}ms {'':>14}")
        print(f"  {'最小值':<16} {min_with*1000:>11.3f}ms {min_without*1000:>11.3f}ms {'':>14}")
        print(f"  {'最大值':<16} {max_with*1000:>11.3f}ms {max_without*1000:>11.3f}ms {'':>14}")
        print(f"  {'标准差':<16} {std_with*1000:>11.3f}ms {std_without*1000:>11.3f}ms {'':>14}")
        print(f"  {'─'*16} {'─'*14} {'─'*14} {'─'*14}")
        print(f"  {'BPF开销':<16} {overhead_pct:>11.2f}% {'':>14} {'':>14}")
        print(f"")
        print(f"  总耗时(有BPF): {sum(times_with_bpf)*1000:.1f}ms")
        print(f"  总耗时(无BPF): {sum(times_no_bpf)*1000:.1f}ms")
    else:
        print_stats(times_with_bpf, "有BPF")
        print_stats(times_no_bpf, "无BPF")

    print(f"{'='*60}")


if __name__ == "__main__":
    main()
