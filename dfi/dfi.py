from bcc import BPF
import ctypes
import os
import re
import sys
import threading
import time
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import csv

if os.geteuid() != 0:
    print("Run with sudo!")
    sys.exit(1)

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
        ("ret_addr", ctypes.c_uint64),          # 原 sp → ret_addr
        ("saved_rax_val", ctypes.c_uint64),     # 新增：保存的 rax
        ("saved_rsp_val", ctypes.c_uint64),     # 新增：保存的 rax
    ]

class DfiLayerMeta(ctypes.Structure):
    _fields_ = [
        ("site_id", ctypes.c_uint32),
        ("reg_sel", ctypes.c_uint32),
        ("instr_type", ctypes.c_uint32),  # 0=direct,1=deref,2=rip_rel,3=rbp_rel
        ("extra", ctypes.c_int32),        # displacement for rip/rbp-rel
        ("instr_len", ctypes.c_uint32),   # instruction byte length
        ("need_deref", ctypes.c_uint32),  # for type 2/3: 1=double-deref, 0=single
        ("save_target_to_saved_rax", ctypes.c_uint32),  # L2: 1=save computed target to saved_rax
        ("save_target_to_saved_rsp", ctypes.c_uint32),  # L2: 1=save computed target to saved_rsp
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
    'rsp': 4,   # ret uses rsp for return address at [rsp]
}

def classify_instr(instr_text):
    """
    根据 CSV 中的 instruction 字段，分类并返回 (instr_type, extra, instr_len)
    instr_type: 0=DIRECT(reg即目标), 1=DEREF(*(reg)), 2=RIP_REL(**(rip+disp)), 3=RBP_REL(**(rbp+disp)), 4=RET(*(rsp))
    """
    i = instr_text.strip()

    # Type 4: ret / retq → target = *(rsp), rsp saved by push %rbp / mov %rsp,%rbp
    if re.match(r'^(ret|retq)$', i):
        return (4, 0, 1)  # ret = 1 byte (c3)

    # Type 0: call/jmp *%reg  → 寄存器值即目标地址
    if re.match(r'^(call|jmp|jmpq|ljmp)\s+\*%[a-z0-9]+', i):
        return (0, 0, 3)  # ff d0 = 2 bytes, but default to 3 for safety

    # Type 1: mov (%reg),%reg  → *(reg) 是目标
    if re.match(r'^mov\s+\(%[a-z0-9]+\),\s*%[a-z0-9]+', i):
        # mov (%rax),%rax  →  48 8b 00 = 3 bytes
        return (1, 0, 3)

    # Type 2: mov DISP(%rip),%reg  → read ptr from rip+len+disp, then deref
    m = re.match(r'^mov\s+(0x[0-9a-fA-F]+)\(%rip\),\s*%[a-z0-9]+', i)
    if m:
        disp = int(m.group(1), 16)
        return (2, disp, 7)  # REX.W + 8B + ModRM + disp32 = 7 bytes

    # Type 3: mov DISP(%rbp),%reg  → read ptr from rbp+disp, then deref
    m = re.match(r'^mov\s+(-?0x[0-9a-fA-F]+)\(%rbp\),\s*%[a-z0-9]+', i)
    if m:
        disp = int(m.group(1), 16)
        # int() handles negative hex correctly if it's two's complement
        # But -0x10 → ValueError. So handle negative prefix
        return (3, disp, 4)  # disp8 = 4 bytes typical

    # Type 3 variant: mov -DISP(%rbp),%reg  (AT&T syntax: -0x10(%rbp))
    m = re.match(r'^mov\s+-(0x[0-9a-fA-F]+)\(%rbp\),\s*%[a-z0-9]+', i)
    if m:
        disp = -int(m.group(1), 16)
        return (3, disp, 4)

    # Type 0 fallback: lea → effective address is in reg
    if re.match(r'^lea\s+', i):
        return (0, 0, 7)

    # Default: try dereference
    return (1, 0, 3)

def parse_df1_layer_chains():
    """从 CSV 文件解析间接跳转相关寄存器的三层数据流链"""
    script_dir = os.path.dirname(os.path.abspath(__file__))

    instr_csv = os.path.join(script_dir, 'register_dfi_instructions.csv')
    du_csv = os.path.join(script_dir, 'register_dfi_def_use_chains.csv')

    instr_map = {}
    func_bases = {}
    reg_based_jumps = []

    # 读取指令级 CSV
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
                    reg_based_jumps.append(row)   # ret 也视为间接跳转站点

    # 读取 def-use chains，建立索引
    du_index = {}  # (reg, use_func, use_addr) -> [(def_func, def_addr, def_instr)]
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

        # 提取寄存器名
        reg_match = re.search(r'\*(%[a-z0-9]+)', instr)
        if not reg_match:
            # ret 指令没有 *%reg 语法，但 uses rsp (返回地址在 [rsp])
            if re.match(r'^(ret|retq)$', instr.strip()):
                reg_name = 'rsp'
            else:
                continue
        else:
            reg_name_raw = reg_match.group(1).lstrip('%')
            reg_name = REG_ALIASES.get(reg_name_raw, reg_name_raw)

        # 查找定义链
        chain_key = (reg_name, func, jump_addr)
        def_entries = du_index.get(chain_key, [])

        # 按 def_addr 降序（最近的排前面）
        def_entries.sort(key=lambda x: x['def_addr'], reverse=True)

        # 去重
        seen_addr = set()
        unique_defs = []
        for d in def_entries:
            if d['def_addr'] not in seen_addr and d['def_addr'] != 0:
                seen_addr.add(d['def_addr'])
                unique_defs.append(d)

        layers = []
        # Layer 1: 间接跳转指令本身
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
        # Layer 2 & 3: 从定义链取
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

        # 补足到 3 层
        while len(layers) < 3:
            last = layers[-1].copy()
            last['level'] = len(layers) + 1
            layers.append(last)

        # 决定是否需要对 types 2/3 做双重解引用
        # 如果链中存在 DEREF(instr_type=1) 中间层，则外层的值是指针 → 需要 double deref
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
    print(f"✅ 从 CSV 成功解析 {len(table)} 个静态跳转规则")
    return table

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
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);
BPF_HASH(saved_rax, u32, u64); // key = pid, value = rax
BPF_HASH(saved_rsp, u64, u64); // key = (pid<<32)|depth, value = saved return address
BPF_HASH(ret_depth, u32, u32); // key = pid, value = current call depth

// ===== Three-Layer DFI Protection =====
struct dfi_layer_meta {
    u32 site_id;
    u32 reg_sel;   // 0=rax,1=rcx,2=rdx,3=rbx,5=rbp,6=rsi,7=rdi,8=r8,9=r9
    u32 instr_type; // 0=direct, 1=deref, 2=rip_rel, 3=rbp_rel
    s32 extra;      // displacement for rip_rel / rbp_rel
    u32 instr_len;  // instruction length (for rip_rel addr calc)
    u32 need_deref; // for type 2/3: 1=double-deref needed, 0=value IS target
    u32 save_target_to_saved_rax; // L2: 1=store computed target into saved_rax map
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

    // L2: 将计算出的正确目标存入 saved_rax，供 trace_all_jumps 校验
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

    // 获取并递增当前 PID 的调用深度
    u32 *dp = ret_depth.lookup(&pid);
    u32 depth = dp ? (*dp + 1) : 1;
    ret_depth.update(&pid, &depth);

    // 读取函数入口处 *(rsp) = 返回地址
    u64 rsp;
    bpf_probe_read(&rsp, sizeof(rsp), &ctx->sp);
    u64 ret_addr = 0;
    bpf_probe_read_user(&ret_addr, sizeof(ret_addr), (void *)rsp);

    // 存入 saved_rsp，key = (pid<<32) | depth
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

    // 从 saved_rax 中取出记录的 rax 值
    u64 *saved = saved_rax.lookup(&event.pid);
    if (saved) {
        event.saved_rax_val = *saved;          // 传递到用户态
        if (*saved == event.reg_rax) {
            event.is_correct = 1;
        } else {
            event.is_correct = 0;
        }
        // 可选：删除该 pid 的记录，避免残留
        // saved_rax.delete(&event.pid);
    } else {
        event.saved_rax_val = 0;
        event.is_correct = 1;                   // 无记录时默认正确
    }

    if (entry->jump_type == 3) {  // RET
        u32 pid = event.pid;
        u64 sp;
        bpf_probe_read(&sp, sizeof(sp), &ctx->sp);
        bpf_probe_read(&event.ret_addr, sizeof(event.ret_addr), (void *)sp);

        // 用深度计数器查找对应层级的 saved_rsp
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
            event.is_correct = 1;   // 无记录默认正确
        }

        // 递减深度 (出栈)
        if (depth > 0) {
            depth--;
            ret_depth.update(&pid, &depth);
        }
    }

    jump_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

def handle_jump_event(cpu, data, size):
    global event_count, violation_count, base, cfi_lookup
    event = b["jump_events"].event(data)

    # 跳转类型名称映射
    jump_type_names = {
        0: "JMP", 1: "JCC", 2: "CALL", 3: "RET",
        4: "INDIRECT_CALL", 5: "INDIRECT_JMP"
    }
    jump_type_name = jump_type_names.get(event.jump_type, f"UNKNOWN({event.jump_type})")
    status = "✓" if event.is_correct else "✗ VIOLATION"

    if not event.is_correct:
        violation_count += 1

    # 解码函数名
    src_func_str = event.src_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()
    dst_func_str = event.dst_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()

    # 从 cfi_lookup 中获取指令信息
    src_addr_key = event.src_addr
    cfi_info = cfi_lookup.get(src_addr_key, {})
    instr_len = cfi_info.get('instr_len', 0)
    instr_content = cfi_info.get('instr_content', '未知')
    instr_bytes = cfi_info.get('instr_bytes', '未知')
    csv_opcode = cfi_info.get('opcode', 0)

    # 输出事件头部
    print("\n" + "="*80)
    print(f"CFI 事件 #{event_count + 1} - {status}")
    print(f"跳转类型: {jump_type_name} ({event.jump_type})")
    print(f"事件时间: {event.timestamp_ns} ns")
    print(f"事件CPU: {event.cpu}")
    print(f"事件PID: {event.pid}")
    print("="*80)

    # CFI 条目信息
    print("\n📋 CFI 条目信息:")
    print(f"  • 源地址(CFI表): 0x{event.src_addr:016x}")
    print(f"  • 源函数地址: 0x{event.src_func_addr:016x}")
    print(f"  • 目标地址(CFI表): 0x{event.cfi_dst_addr:016x}")
    print(f"  • 源函数: {src_func_str}")
    print(f"  • 目标函数: {dst_func_str}")

    # 运行时信息
    print("\n🔄 运行时信息:")
    print(f"  • 运行时源偏移: 0x{event.src_offset:016x}")
    print(f"  • 运行时目标偏移: 0x{event.dst_offset:016x}")
    if event.expected_dst != 0:
        print(f"  • 预期目标地址: 0x{event.expected_dst:016x}")
    else:
        print(f"  • 预期目标地址: (间接跳转无静态目标)")
    print(f"  • 运行时指令指针(IP/RIP): 0x{event.runtime_ip:016x}")
    print(f"  • 模块加载基址(module_base): 0x{event.module_base_addr:016x}")

    # 指令信息
    print("\n💻 指令信息 (来自CSV):")
    print(f"  • 指令长度: {instr_len} 字节")
    print(f"  • 指令内容: {instr_content}")
    print(f"  • 指令字节: {instr_bytes}")
    if instr_bytes and instr_bytes != '未知':
        print(f"  • CSV第一个字节: {instr_bytes.split()[0]}")
    else:
        print(f"  • CSV第一个字节: 未知")

    # 原始指令字节
    insn_bytes = bytes(event.insn_bytes)
    insn_hex = ' '.join([f"{b:02x}" for b in insn_bytes[:16]])
    print(f"  • 原始第一个字节: 0x{insn_bytes[0]:02x} (注: 0xcc=INT3 是 uprobe 断点机制所致)")
    print(f"  • 原始指令字节: {insn_hex}")

    # 合成指令
    if instr_bytes and instr_bytes != '未知' and instr_len > 1:
        csv_first_byte = int(instr_bytes.split()[0], 16)
        new_insn_bytes = [csv_first_byte] + list(insn_bytes[1:instr_len])
        new_insn_hex = ' '.join([f"{b:02x}" for b in new_insn_bytes])
        print(f"\n  🔧 合成指令 (CSV第一个字节 + 原始字节后{instr_len-1}字节):")
        print(f"     指令字节: {new_insn_hex}")

        # 反汇编合成指令
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        for insn in md.disasm(bytes(new_insn_bytes), event.src_offset):
            print(f"     反汇编结果: {insn.mnemonic} {insn.op_str}")
            if insn.mnemonic.startswith(('j', 'call')):
                if len(insn.operands) > 0:
                    op = insn.operands[0]
                    if op.type == 1:  # 立即数
                        target_offset = op.imm
                        target_abs = base + target_offset
                        print(f"         目标偏移: 0x{target_offset:x}")
                        print(f"         目标绝对地址: 0x{target_abs:x}")
                        if target_abs == event.expected_dst:
                            print(f"         ✓ 与CFI预期目标一致")
                        else:
                            print(f"         ✗ 与CFI预期目标不一致 (预期: 0x{event.expected_dst:x})")
            break
    elif instr_bytes and instr_bytes != '未知' and instr_len == 1:
        print(f"\n  🔧 单字节指令: {instr_bytes}")

    # 根据 CSV 第一字节计算目标地址
    print("\n🎯 【根据 CSV 第一字节计算目标地址】")
    computed_target = 0
    comparison_result = "未计算"
    opcode = csv_opcode if csv_opcode else (insn_bytes[0] if instr_len > 0 else 0)

    if opcode:
        print(f"  • 使用的操作码: 0x{opcode:02x}")
        # 直接调用
        if opcode == 0xE8:
            if len(insn_bytes) >= 5:
                offset = int.from_bytes(insn_bytes[:4], 'little', signed=True)
                computed_target = base + event.src_offset + 5 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 直接调用偏移: 0x{offset:08x}")
                print(f"  • 计算目标: 0x{computed_target:016x}")
            else:
                print(f"  • 指令字节不足，无法计算 call rel32")
        # 直接跳转
        elif opcode == 0xE9:
            if len(insn_bytes) >= 5:
                offset = int.from_bytes(insn_bytes[:4], 'little', signed=True)
                computed_target = base + event.src_offset + 5 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 直接跳转偏移: 0x{offset:08x}")
                print(f"  • 计算目标: 0x{computed_target:016x}")
            else:
                print(f"  • 指令字节不足，无法计算 jmp rel32")
        # 短跳转
        elif opcode == 0xEB:
            if len(insn_bytes) >= 2:
                offset = insn_bytes[0] if insn_bytes[0] < 128 else insn_bytes[0] - 256
                computed_target = base + event.src_offset + 2 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 短跳转偏移: 0x{offset:02x}")
                print(f"  • 计算目标: 0x{computed_target:016x}")
            else:
                print(f"  • 指令字节不足，无法计算 jmp rel8")
        # 短条件跳转
        elif 0x70 <= opcode <= 0x7F:
            if len(insn_bytes) >= 2:
                offset = insn_bytes[0] if insn_bytes[0] < 128 else insn_bytes[0] - 256
                computed_target = base + event.src_offset + 2 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 短条件跳转偏移: 0x{offset:02x}")
                print(f"  • 计算目标: 0x{computed_target:016x}")
            else:
                print(f"  • 指令字节不足，无法计算短条件跳转")
        # 长条件跳转
        elif opcode == 0x0F and len(insn_bytes) >= 2:
            second = insn_bytes[0]
            if 0x80 <= second <= 0x8F and len(insn_bytes) >= 6:
                offset = int.from_bytes(insn_bytes[1:5], 'little', signed=True)
                computed_target = base + event.src_offset + 6 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 长条件跳转偏移: 0x{offset:08x}")
                print(f"  • 计算目标: 0x{computed_target:016x}")
            else:
                print(f"  • 无法识别长条件跳转")
        # 间接跳转/调用
        elif opcode == 0xFF:
            if len(insn_bytes) >= 2:
                modrm = insn_bytes[1]
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod == 3:  # 寄存器间接
                    reg_names = {
                        0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx',
                        4: 'rsp', 5: 'rbp', 6: 'rsi', 7: 'rdi'
                    }
                    reg_name = reg_names.get(rm, 'unknown')
                    reg_map = {
                        'rax': event.reg_rax, 'rcx': event.reg_rcx, 'rdx': event.reg_rdx,
                        'rbx': event.reg_rbx, 'rsp': event.reg_rsp, 'rbp': event.reg_rbp,
                        'rsi': event.reg_rsi, 'rdi': event.reg_rdi
                    }
                    computed_target = reg_map.get(reg_name, 0)
                    print(f"  • 间接跳转/调用目标 ({reg_name}): 0x{computed_target:016x}")
                else:
                    print(f"  • 间接跳转/调用: 内存操作数 (ModRM=0x{modrm:02x})，暂不支持解析")
                    computed_target = 0
            else:
                computed_target = event.reg_rax
                print(f"  • 间接跳转/调用目标 (RAX fallback): 0x{computed_target:016x}")

            if computed_target:
                if event.expected_dst == 0:
                    module_end = base + 0x1000000
                    in_module = base <= computed_target < module_end
                    comparison_result = "✓ 在模块内" if in_module else "✗ 超出模块范围"
                else:
                    match = computed_target == event.expected_dst
                    comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
            else:
                comparison_result = "✗ 无效目标"
        # 返回指令
        elif opcode in (0xC3, 0xC2, 0xCB, 0xCA):
            if event.dst_offset != 0:
                computed_target = event.ret_addr          # 使用 ret_addr
                if event.expected_dst == 0:
                    module_end = base + 0x1000000
                    in_module = base <= computed_target < module_end
                    comparison_result = "✓ 在模块内" if in_module else "✗ 超出模块范围"
                else:
                    match = computed_target == event.expected_dst
                    comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 返回地址: 0x{computed_target:016x}")
            else:
                print(f"  • dst_offset 无效，无法计算返回地址")
        else:
            comparison_result = "✗ 未知操作码"
        print(f"  🎯 最终计算结果: {comparison_result}")
    else:
        print("  • 无法获取操作码")

    # 寄存器状态
    print("\n📝 寄存器状态:")
    print(f"  • RAX: 0x{event.reg_rax:016x} (返回值/间接跳转目标)")
    print(f"  • RCX: 0x{event.reg_rcx:016x}")
    print(f"  • RDX: 0x{event.reg_rdx:016x}")
    print(f"  • RBX: 0x{event.reg_rbx:016x}")
    print(f"  • RSP: 0x{event.reg_rsp:016x} (栈指针)")
    print(f"  • RBP: 0x{event.reg_rbp:016x} (帧指针)")
    print(f"  • RSI: 0x{event.reg_rsi:016x}")
    print(f"  • RDI: 0x{event.reg_rdi:016x}")

    # 显示保存的 RAX 值
    print(f"  • 保存的 RAX (trace_rax): 0x{event.saved_rax_val:016x}")
    print(f"  • 保存的 RAX (trace_rsp): 0x{event.saved_rsp_val:016x}")
    # 跳转分析
    print("\n🔍 跳转分析:")
    if event.jump_type in [0, 1, 2]:
        print(f"  • 直接跳转指令")
        print(f"  • CFI预期目标: 0x{event.expected_dst:016x}")
        if event.reg_rax != 0 and event.reg_rax == event.expected_dst:
            print(f"    └─ RAX中的值与预期目标一致")
    elif event.jump_type in [4, 5]:
        print(f"  • 间接跳转指令")
        print(f"  • RAX中的目标: 0x{event.reg_rax:016x}")
        print(f"  • CFI预期目标: 0x{event.expected_dst:016x}")
        if event.expected_dst != 0:
            if event.reg_rax == event.expected_dst:
                print(f"    └─ ✓ 目标匹配")
            else:
                print(f"    └─ ✗ 目标不匹配 (差值: 0x{event.reg_rax - event.expected_dst:x})")
        else:
            in_module = base <= event.reg_rax < base + 0x1000000
            print(f"    └─ 目标是否在模块内: {'是' if in_module else '否'}")
    elif event.jump_type == 3:
        print(f"  • 返回指令")
        print(f"  • 返回地址: 0x{event.ret_addr:016x}")
        print(f"  • 模块范围: [0x{base:016x}, 0x{base + 0x1000000:016x}]")

    # 验证结果
    print("\n✅ 验证结果:")
    if event.is_correct:
        print(f"  ✓ 此跳转符合CFI规则")
    else:
        print(f"  ✗ 此跳转违反CFI规则")
        print(f"  🔴 可能的原因:")
        if event.jump_type in [4, 5] and event.expected_dst != 0 and event.reg_rax != event.expected_dst:
            print(f"     • 间接跳转目标与预期不符")
        elif event.jump_type in [4, 5] and event.expected_dst == 0:
            if event.reg_rax < base or event.reg_rax >= base + 0x1000000:
                print(f"     • 间接跳转目标超出模块范围")
        elif event.jump_type == 3:
            print(f"     • 返回地址异常")
        else:
            print(f"     • 指令类型不匹配或其他原因")

    print("\n" + "-"*80)
    event_count += 1

def handle_df1_layer_event(cpu, data, size):
    global layer_event_count
    event = b["dfi_layer_events"].event(data)
    func_name = event.func_name.decode('utf-8', errors='ignore').split('\x00')[0].strip()

    layer_label = {1: "L1 (call/jmp target)", 2: "L2 (deref ptr)", 3: "L3 (ptr load)"}
    label = layer_label.get(event.layer, f"L{event.layer}")

    print(f"\n{'='*70}")
    print(f"[三层DFI保护] {label}  site_id={event.site_id}  func={func_name}")
    print(f"{'='*70}")
    print(f"  📍 指令偏移:      0x{event.inst_offset:016x}")
    
    # reg_value: for type 0/1 = register snapshot; for type 2/3 = value read from memory
    if event.reg_value != 0:
        print(f"  📝 寄存器/内存值:  0x{event.reg_value:016x}")
    else:
        print(f"  📝 寄存器/内存值:  0x0000000000000000 (读取失败或为空)")
    
    # target_addr: computed target address
    if event.target_addr != 0:
        print(f"  🎯 间接跳转目标:  0x{event.target_addr:016x}")
        if event.layer == 1:
            print(f"      ✅ 目标地址 = 寄存器值 (DIRECT)")
        elif event.layer == 2:
            print(f"      🔗 *(寄存器/内存值) → 目标地址")
        elif event.layer == 3:
            print(f"      🔍 **(内存) → 目标地址")
    else:
        print(f"  🎯 间接跳转目标:  (计算失败或无效)")
    
    print(f"  ⏱️  时间戳:       {event.timestamp} ns")
    print(f"  💻 CPU:           {event.cpu}")
    print(f"  🆔 PID:           {event.pid}")
    print(f"{'─'*70}")
    layer_event_count += 1

def get_module_base_from_maps(so_name):
    """从 /proc/self/maps 中获取共享库的加载基址"""
    with open('/proc/self/maps', 'r') as f:
        for line in f:
            if so_name in line:
                start_addr = int(line.split('-')[0], 16)
                return start_addr
    return None

def main():
    global b, event_count, violation_count, base, cfi_lookup, layer_event_count
    event_count = 0
    layer_event_count = 0
    violation_count = 0
    cfi_lookup = {}

    script_dir = os.path.dirname(os.path.abspath(__file__))
    so_path = os.path.join(script_dir, "test.so")
    if not os.path.exists(so_path):
        print(f"错误：找不到 {so_path}")
        return

    # 解析三层 DFI 链
    print("\n📊 解析三层 DFI 数据流链...")
    layer_chains, func_bases = parse_df1_layer_chains()
    print(f"✅ 发现 {len(layer_chains)} 个基于寄存器的间接跳转站点")
    for chain in layer_chains:
        print(f"   • {chain['func']} @ 0x{chain['jump_addr']:x}  寄存器={chain['reg']}")
        for layer in chain['layers']:
            itype_names = {0: "DIRECT", 1: "DEREF", 2: "RIP_REL", 3: "RBP_REL"}
            itname = itype_names.get(layer.get('instr_type', 0), "?")
            print(f"      L{layer['level']}: 0x{layer['def_addr']:x} (offset=0x{layer['offset']:x}) "
                  f"type={itname} extra=0x{layer.get('extra',0):x} len={layer.get('instr_len',0)} "
                  f"deref={layer.get('need_deref',0)} "
                  f"→ {layer['instr']}")

    # 解析 CFI 表
    table = parse_cfi_table("test_jump_analysis.csv")
    for entry in table:
        cfi_lookup[entry['src_addr']] = entry

    # 从 CSV 中获取 test_returns 的静态偏移
    static_offset = None
    for entry in table:
        if entry['src_func'].decode() == "test_returns":
            static_offset = entry['src_func_addr']
            break
    if static_offset is None:
        print("错误：无法从 CSV 中找到 test_returns 函数起始地址")
        return

    # 加载 BPF 程序
    print("\n加载BPF程序...")
    b = BPF(text=get_bpf_text())

    # 计算模块基址
    lib = ctypes.CDLL(so_path)
    func_addr = ctypes.cast(getattr(lib, "test_returns"), ctypes.c_void_p).value
    base = get_module_base_from_maps("test.so")
    print(f"检测到 test.so 基址: 0x{base:x}")

    b["module_base"][ctypes.c_uint64(0)] = ctypes.c_uint64(base)

    # 加载 CFI 规则
    for entry in table:
        offset = ctypes.c_uint64(entry['src_addr'])
        cfi = CfiEntry(**{k: v for k, v in entry.items() if k in [f[0] for f in CfiEntry._fields_]})
        b["cfi_map"][offset] = cfi

    # 打开 perf buffers
    b["jump_events"].open_perf_buffer(handle_jump_event)
    b["dfi_layer_events"].open_perf_buffer(handle_df1_layer_event)

    # 加载三层 DFI 配置并挂载 uprobes
    # L1: trace_all_jumps (CFI 校验) + trace_df1_l1 (记录实际调用目标)
    # L2: trace_df1_l2   (预期目标计算 + 自动更新 saved_rax)
    # L3: trace_df1_l3   (数据流追溯)
    print("\n🔗 挂载三层 DFI 数据流保护 + CFI 校验 uprobes...")
    reg_to_idx = REG_TO_IDX
    attached = {}  # (sym_name, sym_off) -> fn_name，处理 L2/L3 同偏移冲突

    for site_id, chain in enumerate(layer_chains):
        if chain['reg'] == 'rsp' and chain['layers'][0]['instr_type'] == 4:   # RET 站点
            l1 = chain['layers'][0]
            sym = chain['func'].split('@')[0]
            # trace_ret_target 挂函数头 (sym_off=0): 保存入口 *(rsp) → saved_rsp
            b.attach_uprobe(name=so_path, sym=sym, sym_off=0, fn_name="trace_ret_target")
            # trace_all_jumps   挂 ret 处:   读取 *(rsp) 对比 saved_rsp
            b.attach_uprobe(name=so_path, sym=sym, sym_off=l1['offset'], fn_name="trace_all_jumps")
            print(f"  ✓ RET site#{site_id}: {sym}+0x0 (save ret addr) + 0x{l1['offset']:x} (verify)")
            continue   # 跳过后续 L2/L3 的挂载
        reg_idx = reg_to_idx.get(chain['reg'], 0)
        func = chain['func']
        sym_name = func.split('@')[0]

        for layer in chain['layers']:
            level = layer['level']
            def_addr = layer['def_addr']
            sym_off = layer['offset']
            addr_key = (sym_name, sym_off)

            # 决定挂载哪个 BPF 函数
            if level == 1:
                fn_name = "trace_df1_l1"       # L1: DFI 事件记录实际调用目标
            elif level == 2:
                fn_name = "trace_df1_l2"       # L2: 预期目标计算 + 保存 saved_rax
            else:
                fn_name = "trace_df1_l3"       # L3: 数据流追溯

            # 冲突处理 (L2/L3 之间; L1 与 L2/L3 map 不同可共存)
            if level != 1 and addr_key in attached:
                existing = attached[addr_key]
                if level == 2 and existing == "trace_df1_l3":
                    pass  # L2 覆盖 L3
                elif level == 3 and existing == "trace_df1_l2":
                    continue  # L2 已存在且更优，跳过 L3
                elif existing in ("trace_df1_l2", "trace_df1_l3"):
                    continue  # 同层冲突，跳过

            # 准备 meta + 挂载 — L1/L2/L3 都需要 meta (L1 记录实际目标)
            meta = DfiLayerMeta()
            meta.site_id = site_id
            meta.reg_sel = reg_idx
            meta.instr_type = layer.get('instr_type', 0)
            meta.extra = layer.get('extra', 0)
            meta.instr_len = layer.get('instr_len', 0)
            meta.need_deref = layer.get('need_deref', 0)
            meta.save_target_to_saved_rax = 1 if level == 2 else 0  # 仅 L2 保存预期目标
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
                tag = {1: "DFI+L1(实际目标)", 2: "DFI+L2+SAVE", 3: "DFI+L3"}.get(level, f"L{level}")
                print(f"  ✓ site#{site_id} {tag}: {sym_name}+0x{sym_off:x}  ({layer['instr']})")
            except Exception as e:
                print(f"  ✗ site#{site_id} L{level}: {sym_name}+0x{sym_off:x} 挂载失败 ({e})")

            # L1 额外挂载 trace_all_jumps 做 CFI 校验 (与 trace_df1_l1 共用偏移)
            if level == 1:
                try:
                    b.attach_uprobe(name=so_path, sym=sym_name, sym_off=sym_off, fn_name="trace_all_jumps")
                    print(f"  ✓ site#{site_id} CFI:     {sym_name}+0x{sym_off:x}  (trace_all_jumps)")
                except Exception as e:
                    print(f"  ✗ site#{site_id} CFI:     {sym_name}+0x{sym_off:x}  ({e})")

    # 触发函数
    def trigger():
        while True:
            lib.test_all()
            time.sleep(1)

    threading.Thread(target=trigger, daemon=True).start()

    print("\n=== CFI 监控已启动（.so 模式 + 三层 DFI）===")
    print("按 Ctrl+C 停止\n")

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n监控已停止")
    finally:
        print(f"\n=== 最终统计 ===")
        print(f"- CFI规则数: {len(table)}")
        print(f"- 处理事件数: {event_count}")
        print(f"- CFI违规数: {violation_count}")
        print(f"- 三层DFI事件数: {layer_event_count}")
        if event_count > 0:
            violation_rate = (violation_count / event_count) * 100
            print(f"- 违规率: {violation_rate:.2f}%")

if __name__ == "__main__":
    main()