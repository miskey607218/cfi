#!/usr/bin/env python3
"""
trace_registers.py — 指令级寄存器变化追踪（无三层DFI）
=====================================================
直接对 test.so 中每条会修改寄存器的指令挂载 uprobe，
按模块执行先后顺序记录改变寄存器的指令及其值到文件。

用法:
    sudo python3 trace_registers.py [--output trace_output.csv]

架构:
    objdump -d  →  解析所有"会写寄存器"的指令  →  挂载 uprobe
    eBPF 捕获全量寄存器  →  Python 差分  →  只写变化到文件
"""

import sys
import os
import re
import ctypes
import csv
import time
import threading
import argparse
from collections import defaultdict
from bcc import BPF

# ============================================================
#  1. 指令分类 — 判断一条指令是否"写寄存器"
# ============================================================

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

REG_ORDER = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',
             'r8','r9','r10','r11','r12','r13','r14','r15']

REG_TO_EVENT_FIELD = {
    'rax': 'reg_rax', 'rcx': 'reg_rcx', 'rdx': 'reg_rdx',
    'rbx': 'reg_rbx', 'rsp': 'reg_rsp', 'rbp': 'reg_rbp',
    'rsi': 'reg_rsi', 'rdi': 'reg_rdi',
}

def norm_reg(r: str) -> str:
    r = r.strip().lower().lstrip('%')
    return REG_ALIASES.get(r, r)

def extract_regs(operand_str: str) -> list:
    """从操作数字符串中提取所有规范寄存器名（去重）"""
    tokens = re.findall(r'%?[a-zA-Z][a-zA-Z0-9]*', operand_str)
    regs = []
    for t in tokens:
        r = norm_reg(t)
        if r and r in REG_ALIASES:
            regs.append(r)
    return list(dict.fromkeys(regs))

def get_dst_regs(mnemonic: str, operands: str) -> list:
    """
    分析一条 AT&T 汇编指令，返回它**会写入**的寄存器列表。
    返回空列表 = 该指令不修改寄存器（如 nop, jmp, cmp, test）。
    """
    m = mnemonic.lower()
    op = operands.strip()

    # ── 无操作数指令 ──
    if not op:
        if m in ('ret', 'retq'):
            return ['rsp']         # ret 后 rsp += 8
        if m == 'leave':
            return ['rsp', 'rbp']  # mov %rbp,%rsp; pop %rbp
        if m in ('push', 'pushq', 'pop', 'popq'):
            return ['rsp']
        return []

    parts = [p.strip() for p in op.split(',')]

    if len(parts) == 2:
        src_str, dst_str = parts
        dst_regs = extract_regs(dst_str)
        dst_is_mem = '(' in dst_str and ')' in dst_str

        # cmp / test 只设标志位，不写寄存器
        if m.startswith('cmp') or m.startswith('test'):
            return []

        if m.startswith('mov') or m.startswith('vmov'):
            return [] if dst_is_mem else dst_regs

        if m.startswith('lea'):
            return dst_regs

        if m in ('add','sub','imul','and','or','xor','shl','shr','sar',
                 'ror','rol','adc','sbb','neg','not','inc','dec',
                 'bsf','bsr','popcnt','tzcnt','lzcnt'):
            return [] if dst_is_mem else dst_regs

        if m.startswith('cmov'):
            return dst_regs

        if m in ('xchg','xchgq'):
            return list(dict.fromkeys(dst_regs + extract_regs(src_str)))

        # 默认: 写目标寄存器
        return dst_regs if not dst_is_mem else []

    elif len(parts) == 1:
        regs = extract_regs(op)
        if m in ('push', 'pushq'):
            return ['rsp']
        if m in ('pop', 'popq'):
            return regs + ['rsp']
        if m in ('inc','dec','neg','not'):
            return regs
        if m in ('call', 'callq'):
            return ['rax']         # 返回值
        if m in ('mul','imul'):
            return ['rax','rdx']
        if m in ('idiv','div'):
            return ['rax','rdx']
        return []

    return []


# ============================================================
#  2. objdump 解析 — 找出所有"会写寄存器"的指令
# ============================================================

FUNC_RE = re.compile(r'^([0-9a-f]+)\s+<([^>]+)>:$')
INSTR_RE = re.compile(
    r'^\s+([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(\S+)\s*(.*?)(?:\s*#.*)?$'
)

SKIP_FUNCS = {
    '_init', '_fini', '_start', '__cxa_finalize', '__stack_chk_fail',
    '__gmon_start__', 'deregister_tm_clones', 'register_tm_clones',
    '__do_global_dtors_aux', 'frame_dummy', '.plt',
    # PLT stubs — 不需要追踪（它们只是跳板）
}

def is_plt_stub(name: str) -> bool:
    return name.endswith('@plt')

def is_skip_func(name: str) -> bool:
    return name in SKIP_FUNCS or is_plt_stub(name) or name.startswith('.')

def parse_objdump(filepath: str) -> list:
    """
    解析 objdump -d 输出，返回需要挂载探针的指令列表。
    每条记录: {func, func_start, offset, addr, mnemonic, operands, asm, dst_regs}
    """
    instructions = []
    current_func = None
    current_func_start = 0

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')

            fm = FUNC_RE.match(line.strip())
            if fm:
                addr = int(fm.group(1), 16)
                name = fm.group(2)
                if is_skip_func(name):
                    current_func = None
                    continue
                current_func = name
                current_func_start = addr
                continue

            if current_func is None:
                continue

            im = INSTR_RE.match(line)
            if not im:
                continue

            addr = int(im.group(1), 16)
            mnemonic = im.group(2)
            operands = im.group(3).strip()
            operands = re.sub(r'#.*$', '', operands).strip()

            dst_regs = get_dst_regs(mnemonic, operands)
            if not dst_regs:
                continue   # 不修改任何寄存器，跳过

            offset = addr - current_func_start
            asm = f"{mnemonic} {operands}".strip()

            instructions.append({
                'func': current_func,
                'func_start': current_func_start,
                'offset': offset,
                'addr': addr,
                'mnemonic': mnemonic,
                'operands': operands,
                'asm': asm,
                'dst_regs': dst_regs,
            })

    return instructions


# ============================================================
#  3. eBPF 程序 — 在所有探针点捕获全量寄存器
# ============================================================

BPF_TEXT = """
#include <uapi/linux/ptrace.h>

struct reg_event {
    u64 offset;        // 指令偏移 (相对模块基址)
    u64 timestamp_ns;
    u32 pid;
    u32 cpu;
    u64 reg_rax;
    u64 reg_rcx;
    u64 reg_rdx;
    u64 reg_rbx;
    u64 reg_rsp;
    u64 reg_rbp;
    u64 reg_rsi;
    u64 reg_rdi;
};

BPF_HASH(module_base_map, u64, u64);
BPF_PERF_OUTPUT(reg_events);

int trace_instruction(struct pt_regs *ctx) {
    u64 zero = 0;
    u64 *base = module_base_map.lookup(&zero);
    if (!base) return 0;

    u64 ip = PT_REGS_IP(ctx);
    u64 offset = ip - *base;

    struct reg_event evt = {};
    evt.offset = offset;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.cpu = bpf_get_smp_processor_id();

    bpf_probe_read(&evt.reg_rax, sizeof(evt.reg_rax), &ctx->ax);
    bpf_probe_read(&evt.reg_rcx, sizeof(evt.reg_rcx), &ctx->cx);
    bpf_probe_read(&evt.reg_rdx, sizeof(evt.reg_rdx), &ctx->dx);
    bpf_probe_read(&evt.reg_rbx, sizeof(evt.reg_rbx), &ctx->bx);
    bpf_probe_read(&evt.reg_rsp, sizeof(evt.reg_rsp), &ctx->sp);
    bpf_probe_read(&evt.reg_rbp, sizeof(evt.reg_rbp), &ctx->bp);
    bpf_probe_read(&evt.reg_rsi, sizeof(evt.reg_rsi), &ctx->si);
    bpf_probe_read(&evt.reg_rdi, sizeof(evt.reg_rdi), &ctx->di);

    reg_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""


# ============================================================
#  4. 事件结构体 & 运行时状态
# ============================================================

class RegEvent(ctypes.Structure):
    _fields_ = [
        ("offset",        ctypes.c_uint64),
        ("timestamp_ns",  ctypes.c_uint64),
        ("pid",           ctypes.c_uint32),
        ("cpu",           ctypes.c_uint32),
        ("reg_rax",       ctypes.c_uint64),
        ("reg_rcx",       ctypes.c_uint64),
        ("reg_rdx",       ctypes.c_uint64),
        ("reg_rbx",       ctypes.c_uint64),
        ("reg_rsp",       ctypes.c_uint64),
        ("reg_rbp",       ctypes.c_uint64),
        ("reg_rsi",       ctypes.c_uint64),
        ("reg_rdi",       ctypes.c_uint64),
    ]

# 全局状态
output_file = None
output_writer = None
event_count = 0
change_count = 0
last_state = {}           # pid -> {reg_name: value}
instr_info = {}           # offset -> {func, asm, dst_regs}
probed_offsets = set()
bpf_module = None
module_base = 0
start_time = 0
lock = threading.Lock()


# ============================================================
#  5. 事件处理器 — 差分并写文件
# ============================================================

def handle_reg_event(cpu, data, size):
    global event_count, change_count, last_state, output_writer

    evt = bpf_module["reg_events"].event(data)
    pid = evt.pid
    offset = evt.offset

    # 查找指令信息
    info = instr_info.get(offset)
    if info is None:
        return   # 非追踪范围内的指令

    event_count += 1
    func = info['func']
    asm = info['asm']
    dst_regs = info['dst_regs']

    # 当前寄存器值
    current = {
        'rax': evt.reg_rax, 'rcx': evt.reg_rcx,
        'rdx': evt.reg_rdx, 'rbx': evt.reg_rbx,
        'rsp': evt.reg_rsp, 'rbp': evt.reg_rbp,
        'rsi': evt.reg_rsi, 'rdi': evt.reg_rdi,
    }

    if pid not in last_state:
        last_state[pid] = {}

    has_change = False
    elapsed_ms = (evt.timestamp_ns - start_time) / 1_000_000

    for reg in dst_regs:
        val = current.get(reg)
        if val is None:
            continue
        prev = last_state[pid].get(reg)
        if prev is None or val != prev:
            has_change = True
            old_str = f"0x{prev:016x}" if prev is not None else "(首次)"
            new_str = f"0x{val:016x}"

            with lock:
                output_writer.writerow({
                    'elapsed_ms': f"{elapsed_ms:.3f}",
                    'pid': pid,
                    'cpu': evt.cpu,
                    'func': func,
                    'offset': f"0x{info['offset']:x}",
                    'reg': reg.upper(),
                    'old_value': old_str,
                    'new_value': new_str,
                    'instruction': asm,
                })
            change_count += 1

    # 更新所有寄存器快照（不仅是 dst_regs，因为其他寄存器也可能被隐式修改）
    for reg in current:
        last_state[pid][reg] = current[reg]


# ============================================================
#  6. 终端实时显示（简要）
# ============================================================

def handle_reg_event_display(cpu, data, size):
    """带终端输出的版本 — 在 handle_reg_event 基础上加打印"""
    global event_count
    evt = bpf_module["reg_events"].event(data)
    pid = evt.pid
    offset = evt.offset

    info = instr_info.get(offset)
    if info is None:
        return

    event_count += 1
    func = info['func']
    asm = info['asm']
    dst_regs = info['dst_regs']

    current = {
        'rax': evt.reg_rax, 'rcx': evt.reg_rcx,
        'rdx': evt.reg_rdx, 'rbx': evt.reg_rbx,
        'rsp': evt.reg_rsp, 'rbp': evt.reg_rbp,
        'rsi': evt.reg_rsi, 'rdi': evt.reg_rdi,
    }

    if pid not in last_state:
        last_state[pid] = {}

    changed = []
    for reg in dst_regs:
        val = current.get(reg)
        if val is None:
            continue
        prev = last_state[pid].get(reg)
        if prev is None or val != prev:
            direction = "↗" if (prev is not None and val > prev) else ("↘" if (prev is not None and val < prev) else "→")
            old_s = f"0x{prev:016x}" if prev is not None else "(新)"
            changed.append(f"{reg.upper()}: {direction} {old_s} → 0x{val:016x}")

    if changed:
        elapsed_ms = (evt.timestamp_ns - start_time) / 1_000_000
        print(f"[{elapsed_ms:8.1f}ms] {func}+0x{info['offset']:x}  {asm}")
        for c in changed:
            print(f"           {c}")

    # 保存到 CSV
    handle_reg_event(cpu, data, size)


# ============================================================
#  7. 主程序
# ============================================================

def get_module_base_from_maps(so_name: str) -> int:
    """获取模块的加载基址 (VMA=0 对应的运行时地址)。

    对于 PIE 共享库，第一个 LOAD 段的 p_vaddr=0，
    它在 /proc/self/maps 中对应的是该库地址最低的映射。
    不能只取 r-x 映射，因为 r-x 段可能有非零的 p_vaddr 偏移。
    """
    base = None
    with open('/proc/self/maps', 'r') as f:
        for line in f:
            if so_name in line:
                addr = int(line.split('-')[0], 16)
                if base is None or addr < base:
                    base = addr
    return base or 0


def main():
    global output_writer, instr_info, probed_offsets, bpf_module
    global module_base, start_time, last_state

    parser = argparse.ArgumentParser(description='指令级寄存器变化追踪')
    parser.add_argument('-o', '--output', default='register_trace.csv',
                        help='输出 CSV 文件路径 (默认: build/register_trace.csv)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='静默模式：不打印终端输出，只写文件')
    parser.add_argument('-d', '--disasm', default='test.txt',
                        help='objdump 反汇编文件 (默认: build/test.txt)')
    parser.add_argument('-s', '--so', default='test.so',
                        help='目标 .so 文件 (默认: src/test.so)')
    parser.add_argument('-n', '--iterations', type=int, default=3,
                        help='test_all() 执行次数 (默认: 3)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("请用 sudo 运行!")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)          # dfi_rop/
    src_dir = os.path.join(project_dir, 'src')
    build_dir = os.path.join(project_dir, 'build')

    # 如果参数只是文件名，自动加上对应目录前缀
    if not os.path.dirname(args.so):
        args.so = os.path.join(src_dir, args.so)
    if not os.path.dirname(args.disasm):
        args.disasm = os.path.join(build_dir, args.disasm)
    if not os.path.dirname(args.output):
        args.output = os.path.join(build_dir, args.output)

    so_path = args.so
    disasm_path = args.disasm

    if not os.path.exists(so_path):
        print(f"错误：找不到 {so_path}")
        sys.exit(1)

    # ── Phase 1: 生成反汇编（如果需要） ──
    if not os.path.exists(disasm_path):
        print(f"[*] 生成反汇编: objdump -d {args.so} > {args.disasm}")
        os.system(f"objdump -d {so_path} > {disasm_path}")

    # ── Phase 2: 解析 objdump，找出所有会修改寄存器的指令 ──
    print(f"[*] 解析反汇编: {disasm_path}")
    instrs = parse_objdump(disasm_path)
    print(f"[*] 发现 {len(instrs)} 条会修改寄存器的指令")

    # 构建 offset → info 索引
    for i in instrs:
        instr_info[i['addr'] - i['func_start']] = i
        # 同时用全局 offset (addr - base) — 稍后填入
    print(f"[*] 涉及 {len(set(i['func'] for i in instrs))} 个函数")

    # 打印函数级统计
    func_counts = defaultdict(int)
    for i in instrs:
        func_counts[i['func']] += 1
    for func, count in sorted(func_counts.items(), key=lambda x: -x[1]):
        print(f"    {func}: {count} 条探针")

    # ── Phase 3: 加载 BPF ──
    print(f"\n[*] 加载 eBPF 程序...")
    bpf_module = BPF(text=BPF_TEXT)

    # 获取模块基址
    lib = ctypes.CDLL(so_path)
    # 触发加载
    try:
        func_addr = ctypes.cast(getattr(lib, "test_all"), ctypes.c_void_p).value
    except AttributeError:
        print("错误：test.so 中没有 test_all 符号")
        sys.exit(1)

    module_base = get_module_base_from_maps(args.so)
    if module_base == 0:
        print("错误：无法从 /proc/self/maps 中获取模块基址")
        sys.exit(1)
    print(f"[*] 模块基址: 0x{module_base:x}")

    bpf_module["module_base_map"][ctypes.c_uint64(0)] = ctypes.c_uint64(module_base)

    # 用绝对地址重建 instr_info
    global_offset_info = {}
    for i in instrs:
        abs_addr = i['addr']  # objdump 中的地址是相对于 0 的
        goff = abs_addr       # 用作 event 中的 offset
        global_offset_info[goff] = i
    instr_info = global_offset_info

    # ── Phase 4: 挂载 uprobes ──
    # 使用 addr (文件偏移) 而非 sym+offset，因为非导出符号
    # 在 .dynsym 中不可见，sym 解析会静默失败
    print(f"\n[*] 挂载 uprobes ({len(instrs)} 个探针点)...")
    attached = 0
    failed = 0
    seen = set()

    for i in instrs:
        file_offset = i['addr']   # objdump 地址即文件偏移 (PIE/.so)

        if file_offset in seen:
            continue
        seen.add(file_offset)

        try:
            bpf_module.attach_uprobe(
                name=so_path,
                addr=file_offset,
                fn_name="trace_instruction"
            )
            probed_offsets.add(file_offset)
            attached += 1
        except Exception as e:
            failed += 1
            if failed <= 5:
                print(f"  ✗ 0x{file_offset:x} [{i['func']}]: {e}")

    print(f"  挂载成功: {attached}, 失败: {failed}")

    # ── Phase 5: 打开输出文件 ──
    csv_path = args.output  # 已在上面添加了 build/ 前缀
    out_f = open(csv_path, 'w', newline='', encoding='utf-8')
    fieldnames = ['elapsed_ms', 'pid', 'cpu', 'func', 'offset',
                  'reg', 'old_value', 'new_value', 'instruction']
    output_writer = csv.DictWriter(out_f, fieldnames=fieldnames)
    output_writer.writeheader()
    out_f.flush()

    print(f"[*] 输出文件: {csv_path}")
    print(f"[*] 字段: {', '.join(fieldnames)}")

    # ── Phase 6: 打开 perf buffer ──
    handler = handle_reg_event_display if not args.quiet else handle_reg_event
    bpf_module["reg_events"].open_perf_buffer(handler)

    # ── Phase 7: 触发线程 (固定次数) ──
    trigger_done = threading.Event()

    def trigger():
        for i in range(args.iterations):
            try:
                lib.test_all()
            except Exception as e:
                print(f"  [!] trigger 第{i+1}次异常: {e}")
            time.sleep(0.5)
        trigger_done.set()
        print(f"\n[*] 触发完成 ({args.iterations} 次)，等待缓冲事件写入...")
        time.sleep(1)
        print(f"[*] 事件收集完毕，可以按 Ctrl+C 停止")

    start_time = time.time_ns()
    threading.Thread(target=trigger, daemon=True).start()

    print(f"\n{'='*60}")
    print(f"  指令级寄存器追踪已启动")
    print(f"  探针点: {len(probed_offsets)} 个")
    print(f"  迭代次数: {args.iterations}")
    print(f"  输出文件: {csv_path}")
    print(f"  触发完成后按 Ctrl+C 停止")
    print(f"{'='*60}\n")

    try:
        while True:
            bpf_module.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] 停止中...")
    finally:
        out_f.close()
        print(f"\n{'='*60}")
        print(f"  追踪完成")
        print(f"{'='*60}")
        print(f"  探针点总数:       {len(probed_offsets)}")
        print(f"  捕获事件总数:     {event_count}")
        print(f"  寄存器变化记录数: {change_count}")
        print(f"  输出文件:         {csv_path}")
        print(f"  文件行数:         {change_count + 1} (含表头)")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
