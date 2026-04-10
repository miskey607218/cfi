from bcc import BPF
import ctypes
import os
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
        ("sp", ctypes.c_uint64),
    ]

def get_module_base_from_maps(so_name):
    """从 /proc/self/maps 中获取共享库的加载基址"""
    with open('/proc/self/maps', 'r') as f:
        for line in f:
            if so_name in line:
                start_addr = int(line.split('-')[0], 16)
                return start_addr
    return None

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
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);

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
    event.reg_rax = ctx->ax;
    event.reg_rcx = ctx->cx;
    event.reg_rdx = ctx->dx;
    event.reg_rbx = ctx->bx;
    event.reg_rsp = ctx->sp;
    event.reg_rbp = ctx->bp;
    event.reg_rsi = ctx->si;
    event.reg_rdi = ctx->di;

    bpf_probe_read(event.insn_bytes, 16, (void*)ip);
    bpf_probe_read(event.src_func, 64, entry->src_func);
    bpf_probe_read(event.dst_func, 64, entry->dst_func);
    
    if (entry->jump_type == 3) {  // RET
        u64 sp = PT_REGS_SP(ctx);
        bpf_probe_read(&event.ret_addr, sizeof(event.ret_addr), (void *)sp);
    } else {
        event.ret_addr = 0;
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
    print(f"  • 预期目标地址: 0x{(event.expected_dst-base):016x}")
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
    print(f"  • 原始第一个字节: 0x{insn_bytes[0]:02x}")
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
            # 如果是跳转/调用，计算目标地址
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
            # 根据 ModRM 字节解析使用的寄存器
            if len(insn_bytes) >= 2:
                modrm = insn_bytes[1]
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod == 3:  # 寄存器间接
                    # 根据 rm 值确定寄存器名称
                    reg_names = {
                        0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx',
                        4: 'rsp', 5: 'rbp', 6: 'rsi', 7: 'rdi'
                    }
                    reg_name = reg_names.get(rm, 'unknown')
                    # 从 event 中获取对应寄存器的值
                    reg_map = {
                        'rax': event.reg_rax, 'rcx': event.reg_rcx, 'rdx': event.reg_rdx,
                        'rbx': event.reg_rbx, 'rsp': event.reg_rsp, 'rbp': event.reg_rbp,
                        'rsi': event.reg_rsi, 'rdi': event.reg_rdi
                    }
                    computed_target = reg_map.get(reg_name, 0)
                    print(f"  • 间接跳转/调用目标 ({reg_name}): 0x{computed_target:016x}")
                else:
                    # 内存间接，暂不支持精确解析
                    print(f"  • 间接跳转/调用: 内存操作数 (ModRM=0x{modrm:02x})，暂不支持解析")
                    computed_target = 0
            else:
                # 指令字节不足，使用 RAX fallback
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
                computed_target = event.sp
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

    # 跳转分析
    print("\n🔍 跳转分析:")
    if event.jump_type in [0, 1, 2]:  # 直接跳转
        print(f"  • 直接跳转指令")
        print(f"  • CFI预期目标: 0x{event.expected_dst:016x}")
        if event.reg_rax != 0 and event.reg_rax == event.expected_dst:
            print(f"    └─ RAX中的值与预期目标一致")
    elif event.jump_type in [4, 5]:  # 间接跳转
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
    elif event.jump_type == 3:  # 返回
        print(f"  • 返回指令")
        print(f"  • 栈指针(RSP): 0x{event.ret_addr:016x}")
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

def main():
    global b, event_count, violation_count, base, cfi_lookup
    event_count = 0
    violation_count = 0
    cfi_lookup = {}

    script_dir = os.path.dirname(os.path.abspath(__file__))
    so_path = os.path.join(script_dir, "libvuln.so")
    if not os.path.exists(so_path):
        print(f"错误：找不到 {so_path}")
        return

    # 解析 CSV
    table = parse_cfi_table("libvuln_jump_analysis.csv")
    for entry in table:
        cfi_lookup[entry['src_addr']] = entry

    # 加载 BPF 程序
    print("\n加载BPF程序...")
    b = BPF(text=get_bpf_text())

    # 加载共享库到当前进程（用于触发漏洞）
    lib = ctypes.CDLL(so_path)

    # 获取共享库基址
    base = get_module_base_from_maps("libvuln.so")
    print(f"检测到 libvuln.so 基址: 0x{base:x}")

    b["module_base"][ctypes.c_uint64(0)] = ctypes.c_uint64(base)

    # 加载 CFI 规则
    for entry in table:
        offset = ctypes.c_uint64(entry['src_addr'])
        cfi = CfiEntry(**{k: v for k, v in entry.items() if k in [f[0] for f in CfiEntry._fields_]})
        b["cfi_map"][offset] = cfi

    b["jump_events"].open_perf_buffer(handle_jump_event)

    # 为每个跳转指令附加 uprobe
    attached = 0
    for entry in table:
        try:
            b.attach_uprobe(name=so_path, addr=entry['src_addr'], fn_name="trace_all_jumps")
            attached += 1
        except Exception as e:
            print(f"附加 uprobe 到偏移 0x{entry['src_addr']:x} 失败: {e}")
    print(f"成功附加 {attached} 个 uprobe 探测点")

    # 触发漏洞的线程
    def trigger():
        payload = b'A' * 199 + b'\x00'   # 200 字节，确保溢出
        while True:
            lib.vulnerable_function(payload)
            time.sleep(2)

    threading.Thread(target=trigger, daemon=True).start()

    print("\n=== CFI 监控已启动（监控 libvuln.so）===")
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
        if event_count > 0:
            violation_rate = (violation_count / event_count) * 100
            print(f"- 违规率: {violation_rate:.2f}%")
            
if __name__ == "__main__":
    main()