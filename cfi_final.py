from bcc import BPF
import ctypes
import re
import os
import sys
import subprocess
import threading
import time
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import csv

if os.geteuid() != 0:
    print("Run with sudo!")
    sys.exit(1)

def get_module_base(module_name):
    """获取内核模块的加载基址"""
    try:
        with open('/proc/modules', 'r') as f:
            for line in f:
                if line.startswith(module_name + ' '):
                    parts = line.split()
                    if len(parts) >= 6:
                        return int(parts[-1], 16)
    except Exception:
        pass

    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2].startswith(module_name + '_'):
                    return int(parts[0], 16)
    except Exception:
        pass

    return None

class CfiEntry(ctypes.Structure):
    _fields_ = [
        ("src_addr", ctypes.c_uint64),
        ("src_func_addr", ctypes.c_uint64),
        ("dst_addr", ctypes.c_uint64),
        ("jump_type", ctypes.c_uint8),
        ("is_indirect", ctypes.c_uint8),
        ("src_func", ctypes.c_char * 64),
        ("dst_func", ctypes.c_char * 64),
        ("opcode", ctypes.c_uint8),   # 新增：CSV 中的操作码（指令第一个字节）
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
    ]

def parse_cfi_table(file_path):
    """从 e1000_jump_analysis.csv 读取静态跳转规则"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"文件未找到: {file_path}")

    table = []
    with open(file_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                def to_offset(s):
                    if not s or s == "UNKNOWN":
                        return 0
                    val = int(s, 16)
                    if val >= 0xffffffff00000000:
                        val &= 0xffffffff
                    return val

                src_addr       = to_offset(row['jump_instr_address']) + 1
                src_func_addr  = to_offset(row['parent_function_start'])
                dst_addr       = to_offset(row['target_address'])

                # 读取新增的字段
                instr_len = int(row.get('instr_len', 0)) if row.get('instr_len') else 0
                instr_content = row.get('instr_content', '').strip()
                instr_bytes = row.get('instr_bytes', '').strip()

                jump_instr = row.get('jump_instr', '').strip()
                if jump_instr == 'callq' or jump_instr == 'call':
                    jump_type = 2  # CALL
                elif jump_instr == 'jmp':
                    jump_type = 0  # JMP
                elif jump_instr in ['ret', 'retq']:
                    jump_type = 3  # RET
                else:
                    jump_type = 1  # JCC (条件跳转)

                # 判断是否为间接跳转（根据指令内容中的 '*' 或指令助记符）
                is_indirect = 0
                if '*' in instr_content:
                    is_indirect = 1
                elif jump_instr in ['callq', 'jmp'] and '*' in instr_content:
                    is_indirect = 1
                
                # 如果是间接跳转，调整 jump_type
                if is_indirect:
                    if jump_type == 2:  # CALL
                        jump_type = 4  # INDIRECT_CALL
                    elif jump_type == 0:  # JMP
                        jump_type = 5  # INDIRECT_JMP

                src_func = row.get('parent_function_name', 'unknown').encode('utf-8')[:63]
                dst_func = row.get('target_function_name', 'unknown').encode('utf-8')[:63]
                opcode = 0
                if instr_bytes and instr_bytes != '未知':
                    bytes_list = instr_bytes.split()
                    if bytes_list:
                        try:
                            opcode = int(bytes_list[0], 16)
                        except ValueError:
                            opcode = 0
                entry = {
                    'src_addr': src_addr,
                    'src_func_addr': src_func_addr,
                    'dst_addr': dst_addr,
                    'jump_type': jump_type,
                    'is_indirect': is_indirect,
                    'src_func': src_func,
                    'dst_func': dst_func,
                    # 新增字段
                    'instr_len': instr_len,
                    'instr_content': instr_content,
                    'instr_bytes': instr_bytes,
                    'opcode': opcode,          # 新增
                }
                table.append(entry)
            except Exception as e:
                print(f"解析行出错: {e}")
                continue

    print(f"✅ 从 CSV 成功解析 {len(table)} 个静态跳转规则")
    
    # 统计跳转类型分布
    type_counts = {0:0, 1:0, 2:0, 3:0, 4:0, 5:0}
    for entry in table:
        type_counts[entry['jump_type']] += 1
    
    print("跳转类型分布:")
    type_names = {0:"JMP", 1:"JCC", 2:"CALL", 3:"RET", 4:"INDIRECT_CALL", 5:"INDIRECT_JMP"}
    for t, count in type_counts.items():
        if count > 0:
            print(f"  {type_names[t]}: {count}")
    
    # 显示前几条记录的指令信息作为示例
    if len(table) > 0:
        print("\n前3条记录的指令信息:")
        for i, entry in enumerate(table[:3]):
            print(f"  {i+1}. 指令: {entry['instr_content']}")
            print(f"     长度: {entry['instr_len']} 字节")
            print(f"     字节: {entry['instr_bytes']}")
    
    return table

def get_bpf_text():
    """返回BPF程序代码，实际目标地址计算全部在 parse_jump_target 中完成"""
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
    u8 opcode;               // CSV 中的操作码
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
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);
BPF_HASH(debug_stats, u64, u64);

// 解析指令，根据静态操作码和实际指令字节计算实际目标地址
static int parse_jump_target(struct pt_regs *ctx, u8 *insn_bytes, u64 ip, u64 *target, u8 *len, u8 opcode) {
    u8 first = opcode;              // 使用静态操作码决定指令类型
    *len = 1;
    *target = 0;
    
    // 返回指令
    if (first == 0xC3 || first == 0xCB) {
        *len = 1;
        bpf_probe_read(target, sizeof(*target), (void *)ctx->sp);
        return 1;
    }
    if (first == 0xC2 || first == 0xCA) {
        *len = 3;
        bpf_probe_read(target, sizeof(*target), (void *)ctx->sp);
        return 1;
    }
    
    // 短条件跳转 (0x70-0x7F)
    if (first >= 0x70 && first <= 0x7F) {
        *len = 2;
        s8 offset = (s8)insn_bytes[0];
        *target = ip +  offset + 1;
        return 1;
    }
    
    // 长条件跳转 (0x0F 0x80-0x8F)
    if (first == 0x0F) {
        u8 cond = insn_bytes[0];
        if (cond >= 0x80 && cond <= 0x8F) {
            *len = 6;
            s32 offset;
            bpf_probe_read(&offset, sizeof(offset), &insn_bytes[2]);
            *target = ip + 6 + offset;
            return 1;
        }
        return 0;
    }
    
    // 短跳转 jmp rel8
    if (first == 0xEB) {
        *len = 2;
        s8 offset = (s8)insn_bytes[0];
        *target = ip + 2 + offset;
        return 1;
    }
    
    // 长跳转 jmp rel32
    if (first == 0xE9) {
        *len = 5;
        s32 offset;
        bpf_probe_read(&offset, sizeof(offset), &insn_bytes[0]);
        *target = ip + 5 + offset;
        return 1;
    }
    
    // 直接调用 call rel32
    if (first == 0xE8) {
        *len = 5;
        s32 offset;
        bpf_probe_read(&offset, sizeof(offset), &insn_bytes[0]);
        *target = ip + 4;
        return 1;
    }
    
    // 间接跳转/调用 (FF /2, /3, /4, /5)
    //if (first == 0xFF) {
    //    u8 modrm = insn_bytes[0];
    //    u8 mod = (modrm >> 6) & 3;
    //    u8 rm = modrm & 7;
    //    // 寄存器间接 (mod == 3)
    //    if (mod == 3) {
    //        *target = ctx->ax;   // 目标在 rax 中
    //    } else {
    //        // 内存间接：简化处理，不支持，返回 0
    //        *target = 0;
    //    }
        // 指令长度粗略估计（实际需要根据 modrm 精确计算，这里简化）
    //    *len = 2;
    //    if (mod == 0 || mod == 1 || mod == 2) {
    //        // 可能需要额外的位移或 SIB，保守取 6
    //        *len = 6;
    //    }
    //    return 1;
    //}
    
    // 其他指令不处理
    return 0;
}

int trace_all_jumps(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *base_ptr = module_base.lookup(&key);
    if (!base_ptr) {
        return 0;
    }
    u64 base = *base_ptr;
    u64 ip = PT_REGS_IP(ctx);
    
    if (ip < base) {
        return 0;
    }

    

    u64 offset = ip - base;
   
    u64 *count = debug_stats.lookup(&offset);
    if (!count) {
        u64 one = 1;
        debug_stats.update(&offset, &one);
    } else {
        *count += 1;
        debug_stats.update(&offset, count);
    }
   
    struct cfi_entry *entry = cfi_map.lookup(&offset);
    if (!entry) {
        return 0;
    }
   
    struct jump_event event = {};
    u64 expected_target = 0;
    int is_correct = 0;
   
    event.src_offset = offset;
    event.src_addr = entry->src_addr;
    event.src_func_addr = entry->src_func_addr;
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
    __builtin_memcpy(event.src_func, entry->src_func, sizeof(event.src_func));
    __builtin_memcpy(event.dst_func, entry->dst_func, sizeof(event.dst_func));
    
    event.runtime_ip = ip;          
    event.module_base_addr = base;  

    bpf_probe_read(&event.insn_bytes, sizeof(event.insn_bytes), (void *)ip);
    
    // 解析指令，获取实际目标地址和指令长度
    u64 real_target = 0;
    u8 insn_len = 0;
    parse_jump_target(ctx, event.insn_bytes, ip, &real_target, &insn_len, entry->opcode);
    event.insn_len = insn_len;
    event.real_target = real_target;
    
    // 计算预期目标
    if (entry->dst_addr != 0) {
        expected_target = entry->dst_addr + base;
    }
    event.expected_dst = expected_target;
    
    // 验证
    if (expected_target == 0) {
        is_correct = 1;
    } else {
        is_correct = (real_target == expected_target);
    }
    
    event.is_correct = is_correct;
    
    // 提交事件
    jump_events.perf_submit(ctx, &event, sizeof(event));
   
    return 0;
}
"""

def print_debug_stats(debug_map):
    """打印调试统计信息"""
    if not debug_map:
        print("无调试统计信息")
        return
    
    print("\n=== 调试统计 ===")
    print(f"{'偏移量':<12} {'次数':<8}")
    print("-" * 25)
    
    stats = []
    for key, value in debug_map.items():
        if hasattr(key, 'value'):
            offset = key.value
        else:
            offset = key
            
        if hasattr(value, 'value'):
            count = value.value
        else:
            count = value
            
        stats.append((offset, count))
    
    stats.sort(key=lambda x: x[1], reverse=True)
    
    for offset, count in stats[:20]:
        hex_offset = f"0x{offset:x}"
        print(f"{hex_offset:<12} {count:<8}")

# 全局变量用于统计
event_count = 0
violation_count = 0
cfi_lookup = {}  # 用于通过src_addr快速查找CFI条目

def handle_jump_event(cpu, data, size):
    """处理跳转事件 - 输出完整的CFI信息"""
    global event_count, violation_count, base, cfi_lookup
   
    event = b["jump_events"].event(data)
    
    # 跳转类型名称映射（与BPF中的定义一致）
    jump_type_names = {
        0: "JMP",
        1: "JCC",
        2: "CALL",
        3: "RET",
        4: "INDIRECT_CALL",
        5: "INDIRECT_JMP"
    }
    
    jump_type_name = jump_type_names.get(event.jump_type, f"UNKNOWN({event.jump_type})")
    status = "✓" if event.is_correct else "✗ VIOLATION"
    
    if not event.is_correct:
        violation_count += 1
    
    # 解码函数名字符串
    try:
        src_func_str = event.src_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()
    except:
        src_func_str = str(event.src_func)
    
    try:
        dst_func_str = event.dst_func.decode('utf-8', errors='ignore').split('\x00')[0].strip()
    except:
        dst_func_str = str(event.dst_func)
    
    # 从cfi_lookup中获取指令信息
    src_addr_key = event.src_addr
    cfi_info = cfi_lookup.get(src_addr_key, {})
    
    instr_len = cfi_info.get('instr_len', 0)
    instr_content = cfi_info.get('instr_content', '未知')
    instr_bytes = cfi_info.get('instr_bytes', '未知')
    
    # 输出事件头部
    print("\n" + "="*80)
    print(f"CFI 事件 #{event_count + 1} - {status}")
    print(f"跳转类型: {jump_type_name} ({event.jump_type})")
    print(f"事件时间: {event.timestamp_ns} ns")
    print(f"事件CPU: {event.cpu}")
    print(f"事件PID: {event.pid}")
    print("="*80)
    
    # CFI条目信息
    print("\n📋 CFI 条目信息:")
    print(f"  • 源地址(CFI表): 0x{event.src_addr:016x}")
    print(f"  • 源函数地址: 0x{event.src_func_addr:016x}")
    print(f"  • 目标地址(CFI表): 0x{event.cfi_dst_addr:016x}")
    print(f"  • 源函数: {src_func_str}")
    print(f"  • 目标函数: {dst_func_str}")
    print(f"  • real_target: 0x{event.real_target:016x}")
    # 运行时信息
    print("\n🔄 运行时信息:")
    print(f"  • 运行时源偏移: 0x{event.src_offset:016x}")
    print(f"  • 运行时目标偏移: 0x{event.dst_offset:016x}")
    print(f"  • 预期目标地址: 0x{(event.expected_dst-base):016x}")
    
    # ========== 新增：输出运行时 IP 和模块基址 ==========
    print(f"  • 运行时指令指针(IP/RIP): 0x{event.runtime_ip:016x}")  # 真实运行时指令地址
    print(f"  • 模块加载基址(module_base): 0x{event.module_base_addr:016x}")  # 模块真实加载地址
    # ==================================================

    # 计算实际目标地址（如果有）
    if event.dst_offset != 0:
        actual_target = base + event.dst_offset
        print(f"  • 实际目标地址: 0x{actual_target:016x}")
    
    # 指令信息 - 从CFI表中获取的字段
    print("\n💻 指令信息 (来自CSV):")
    print(f"  • 指令长度: {instr_len} 字节")
    print(f"  • 指令内容: {instr_content}")
    print(f"  • 指令字节: {instr_bytes}")

    # 从CSV指令字节中提取第一个字节
    csv_first_byte = None
    if instr_bytes and instr_bytes != '未知':
        bytes_list = instr_bytes.split()
        if bytes_list:
            csv_first_byte = bytes_list[0]
            print(f"  • CSV第一个字节: {csv_first_byte}")
    else:
        print(f"  • CSV第一个字节: 未知")

    # 原始指令字节
    insn_bytes = bytes(event.insn_bytes)
    insn_hex = ' '.join([f"{b:02x}" for b in insn_bytes[:16]])

    # 从原始指令字节中提取第一个字节
    first_byte = insn_bytes[0] if insn_bytes else 0
    print(f"  • 原始第一个字节: 0x{first_byte:02x}")
    print(f"  • 原始指令字节: {insn_hex}")

    # 生成新指令：CSV第一个字节 + 原始字节的后 instr_len-1 个字节
    if csv_first_byte and instr_len > 1 and len(insn_bytes) >= instr_len:
        # 取 CSV 第一个字节
        new_insn_bytes = [int(csv_first_byte, 16)]
        
        # 从原始字节中取后面的 instr_len-1 个字节
        for i in range(0, instr_len-1):
            if i < len(insn_bytes):
                new_insn_bytes.append(insn_bytes[i])
            else:
                new_insn_bytes.append(0)  # 如果不够长度，补0
        
        # 生成新指令的十六进制字符串
        new_insn_hex = ' '.join([f"{b:02x}" for b in new_insn_bytes])
        print(f"\n  🔧 合成指令 (CSV第一个字节 + 原始字节后{instr_len-1}字节):")
        print(f"     指令字节: {new_insn_hex}")
        
        # 尝试反汇编这个合成指令
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            new_insn_bytes_array = bytes(new_insn_bytes)
            for i, insn in enumerate(md.disasm(new_insn_bytes_array, event.src_offset)):
                if i == 0:  # 只显示第一条指令
                    print(f"     反汇编结果: {insn.mnemonic} {insn.op_str}")
                    
                    # 如果是跳转指令，计算目标地址
                    if insn.mnemonic.startswith('j') or insn.mnemonic == 'call':
                        if len(insn.operands) > 0:
                            op = insn.operands[0]
                            if op.type == 1:  # 立即数
                                target_offset = op.imm
                                target_abs = base + target_offset
                                print(f"         目标偏移: 0x{target_offset:x}")
                                print(f"         目标绝对地址: 0x{target_abs:x}")
                                
                                # 检查是否与CFI预期一致
                                if target_abs == event.expected_dst:
                                    print(f"         ✓ 与CFI预期目标一致")
                                else:
                                    print(f"         ✗ 与CFI预期目标不一致 (预期: 0x{event.expected_dst:x})")
                else:
                    break
        except Exception as e:
            print(f"     反汇编失败: {e}")
    elif csv_first_byte and instr_len == 1:
        # 单字节指令
        print(f"\n  🔧 单字节指令: {csv_first_byte}")
    else:
        print(f"\n  🔧 无法合成指令: 参数不足")



        # ==================== 根据 csv_first_byte 值直接计算目标地址 ====================
    print("\n🎯 【根据 CSV 第一字节计算目标地址】")
    computed_target = 0
    comparison_result = "未计算"
    
    # 将 csv_first_byte 转换为整数
    if csv_first_byte is not None and csv_first_byte != '未知' and csv_first_byte != '':
        try:
            opcode = int(csv_first_byte, 16)
            print(f"  • 解析出的操作码: 0x{opcode:02x}")  # 适配原程序的打印风格
        except ValueError:
            print(f"  • 无法解析 opcode: {csv_first_byte}")
            opcode = None
    else:
        opcode = None

    if opcode is not None:
        # ---------- 1. 直接调用 (call rel32) ----------
        if opcode == 0xE8:
            if len(insn_bytes) >= 5:  # E8 + 4字节偏移 = 5字节指令
                # rel32是小端、有符号整数
                offset = int.from_bytes(insn_bytes[0:4], 'little', signed=True)
                # 目标地址 = 基址 + 指令起始偏移 + 指令长度 + 偏移量
                computed_target = base + event.src_offset + 4
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 直接调用 (call rel32) 偏移量: 0x{offset:08x}")
                print(f"  • 计算目标地址: 0x{computed_target:016x}")
                print(f"  • 与 CFI 预期对比: {comparison_result}")
            else:
                print(f"  • 指令字节不足（需要5字节，实际{len(insn_bytes)}字节），无法计算 call rel32 偏移")

        # ---------- 2. 直接跳转 (jmp rel32) ----------
        elif opcode == 0xE9:
            if len(insn_bytes) >= 5:  # E9 + 4字节偏移 = 5字节指令
                offset = int.from_bytes(insn_bytes[1:5], 'little', signed=True)
                computed_target = base + event.src_offset + 5 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 直接跳转 (jmp rel32) 偏移量: 0x{offset:08x}")
                print(f"  • 计算目标地址: 0x{computed_target:016x}")
                print(f"  • 与 CFI 预期对比: {comparison_result}")
            else:
                print(f"  • 指令字节不足（需要5字节，实际{len(insn_bytes)}字节），无法计算 jmp rel32 偏移")

        # ---------- 3. 短跳转 (jmp rel8) ----------
        elif opcode == 0xEB:
            if len(insn_bytes) >= 2:  # EB + 1字节偏移 = 2字节指令
                # 正确解析8位有符号偏移（适配原程序的insn_bytes格式）
                offset = int.from_bytes(insn_bytes[0:1], 'little', signed=True)
                computed_target = base + event.src_offset + 2 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 短跳转 (jmp rel8) 偏移量: 0x{offset:02x}")
                print(f"  • 计算目标地址: 0x{computed_target:016x}")
                print(f"  • 与 CFI 预期对比: {comparison_result}")
            else:
                print(f"  • 指令字节不足（需要2字节，实际{len(insn_bytes)}字节），无法计算 jmp rel8 偏移")

        # ---------- 4. 短条件跳转 (je, jne, etc. rel8) ----------
        elif 0x70 <= opcode <= 0x7F:
            if len(insn_bytes) >= 2:  # 0x70-0x7F + 1字节偏移 = 2字节指令
                # 正确解析8位有符号偏移
                offset = int.from_bytes(insn_bytes[0:1], 'little', signed=True)
                computed_target = base + event.src_offset + 1 + offset
                match = computed_target == event.expected_dst
                comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 短条件跳转 (0x{opcode:02x}) 偏移量: 0x{offset:02x}")
                print(f"  • 计算目标地址: 0x{computed_target:016x}")
                print(f"  • 与 CFI 预期对比: {comparison_result}")
            else:
                print(f"  • 指令字节不足（需要2字节，实际{len(insn_bytes)}字节），无法计算短条件跳转偏移")

        # ---------- 5. 长条件跳转 (0x0F 0x80-0x8F rel32) ----------
        elif opcode == 0x0F:
            if len(insn_bytes) >= 6:  # 0x0F + 0x80-0x8F + 4字节偏移 = 6字节指令
                second_byte = insn_bytes[1]
                if 0x80 <= second_byte <= 0x8F:
                    offset = int.from_bytes(insn_bytes[2:6], 'little', signed=True)
                    computed_target = base + event.src_offset + 6 + offset
                    match = computed_target == event.expected_dst
                    comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                    print(f"  • 长条件跳转 (0x0F {second_byte:02x}) 偏移量: 0x{offset:08x}")
                    print(f"  • 计算目标地址: 0x{computed_target:016x}")
                    print(f"  • 与 CFI 预期对比: {comparison_result}")
                else:
                    comparison_result = "✗ 非长条件跳转"
                    print(f"  • 操作码 0x0F 后不是条件跳转 (实际第二字节 0x{second_byte:02x}，预期0x80-0x8F)")
            else:
                comparison_result = "✗ 指令字节不足"
                print(f"  • 指令字节不足（需要6字节，实际{len(insn_bytes)}字节），无法计算长条件跳转偏移")

        # ---------- 6. 间接跳转/调用 (FF /2, /3, /4, /5) ----------
        elif opcode == 0xFF:
            # 适配原程序的间接跳转逻辑（基于RAX）
            if hasattr(event, 'reg_rax') and event.reg_rax != 0:
                computed_target = event.reg_rax
                if event.expected_dst != 0:
                    match = computed_target == event.expected_dst
                    comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                else:
                    # 保留原程序的模块范围判断逻辑（16MB）
                    module_end = base + 0x1000000
                    in_module = (computed_target >= base and computed_target < module_end)
                    comparison_result = "✓ 在模块内" if in_module else "✗ 超出模块范围"
                print(f"  • 间接跳转/调用目标 (RAX): 0x{computed_target:016x}")
                print(f"  • 与 CFI 预期对比: {comparison_result}")
            else:
                comparison_result = "✗ RAX值无效"
                rax_val = event.reg_rax if hasattr(event, 'reg_rax') else '未定义'
                print(f"  • 间接跳转/调用：RAX值无效（{rax_val}），无法计算目标地址")

        # ---------- 7. 返回指令 (ret, retf) ----------
        elif opcode in (0xC3, 0xC2, 0xCB, 0xCA):
            # 适配原程序的返回地址计算逻辑
            if hasattr(event, 'dst_offset') and event.dst_offset != 0:
                computed_target = base + event.dst_offset
                if event.expected_dst == 0:
                    module_end = base + 0x1000000
                    in_module = (computed_target >= base and computed_target < module_end)
                    comparison_result = "✓ 在模块内" if in_module else "✗ 超出模块范围"
                else:
                    match = computed_target == event.expected_dst
                    comparison_result = "✓ 一致" if match else f"✗ 不一致 (差值 0x{abs(computed_target - event.expected_dst):x})"
                print(f"  • 返回地址: 0x{computed_target:016x}")
                print(f"  • 与 CFI 预期对比: {comparison_result}")
            else:
                comparison_result = "✗ dst_offset无效"
                dst_offset_val = event.dst_offset if hasattr(event, 'dst_offset') else '未定义'
                print(f"  • 返回指令：dst_offset值无效（{dst_offset_val}），无法计算目标地址")

        # ---------- 8. 未知操作码 ----------
        else:
            comparison_result = "✗ 未知操作码"
            print(f"  • 未知指令类型 (0x{opcode:02x})，无法自动计算")
    else:
        comparison_result = "✗ 无效opcode"
        print(f"  • CSV第一个字节无效: {csv_first_byte}")

    print(f"  🎯 最终计算结果: {comparison_result}")



    # 寄存器状态
    print("\n📝 寄存器状态:")
    print(f"  • RAX: 0x{event.reg_rax:016x} (返回值/间接跳转目标)")
    print(f"  • RCX: 0x{event.reg_rcx:016x} (第4个参数)")
    print(f"  • RDX: 0x{event.reg_rdx:016x} (第3个参数)")
    print(f"  • RBX: 0x{event.reg_rbx:016x} (被调用者保存)")
    print(f"  • RSP: 0x{event.reg_rsp:016x} (栈指针)")
    print(f"  • RBP: 0x{event.reg_rbp:016x} (帧指针)")
    print(f"  • RSI: 0x{event.reg_rsi:016x} (第2个参数)")
    print(f"  • RDI: 0x{event.reg_rdi:016x} (第1个参数)")
    
    # 根据跳转类型进行专门分析
    print("\n🔍 跳转分析:")
    
    if event.jump_type in [0, 1, 2]:  # 直接跳转
        print(f"  • 直接跳转指令")
        print(f"  • CFI预期目标: 0x{event.expected_dst:016x}")
        
        # 检查RAX是否可能包含目标（有时间接跳转也会使用RAX）
        if event.reg_rax != 0:
            print(f"  • RAX中的值: 0x{event.reg_rax:016x}")
            if event.reg_rax == event.expected_dst:
                print(f"    └─ RAX中的值与预期目标一致")
        
    elif event.jump_type in [4, 5]:  # 间接跳转
        print(f"  • 间接跳转指令")
        print(f"  • RAX中的目标: 0x{event.reg_rax:016x}")
        print(f"  • CFI预期目标: 0x{event.expected_dst:016x}")
        
        if event.expected_dst != 0:
            if event.reg_rax == event.expected_dst:
                print(f"    └─ ✓ 目标匹配")
            else:
                diff = event.reg_rax - event.expected_dst
                print(f"    └─ ✗ 目标不匹配 (差值: 0x{diff:x})")
        else:
            # 检查目标是否在模块内
            in_module = (event.reg_rax >= base and event.reg_rax < base + 0x1000000)
            print(f"    └─ 目标是否在模块内: {'是' if in_module else '否'}")
    
    elif event.jump_type == 3:  # 返回指令
        print(f"  • 返回指令")
        print(f"  • 栈指针(RSP): 0x{event.reg_rsp:016x}")
        print(f"  • 模块范围: [0x{base:016x}, 0x{base + 0x1000000:016x}]")
    
    # 验证结果
    print("\n✅ 验证结果:")
    if event.is_correct:
        print(f"  ✓ 此跳转符合CFI规则")
    else:
        print(f"  ✗ 此跳转违反CFI规则")
        
        # 违规原因分析
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

def attach_probes(b, module_name="e1000"):
    """附加探测点到模块函数"""
    try:
        print(f"查找 {module_name} 模块的函数...")
        b.attach_kprobe(event=f"e1000_clean_tx_irq", fn_name="trace_all_jumps")

        try:
            with open('/proc/kallsyms', 'r') as f:
                lines = f.readlines()
            
            func_count = 0
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 3 and module_name in parts[2]:
                    func_name = parts[2]
                    if '.cold' in func_name:
                        continue

                    if any(skip in func_name for skip in ['.isra', '.constprop', '.part']):
                        continue
                    try:
                        if func_name.startswith(f"{module_name}_"):
                            print(func_name)
                            #b.attach_kprobe(event=func_name, fn_name="trace_all_jumps")
                            
                            func_count += 1
                            if func_count <= 5:
                                print(f"  附加到: {func_name}")
                    except Exception:
                        continue
            
            if func_count > 0:
                print(f"成功附加到 {func_count} 个函数")
                return True
        except Exception as e:
            print(f"通过kallsyms附加失败: {e}")     
    except Exception as e:
        print(f"附加探测点失败: {e}")
        return False

def main():
    global b, event_count, violation_count, base, cfi_lookup
    
    # 首先解析CFI表
    cfi_file = "data/csv/e1000_jump_analysis.csv"
    print("解析CFI表...")
    table = parse_cfi_table(cfi_file)
    
    if len(table) == 0:
        print("错误: 未能解析任何CFI条目!")
        return
    
    # 统计跳转类型
    jump_types = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for entry in table:
        if entry['jump_type'] in jump_types:
            jump_types[entry['jump_type']] += 1
    
    print("\n跳转类型统计:")
    type_names = {0: "JMP", 1: "JCC", 2: "CALL", 3: "RET", 4: "INDIRECT_CALL", 5: "INDIRECT_JMP"}
    for jump_type, count in jump_types.items():
        if count > 0:
            print(f"  {type_names.get(jump_type, f'UNKNOWN({jump_type})')}: {count}")
    
    # 构建查找表
    for entry in table:
        cfi_lookup[entry['src_addr']] = entry
    
    # 然后加载BPF程序
    print("\n加载BPF程序...")
    try:
        # 重定向stderr到/dev/null来抑制编译警告
        with open(os.devnull, 'w') as devnull:
            old_stderr = os.dup(2)
            os.dup2(devnull.fileno(), 2)
            try:
                b = BPF(text=get_bpf_text())
            finally:
                os.dup2(old_stderr, 2)
                os.close(old_stderr)
        print("BPF程序加载成功")
    except Exception as e:
        print(f"BPF加载失败: {e}")
        return
    
    module_name = "e1000"
    base = get_module_base(module_name)
    if base is None:
        print(f"警告: 无法获取 {module_name} 模块基址，使用默认值 0xffffffffc0000000")
        base = 0xffffffffc0000000
    else:
        print(f"检测到 {module_name} 基址: 0x{base:x}")
    
    # 存储模块基址
    b['module_base'][ctypes.c_uint64(0)] = ctypes.c_uint64(base)
    print(f"设置的模块基址: 0x{base:x}")
    
    # 加载CFI规则
    print("\n加载CFI规则...")
    loaded_count = 0
    
    for entry_dict in table:
        offset = ctypes.c_uint64(entry_dict['src_addr'])
        cfi_entry = CfiEntry(
            src_addr=entry_dict['src_addr'],
            src_func_addr=entry_dict['src_func_addr'],
            dst_addr=entry_dict['dst_addr'],
            jump_type=entry_dict['jump_type'],
            is_indirect=entry_dict['is_indirect'],
            src_func=entry_dict['src_func'],
            dst_func=entry_dict['dst_func'],
            opcode=entry_dict.get('opcode', 0)   # 新增
        )
        b['cfi_map'][offset] = cfi_entry
        loaded_count += 1
    
    print(f"已加载 {loaded_count} 个CFI规则")
    
    # 设置perf buffer
    b["jump_events"].open_perf_buffer(handle_jump_event)
    
    # 附加探测点
    print("\n附加探测点...")
    if not attach_probes(b, module_name):
        print("警告: 探测点附加可能不完整，但仍可继续运行")
    
    print("\n=== CFI监控已启动 ===")
    print("正在监控跳转指令并输出完整的CFI信息...")
    print("按 Ctrl+C 停止\n")
    print("请在另一个终端运行: sudo python3 network_trigger.py 来触发网络事件")
    
    try:
        last_stat_time = time.time()
        last_event_count = 0
        
        print("开始事件循环...")
        
        while True:
            try:
                b.perf_buffer_poll(timeout=100)
                
                current_time = time.time()
                if current_time - last_stat_time > 5.0:
                    debug_stats_data = {}
                    try:
                        for key, value in b["debug_stats"].items():
                            if hasattr(key, 'value'):
                                k = key.value
                            else:
                                k = key
                                
                            if hasattr(value, 'value'):
                                v = value.value
                            else:
                                v = value
                            
                            debug_stats_data[k] = v
                    except Exception as e:
                        print(f"获取调试统计失败: {e}")
                    
                    if debug_stats_data:
                        print_debug_stats(debug_stats_data)
                        new_events = event_count - last_event_count
                        print(f"\n统计: 总事件数={event_count}, 新增事件={new_events}, 违规数={violation_count}")
                        last_event_count = event_count
                        print("-" * 40)
                    
                    last_stat_time = current_time
                
            except KeyboardInterrupt:
                print("\n正在停止监控...")
                break
            except Exception as e:
                if "Interrupted system call" not in str(e):
                    print(f"事件循环错误: {e}")
                continue
    
    except KeyboardInterrupt:
        print("\n监控已停止")
    
    finally:
        print("\n=== 最终统计 ===")
        
        debug_stats_data = {}
        try:
            for key, value in b["debug_stats"].items():
                if hasattr(key, 'value'):
                    k = key.value
                else:
                    k = key
                    
                if hasattr(value, 'value'):
                    v = value.value
                else:
                    v = value
                
                debug_stats_data[k] = v
        except Exception as e:
            print(f"获取最终调试统计失败: {e}")
        
        print_debug_stats(debug_stats_data)
        
        print(f"\n监控总结:")
        print(f"- CFI规则数: {len(table)}")
        print(f"- 加载规则数: {loaded_count}")
        print(f"- 处理事件数: {event_count}")
        print(f"- CFI违规数: {violation_count}")
        
        if event_count > 0:
            violation_rate = (violation_count / event_count) * 100
            print(f"- 违规率: {violation_rate:.2f}%")
        else:
            print("- 违规率: 0% (无事件)")

if __name__ == "__main__":
    main()