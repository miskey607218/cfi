from bcc import BPF
import ctypes
import re
import os
import sys
import subprocess
import threading
import time
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # 新增：Capstone 反汇编库
import csv   # ← 新增这一行

if os.geteuid() != 0:
    print("Run with sudo!")
    sys.exit(1)

def get_module_base(module_name):
    """获取内核模块的加载基址"""
    # 方法1：从 /proc/modules 精确匹配模块名
    try:
        with open('/proc/modules', 'r') as f:
            for line in f:
                if line.startswith(module_name + ' '):   # 精确匹配
                    parts = line.split()
                    if len(parts) >= 6:
                        return int(parts[-1], 16)
    except Exception:
        pass

    # 方法2：从 /proc/kallsyms 查找第一个模块函数符号
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2].startswith(module_name + '_'):
                    # 返回第一个 e1000_ 符号的地址
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
        ("insn_bytes", ctypes.c_uint8 * 16),  # 新增：指令字节数组，用于反汇编
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
                # 地址可能带高位内核前缀（如 0xffffffff00000000...），统一转为相对偏移
                def to_offset(s):
                    if not s or s == "UNKNOWN":
                        return 0
                    val = int(s, 16)
                    if val >= 0xffffffff00000000:   # 高位内核地址
                        val &= 0xffffffff
                    return val

                src_addr       = to_offset(row['jump_instr_address'])+1
                src_func_addr  = to_offset(row['parent_function_start'])
                dst_addr       = to_offset(row['target_address'])

                # 中文类型 → 数字类型（与 BPF switch 一致）
                jtype_str = row.get('jump_type', '')
                jump_type_map = {
                    '无条件跳转': 0,   # JMP
                    '条件跳转':   1,   # JCC
                    '函数调用':   2,   # CALL
                    '函数返回':   3,   # RET
                }
                jump_type = jump_type_map.get(jtype_str, 0)

                is_indirect = 0   # CSV 里全是静态直接跳转

                src_func = row.get('parent_function_name', 'unknown').encode('utf-8')[:63]
                dst_func = row.get('target_function_name', 'unknown').encode('utf-8')[:63]

                entry = {
                    'src_addr': src_addr,
                    'src_func_addr': src_func_addr,
                    'dst_addr': dst_addr,
                    'jump_type': jump_type,
                    'is_indirect': is_indirect,
                    'src_func': src_func,
                    'dst_func': dst_func,
                }
                table.append(entry)
            except Exception:
                continue   # 跳过格式错误的行

    print(f"✅ 从 CSV 成功解析 {len(table)} 个静态跳转规则")
    return table

# 修改BPF代码：添加读取指令字节
bpf_text = """
#include <uapi/linux/ptrace.h>

struct cfi_entry {
    u64 src_addr;
    u64 src_func_addr;
    u64 dst_addr;
    u8 jump_type;
    u8 is_indirect;
    char src_func[64];
    char dst_func[64];
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
    u8 insn_bytes[16];  // 新增：读取 16 字节指令
};

BPF_HASH(cfi_map, u64, struct cfi_entry);
BPF_HASH(module_base, u64, u64);
BPF_PERF_OUTPUT(jump_events);
BPF_HASH(debug_stats, u64, u64);

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
   
    // 调试：记录所有进入的偏移量
    u64 *count = debug_stats.lookup(&offset);
    if (!count) {
        u64 one = 1;
        debug_stats.update(&offset, &one);
    } else {
        *count += 1;
        debug_stats.update(&offset, count);
    }
   
    // 查找CFI规则
    struct cfi_entry *entry = cfi_map.lookup(&offset);
    if (!entry) {
        return 0;
    }
   
    struct jump_event event = {};
    u64 expected_target = 0;
    u64 actual_target = 0;
    int is_correct = 0;
   
    // 填充完整的CFI信息
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
   
    // 新增：读取当前指令字节（从 ip 开始读 16 字节）
    bpf_probe_read(&event.insn_bytes, sizeof(event.insn_bytes), (void *)ip);



    // 输出 hex (简化，只输出前 8 字节)
    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[0], event.insn_bytes[1]);

    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[2], event.insn_bytes[3]);

    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[4], event.insn_bytes[5]);

    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[6], event.insn_bytes[7]);

    // 计算预期目标地址
    if (entry->dst_addr != 0) {
        expected_target = entry->dst_addr + base;
    }
    event.expected_dst = expected_target;
   
    // 根据跳转类型处理
    switch (entry->jump_type) {
        case 0: // CFI_JMP
        case 1: // CFI_JCC
        case 2: // CFI_CALL
            is_correct = 1;
            break;
           
        case 3: // CFI_RET
            is_correct = 1;
            break;
           
        case 4: // CFI_INDIRECT_CALL
        case 5: // CFI_INDIRECT_JMP
            actual_target = ctx->ax;  // 假设在 ax，根据你的 dump 调整
           
            if (actual_target >= base) {
                event.dst_offset = actual_target - base;
            }
           
            if (expected_target == 0) {
                is_correct = 1;
            } else if (actual_target == expected_target) {
                is_correct = 1;
            } else {
                is_correct = 0;
            }
            break;
           
        default:
            is_correct = 0;
            break;
    }
   
    event.is_correct = is_correct;
   
    // 提交事件
    jump_events.perf_submit(ctx, &event, sizeof(event));
   
    return 0;
}
"""

# ... 其他函数如 parse_cfi_table, print_debug_stats, trigger_network_events 等保持不变 ...
def print_debug_stats(debug_map):
    """打印调试统计信息"""
    if not debug_map:
        print("无调试统计信息")
        return
    
    print("\n=== 调试统计 ===")
    print(f"{'偏移量':<12} {'次数':<8}")
    print("-" * 25)
    
    # 处理BPF map返回的数据
    stats = []
    for key, value in debug_map.items():
        # 处理键和值的类型
        if hasattr(key, 'value'):
            offset = key.value
        else:
            offset = key
            
        if hasattr(value, 'value'):
            count = value.value
        else:
            count = value
            
        stats.append((offset, count))
    
    # 按次数排序
    stats.sort(key=lambda x: x[1], reverse=True)
    
    for offset, count in stats[:20]:
        # 修复格式化字符串：将格式说明符分开
        hex_offset = f"0x{offset:x}"
        print(f"{hex_offset:<12} {count:<8}")

# 全局变量用于统计
event_count = 0
violation_count = 0

def handle_jump_event(cpu, data, size):
    """处理跳转事件，输出完整的CFI信息，并反汇编指令"""
    global event_count, violation_count
   
    try:
        event = b["jump_events"].event(data)
       
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
       
        # 解码字符串
        try:
            src_func_str = event.src_func.decode('utf-8', errors='ignore').strip()
        except:
            src_func_str = str(event.src_func)
           
        try:
            dst_func_str = event.dst_func.decode('utf-8', errors='ignore').strip()
        except:
            dst_func_str = str(event.dst_func)
       
        # 打印详细的CFI信息
        #print("\n" + "="*80)
        #print(f"CFI 事件 #{event_count + 1}")
        #print("="*80)
       
        #print(f"状态: {status}")
        #print(f"跳转类型: {jump_type_name} ({event.jump_type})")
        #print(f"是否为间接跳转: {'是' if event.is_indirect else '否'}")
        #print(f"时间戳: {event.timestamp_ns} ns")
        #print(f"CPU: {event.cpu}, PID: {event.pid}")
        #print("-" * 40)
       
        print("CFI 条目信息:")
        print(f" src_addr: 0x{event.src_addr:x} (CFI表中的源地址)")
        print(f" src_offset: 0x{event.src_offset:x} (运行时源偏移)")
        print(f" src_func_addr: 0x{event.src_func_addr:x} (源函数地址)")
        print(f" src_func: {src_func_str}")
        print(f" dst_func: {dst_func_str}")
        print(f" cfi_dst_addr: 0x{event.cfi_dst_addr:x} (CFI表中的目标地址)")
       
        print("\n寄存器状态:")
        print(f" RAX: 0x{event.reg_rax:x}")
        #print(f" RCX: 0x{event.reg_rcx:x}")
        #print(f" RDX: 0x{event.reg_rdx:x}")
        #print(f" RBX: 0x{event.reg_rbx:x}")
        #print(f" RSP: 0x{event.reg_rsp:x}")
        #print(f" RBP: 0x{event.reg_rbp:x}")
        #print(f" RSI: 0x{event.reg_rsi:x}")
        #print(f" RDI: 0x{event.reg_rdi:x}")
       
        if event.jump_type in [4, 5]:  # 间接跳转/调用
            print(f" 预期目标: 0x{event.expected_dst:x}")
            print(f" 实际目标偏移: 0x{event.dst_offset:x}")
            print(f" 实际目标地址: 0x{event.expected_dst - base + event.dst_offset:x if event.expected_dst != 0 else '未知'}")
           
            # 检查是否匹配
            if event.expected_dst != 0:
                actual_target = event.expected_dst - base + event.dst_offset if event.dst_offset != 0 else 0
                if actual_target != 0 and actual_target != event.expected_dst:
                    print(f" 目标不匹配! 预期: 0x{event.expected_dst:x}, 实际: 0x{actual_target:x}")
       
        elif event.jump_type == 3:  # RET
            print(f" 返回指令 - 目标通过栈确定")
        else:  # 直接跳转
            print(f" 直接跳转 - 目标编码在指令中")
            print(f" 预期目标: 0x{event.expected_dst:x}")
       
        print("-" * 40)
       
        # 新增: 反汇编指令字节
        print("触发时的指令反汇编:")
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True  # 启用详细模式
            
            insn_bytes = bytes(event.insn_bytes)
            print(f"原始字节: {insn_bytes.hex()}")
            for i in md.disasm(insn_bytes, 0):
                print(f"0x{i.address:x}: {i.mnemonic} {i.op_str}")
                
        except Exception as e:
            print(f"反汇编失败: {e}")
            print(f"原始字节: {insn_bytes.hex()}")
       
        print("-" * 40)
       
        # 计算并显示与基址的偏移
        if event.src_offset != event.src_addr:
            print(f"注意: src_offset(0x{event.src_offset:x}) 与 src_addr(0x{event.src_addr:x}) 不同")
            print(f" diff = 0x{event.src_offset - event.src_addr:x}")
       
        event_count += 1
       
    except Exception as e:
        print(f"处理事件时出错: {e}")
        import traceback
        traceback.print_exc()

# ... 其他函数如 attach_probes, trigger_network_events, main 等保持不变 ...

def attach_probes(b, module_name="e1000"):
    """附加BPF探测点到内核模块函数"""
    try:
        print(f"查找 {module_name} 模块的函数...")
        
        # 获取函数列表
        try:
            with open('/proc/kallsyms', 'r') as f:
                lines = f.readlines()
            
            func_count = 0
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 3 and module_name in parts[2]:
                    func_name = parts[2]
                    
                    try:
                        if func_name.startswith(f"{module_name}_"):
                            print(func_name)
                            b.attach_kprobe(event=func_name, fn_name="trace_all_jumps")
                            
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
        
        # 如果失败，尝试常见函数
    
        

        
        
    except Exception as e:
        print(f"附加探测点失败: {e}")
        return False

def trigger_network_events():
    """触发网络事件以产生跳转"""
    print("触发网络事件...")
    
    # 查找活跃的网络接口
    interfaces = []
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'state UP' in line or 'state DOWN' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    iface = parts[1].strip()
                    if iface and iface != 'lo':
                        interfaces.append(iface)
    except:
        interfaces = ["ens33", "eth0", "enp0s3"]
    
    for iface in interfaces:
        try:
            print(f"操作接口: {iface}")
            
            # 检查接口是否存在
            result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
            if result.returncode != 0:
                continue
            
            # 关闭接口
            print(f"  关闭 {iface}")
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
            time.sleep(0.3)
            
            # 开启接口
            print(f"  开启 {iface}")
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
            time.sleep(0.5)
            
            # 发送ping测试
            print(f"  发送测试数据包")
            subprocess.Popen(["ping", "-c", "2", "8.8.8.8"], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
            
            time.sleep(1)
            break
            
        except Exception as e:
            print(f"  操作接口 {iface} 失败: {e}")
            continue

def main():
    global b, event_count, violation_count, base
    
    cfi_file = "e1000_jump_analysis.csv"
    
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
    
    # 加载BPF程序
    print("\n加载BPF程序...")
    try:
        b = BPF(text=bpf_text)
        print("BPF程序加载成功")
    except Exception as e:
        print(f"BPF加载失败: {e}")
        return
    

    module_name = "e1000"
    base = get_module_base(module_name)
    if base is None:
        print(f"警告: 无法获取 {module_name} 模块基址，使用默认值 0xffffffffc0000000")
        base = 0xffffffffc0348000
    else:
        print(f"检测到 {module_name} 基址: 0x{base:x}")

    base=0xffffffffc0348000

    # 存储模块基址
    b['module_base'][ctypes.c_uint64(0)] = ctypes.c_uint64(base)
    print(f"设置的模块基址: 0x{base:x}")
    
    # 加载CFI规则
    print("\n加载CFI规则...")
    loaded_count = 0
    cfi_dict = {}  # 用于快速查找CFI条目
    
    for entry_dict in table:
        offset = ctypes.c_uint64(entry_dict['src_addr'])
        cfi_entry = CfiEntry(
            src_addr=entry_dict['src_addr'],
            src_func_addr=entry_dict['src_func_addr'],
            dst_addr=entry_dict['dst_addr'],
            jump_type=entry_dict['jump_type'],
            is_indirect=entry_dict['is_indirect'],
            src_func=entry_dict['src_func'],
            dst_func=entry_dict['dst_func']
        )
        b['cfi_map'][offset] = cfi_entry
        cfi_dict[entry_dict['src_addr']] = entry_dict  # 存储到字典中
        loaded_count += 1
    
    print(f"已加载 {loaded_count} 个CFI规则")
    
    # 附加到特定偏移
    # 查找CFI表中所有可能的偏移并附加
    for src_addr in cfi_dict.keys():
        try:
            # 计算实际地址
            actual_addr = base + src_addr
            # 尝试查找对应的符号
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        try:
                            sym_addr = int(parts[0], 16)
                            if sym_addr == actual_addr:
                                func_name = parts[2]
                                b.attach_kprobe(event=func_name, fn_name="trace_all_jumps")
                                print(f"附加到函数: {func_name} (地址: 0x{actual_addr:x})")
                                break
                        except:
                            continue
        except:
            # 如果找不到符号，直接附加到地址
            try:
                b.attach_kprobe(event=f"0x{actual_addr:x}", fn_name="trace_all_jumps")
                print(f"附加到地址: 0x{actual_addr:x}")
            except:
                pass
    
    # 设置perf buffer
    b["jump_events"].open_perf_buffer(handle_jump_event)
    
    # 附加探测点
    print("\n附加探测点...")
    if not attach_probes(b, module_name):
        print("警告: 探测点附加可能不完整，但仍可继续运行")
    
    print("\n=== CFI监控已启动 ===")
    print("正在监控跳转指令并输出完整的CFI信息...")
    print("按 Ctrl+C 停止\n")
    
    # 启动触发事件的线程
    def trigger_thread_func():
        time.sleep(2)
        trigger_network_events()
    
    trigger_thread = threading.Thread(target=trigger_thread_func)
    trigger_thread.daemon = True
    trigger_thread.start()
    
    try:
        last_stat_time = time.time()
        last_event_count = 0
        
        print("开始事件循环...")
        
        while True:
            try:
                # 处理perf事件
                b.perf_buffer_poll(timeout=100)
                
                # 定期打印统计信息
                current_time = time.time()
                if current_time - last_stat_time > 5.0:
                    # 获取调试统计
                    debug_stats_data = {}
                    try:
                        for key, value in b["debug_stats"].items():
                            # 正确处理键和值的类型
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
        # 最终统计
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