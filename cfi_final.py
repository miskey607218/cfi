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

                jump_instr = row.get('jump_instr', '').strip()
                if jump_instr == 'callq':
                    jump_type = 2
                elif jump_instr == 'jmp':
                    jump_type = 0
                else:
                    jump_type = 1

                is_indirect = 0

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
                continue

    print(f"✅ 从 CSV 成功解析 {len(table)} 个静态跳转规则")
    return table

# 将BPF代码定义为一个函数，这样可以在需要时才编译
def get_bpf_text():
    """返回BPF程序代码"""
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
    u64 actual_target = 0;
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
   
    bpf_probe_read(&event.insn_bytes, sizeof(event.insn_bytes), (void *)ip);

    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[0], event.insn_bytes[1]);

    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[2], event.insn_bytes[3]);

    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[4], event.insn_bytes[5]);

    bpf_trace_printk("Insn bytes: %x %x\\n",
    event.insn_bytes[6], event.insn_bytes[7]);

    if (entry->dst_addr != 0) {
        expected_target = entry->dst_addr + base;
    }
    event.expected_dst = expected_target;
   
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
            actual_target = ctx->ax;
           
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

def handle_jump_event(cpu, data, size):
    """处理跳转事件"""
    global event_count, violation_count
   
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
    print(jump_type_name)   
    
    if not event.is_correct:
        violation_count += 1
       
    try:
        src_func_str = event.src_func.decode('utf-8', errors='ignore').strip()
    except:
        src_func_str = str(event.src_func)
           
    try:
        dst_func_str = event.dst_func.decode('utf-8', errors='ignore').strip()
    except:
        dst_func_str = str(event.dst_func)
       
    print("CFI 条目信息:")
    print(f" src_addr: 0x{event.src_addr:x} (CFI表中的源地址)")
    print(f" src_offset: 0x{event.src_offset:x} (运行时源偏移)")
    print(f" src_func_addr: 0x{event.src_func_addr:x} (源函数地址)")
    print(f" src_func: {src_func_str}")
    print(f" dst_func: {dst_func_str}")
    print(f" cfi_dst_addr: 0x{event.cfi_dst_addr:x} (CFI表中的目标地址)")
       
    print("\n寄存器状态:")
    print(f" RAX: 0x{event.reg_rax:x}")
    
    event_count += 1

def attach_probes(b, module_name="e1000"):
    """附加探测点到模块函数"""
    try:
        print(f"查找 {module_name} 模块的函数...")
        
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
    except Exception as e:
        print(f"附加探测点失败: {e}")
        return False

def trigger_network_events():
    """触发网络事件以产生跳转"""
    print("触发网络事件...")
    
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
            
            result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
            if result.returncode != 0:
                continue
            
            print(f"  关闭 {iface}")
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
            time.sleep(0.3)
            
            print(f"  开启 {iface}")
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
            time.sleep(0.5)
            
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
    cfi_dict = {}
    
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
        cfi_dict[entry_dict['src_addr']] = entry_dict
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