#!/usr/bin/env python3
# monitor_insn.py - 挂载到内核函数并输出指令字节
from bcc import BPF
import ctypes
import sys

# BPF 程序：读取指令指针处的 16 字节并提交事件
bpf_text = """
#include <uapi/linux/ptrace.h>

struct event {
    u64 ip;
    u8 bytes[128];
};

BPF_PERF_OUTPUT(events);

int trace_insn(struct pt_regs *ctx) {
    struct event e = {};
    e.ip = PT_REGS_IP(ctx);
    bpf_probe_read(e.bytes, sizeof(e.bytes), (void *)e.ip);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

# 定义事件结构（与 BPF 中一致）
class Event(ctypes.Structure):
    _fields_ = [
        ("ip", ctypes.c_uint64),
        ("bytes", ctypes.c_uint8 * 128),
    ]

def print_event(cpu, data, size):
    """用户空间回调，打印事件内容"""
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    hex_bytes = ' '.join(f"{b:02x}" for b in event.bytes)
    print(f"IP=0x{event.ip:016x}  bytes={hex_bytes}")

# 加载 BPF 程序
b = BPF(text=bpf_text)

# 挂载 kprobe 到指定函数
b.attach_kprobe(event=f"e1000_update_itr+0x13", fn_name="trace_insn")
print("按 Ctrl+C 停止监控...")

# 打开 perf buffer 并设置回调
b["events"].open_perf_buffer(print_event)

# 事件循环
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n监控已停止")