#!/usr/bin/env python3
"""
network_trigger.py - 独立的网络事件触发模块
用于触发e1000驱动的网络活动，产生跳转指令供CFI监控
"""

import subprocess
import time
import os
import sys

def get_active_interfaces():
    """获取所有活跃的网络接口"""
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
    except Exception as e:
        print(f"获取网络接口失败: {e}")
        # 备选接口列表
        interfaces = ["ens33", "eth0", "enp0s3"]
    
    return interfaces

def trigger_interface_reset(iface):
    """重置指定网络接口（关闭再开启）"""
    try:
        print(f"  操作接口: {iface}")
        
        # 检查接口是否存在
        result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  接口 {iface} 不存在")
            return False
        
        # 关闭接口
        print(f"  关闭 {iface}")
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
        time.sleep(0.3)
        
        # 开启接口
        print(f"  开启 {iface}")
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
        time.sleep(0.5)
        
        return True
        
    except Exception as e:
        print(f"  操作接口 {iface} 失败: {e}")
        return False

def send_test_packets(target="8.8.8.8", count=2):
    """发送测试数据包"""
    try:
        print(f"  发送测试数据包到 {target}")
        subprocess.Popen(["ping", "-c", str(count), target], 
                       stdout=subprocess.DEVNULL, 
                       stderr=subprocess.DEVNULL)
        time.sleep(1)
        return True
    except Exception as e:
        print(f"  发送数据包失败: {e}")
        return False

def trigger_network_events(iface=None):
    """
    触发网络事件以产生跳转
    
    参数:
        iface: 指定要操作的接口，None表示自动选择第一个活跃接口
    
    返回:
        bool: 是否成功触发事件
    """
    print("触发网络事件...")
    
    # 获取接口列表
    if iface:
        interfaces = [iface]
    else:
        interfaces = get_active_interfaces()
    
    if not interfaces:
        print("  未找到可用的网络接口")
        return False
    
    # 尝试操作每个接口，直到成功
    for iface in interfaces:
        print(f"尝试操作接口: {iface}")
        
        if trigger_interface_reset(iface):
            send_test_packets()
            print(f"  成功触发 {iface} 的网络事件")
            return True
    
    print("  所有接口操作失败")
    return False

def trigger_all_events():
    """触发所有类型的网络事件"""
    print("触发所有网络事件...")
    
    interfaces = get_active_interfaces()
    if not interfaces:
        print("未找到可用接口")
        return
    
    for iface in interfaces[:2]:  # 最多操作前2个接口
        print(f"\n处理接口: {iface}")
        trigger_interface_reset(iface)
        send_test_packets()
        time.sleep(2)
    
    print("\n所有网络事件触发完成")

def monitor_mode(duration=30):
    """
    监控模式：持续触发网络事件
    
    参数:
        duration: 监控持续时间（秒）
    """
    import threading
    import signal
    import sys
    
    stop_event = threading.Event()
    
    def signal_handler(sig, frame):
        print("\n收到停止信号，停止监控...")
        stop_event.set()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"启动网络事件监控模式，将持续 {duration} 秒")
    print("按 Ctrl+C 提前停止")
    
    start_time = time.time()
    event_count = 0
    
    while not stop_event.is_set() and (time.time() - start_time) < duration:
        print(f"\n[事件 #{event_count + 1}] 触发网络事件...")
        
        interfaces = get_active_interfaces()
        if interfaces:
            iface = interfaces[0]
            trigger_interface_reset(iface)
            send_test_packets()
            event_count += 1
        
        # 等待一段时间再触发下一次
        for i in range(5):
            if stop_event.is_set():
                break
            time.sleep(1)
    
    print(f"\n监控结束，共触发 {event_count} 次网络事件")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="网络事件触发模块")
    parser.add_argument("-i", "--interface", help="指定要操作的网络接口")
    parser.add_argument("-c", "--count", type=int, default=2, help="ping数据包数量")
    parser.add_argument("-t", "--target", default="8.8.8.8", help="ping目标地址")
    parser.add_argument("-m", "--monitor", type=int, metavar="SECONDS", 
                       help="监控模式：持续触发网络事件指定秒数")
    parser.add_argument("--all", action="store_true", help="触发所有类型的网络事件")
    
    args = parser.parse_args()
    
    # 检查root权限
    if os.geteuid() != 0:
        print("需要root权限运行!")
        print("请使用: sudo python3 network_trigger.py [选项]")
        sys.exit(1)
    
    if args.monitor:
        monitor_mode(args.monitor)
    elif args.all:
        trigger_all_events()
    else:
        # 单次触发模式
        if trigger_network_events(args.interface):
            print("网络事件触发成功")
        else:
            print("网络事件触发失败")
            sys.exit(1)