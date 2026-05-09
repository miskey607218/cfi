#!/usr/bin/env python3
"""
RIPE Tester for test.so - 自动化攻击矩阵测试
类似 RIPE 的 ripe_tester.py, 但针对 test.so 的特定位置
"""
import os
import sys
import subprocess

# 攻击参数 (与 RIPE 保持一致)
code_ptrs = ["ret", "baseptr", "funcptrstackvar", "funcptrheap", "funcptrdata"]
funcs = ["memcpy", "strcpy", "strncpy", "sprintf", "snprintf",
         "strcat", "strncat", "sscanf", "fscanf", "homebrew"]
locations = ["stack", "heap", "bss", "data"]
attacks = ["simplenop", "nonop", "polynop", "createfile", "returnintolibc", "rop"]

# 从 test.txt 提取的目标位置 (间接调用/跳转指令的偏移)
target_sites = [
    {"offset": "0x11d4", "name": "test_indirect_call", "inst": "ff d0"},
    {"offset": "0x121b", "name": "test_indirect_jump", "inst": "ff d0"},
    {"offset": "0x124a", "name": "test_ff_instructions_1", "inst": "ff d0"},
    {"offset": "0x1260", "name": "test_ff_instructions_2", "inst": "ff d0"},
    {"offset": "0x10ff", "name": "deregister_tm_clones", "inst": "ff e0"},
    {"offset": "0x1140", "name": "register_tm_clones", "inst": "ff e0"},
]

techniques = []
repeat_times = 0

if len(sys.argv) < 2:
    print(f"Usage: python3 {{}} [direct|indirect|both] <repeat>".format(sys.argv[0]))
    sys.exit(1)

if sys.argv[1] == "both":
    techniques = ["direct", "indirect"]
else:
    techniques = [sys.argv[1]]

repeat_times = int(sys.argv[2]) if len(sys.argv) > 2 else 1

if not os.path.exists("/tmp/rip-eval"):
    os.makedirs("/tmp/rip-eval", exist_ok=True)

total_ok = 0
total_fail = 0
total_some = 0
total_np = 0

for target in target_sites:
    for attack in attacks:
        for loc in locations:
            for ptr in code_ptrs:
                for func in funcs:
                    print(f"[*] Target={{target['name']}}({{target['offset']}}) "
                          f"attack={{attack}} loc={{loc}} ptr={{ptr}} func={{func}}")

print("\\n[*] Attack matrix generated. Implement attack C binary to execute tests.")
print("[*] See ripe_attack_full.c for full implementation.")
