import re
import csv

# ===================== 配置项 =====================
DISASM_FILE = "libvuln_disassembly.txt"  # 你的反汇编文件路径
OUTPUT_CSV = "libvuln_jump_analysis.csv"  # 输出的CSV文件路径

# 跳转指令类型映射（基本分类）
JUMP_TYPE_MAP = {
    # 无条件跳转
    'jmp': '无条件跳转',
    'ljmp': '无条件跳转',
    # 条件跳转
    'je': '条件跳转', 'jne': '条件跳转', 'jz': '条件跳转', 'jnz': '条件跳转',
    'jb': '条件跳转', 'ja': '条件跳转', 'jl': '条件跳转', 'jg': '条件跳转',
    'jbe': '条件跳转', 'jae': '条件跳转', 'jle': '条件跳转', 'jge': '条件跳转',
    'jc': '条件跳转', 'jnc': '条件跳转', 'js': '条件跳转', 'jns': '条件跳转',
    'jo': '条件跳转', 'jno': '条件跳转',
    # 函数调用/返回
    'call': '函数调用', 'callq': '函数调用',
    'ret': '函数返回', 'retq': '函数返回',
    'lret': '函数返回', 'retf': '函数返回',   # 远返回
    # 特殊跳转
    'syscall': '特殊跳转', 'int': '特殊跳转', 'iretq': '特殊跳转'
}


# ===================== 核心解析逻辑 =====================
def parse_functions(disasm_lines):
    """解析所有函数：返回 {函数起始地址: 函数名} 的映射"""
    function_map = {}
    func_pattern = re.compile(r'^([0-9a-fA-F]+) <([^>]+)>:$')

    for line in disasm_lines:
        line_strip = line.strip()
        match = func_pattern.match(line_strip)
        if match:
            func_addr = match.group(1)
            func_name = match.group(2)
            function_map[func_addr] = func_name
    return function_map


def get_parent_function(addr, function_map):
    """根据指令地址，找到所属的函数名和函数起始地址"""
    if not addr or not re.match(r'^[0-9a-fA-F]+$', addr):
        return "UNKNOWN", "UNKNOWN"

    instr_addr_int = int(addr, 16)

    func_addr_list = []
    for fa_str in function_map.keys():
        try:
            fa_int = int(fa_str, 16)
            func_addr_list.append((fa_int, fa_str))
        except ValueError:
            continue

    if not func_addr_list:
        return "UNKNOWN", "UNKNOWN"

    func_addr_list.sort(reverse=True, key=lambda x: x[0])

    for fa_int, fa_str in func_addr_list:
        if fa_int <= instr_addr_int:
            return function_map[fa_str], fa_str

    return "UNKNOWN", "UNKNOWN"


def clean_hex_address(hex_str):
    """清理十六进制地址的前导0，返回如0x9e1的格式"""
    if hex_str == "UNKNOWN":
        return "UNKNOWN"
    try:
        addr_int = int(hex_str, 16)
        return f"0x{addr_int:x}"
    except ValueError:
        return "UNKNOWN"


def parse_jump_instructions(disasm_lines, function_map):
    """解析所有跳转指令，返回结构化数据列表（支持直接/间接调用，含FF指令）"""
    jump_data = []

    # 返回指令正则（无目标地址）
    ret_pattern = re.compile(
        r'^([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s*)+?)\s+(ret|retq|retf|lret)\s*$'
    )

    # 普通跳转/调用正则（捕获完整操作数）
    jump_pattern = re.compile(
        r'^([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s*)+?)\s+(' +
        '|'.join(JUMP_TYPE_MAP.keys()) +
        r')\s+(.*)$'
    )

    for line in disasm_lines:
        line_strip = line.strip()
        if not line_strip:
            continue

        # ----- 返回指令 -----
        ret_match = ret_pattern.match(line_strip)
        if ret_match:
            instr_addr = ret_match.group(1)
            instr_bytes_str = ret_match.group(2).strip()
            jump_instr = ret_match.group(3)
            target_addr = None
            target_func_name = None
            is_indirect = False
            op_str = ""   # 无操作数
        else:
            # ----- 普通跳转/调用 -----
            jump_match = jump_pattern.match(line_strip)
            if not jump_match:
                continue
            instr_addr = jump_match.group(1)
            instr_bytes_str = jump_match.group(2).strip()
            jump_instr = jump_match.group(3)
            op_str = jump_match.group(4).strip()

            # 解析操作数，区分直接/间接
            is_indirect = '*' in op_str or '(' in op_str or ')' in op_str

            if not is_indirect:
                # 尝试提取数字地址或符号
                # 格式1: 0x123456
                hex_match = re.match(r'^0x([0-9a-fA-F]+)$', op_str)
                if hex_match:
                    target_addr = hex_match.group(1)
                    target_func_name = "UNKNOWN"
                else:
                    # 格式2: <function+0x10> 或 <function>
                    sym_match = re.match(r'^<([^>]+)>$', op_str)
                    if sym_match:
                        sym_str = sym_match.group(1)
                        # 分离符号名和偏移
                        parts = sym_str.split('+')
                        if len(parts) == 2:
                            target_func_name = parts[0]
                            offset = parts[1]
                            # 目标地址 = 符号地址 + 偏移，但这里无法获取符号地址，留空
                            target_addr = None
                        else:
                            target_func_name = sym_str
                            target_addr = None
                    else:
                        # 其他情况，视为直接但地址未知
                        target_addr = None
                        target_func_name = "UNKNOWN"
            else:
                # 间接形式，目标地址未知
                target_addr = None
                target_func_name = "UNKNOWN"

        # ----- 计算指令长度 -----
        instr_bytes = instr_bytes_str.split()
        instr_len = len(instr_bytes)

        # ----- 构建指令内容字符串（保留原始操作数）-----
        instr_content = f"{jump_instr} {op_str}" if op_str else f"{jump_instr}"
        if target_func_name and target_func_name != "UNKNOWN" and not is_indirect:
            instr_content += f" <{target_func_name}>"

        # ----- 获取父函数信息 -----
        parent_func_name, parent_func_start = get_parent_function(instr_addr, function_map)

        # ----- 获取目标函数信息（仅直接形式）-----
        if target_addr and not is_indirect:
            target_func_name_by_addr, target_func_start = get_parent_function(target_addr, function_map)
            if target_func_name == "UNKNOWN" and target_func_name_by_addr != "UNKNOWN":
                final_target_func_name = target_func_name_by_addr
            else:
                final_target_func_name = target_func_name
        else:
            final_target_func_name = target_func_name if target_func_name != "UNKNOWN" else ""
            target_func_start = "UNKNOWN"

        # ----- 跳转类型细化（基于机器码）-----
        jump_type = JUMP_TYPE_MAP.get(jump_instr, "未知跳转")

        if instr_bytes:
            first_byte = int(instr_bytes[0], 16)

            # 返回指令细化
            if jump_instr in ('ret', 'retq', 'retf', 'lret'):
                if first_byte == 0xC2:
                    jump_type = "函数返回(imm16)"
                elif first_byte == 0xC3:
                    jump_type = "函数返回"
                elif first_byte == 0xCA:
                    jump_type = "函数返回(far imm16)"   # ca 指令
                elif first_byte == 0xCB:
                    jump_type = "函数返回(far)"         # cb 指令

            # FF 指令识别（间接跳转/调用）
            if first_byte == 0xFF:
                if jump_instr in ('call', 'callq'):
                    jump_type = "间接调用"
                elif jump_instr == 'jmp':
                    jump_type = "间接跳转"

            # 如果操作数包含 '*' 或括号，也视为间接（补充）
            if is_indirect and jump_instr in ('call', 'callq', 'jmp'):
                if jump_instr in ('call', 'callq'):
                    jump_type = "间接调用"
                else:
                    jump_type = "间接跳转"

        # ----- 清理地址格式 -----
        full_instr_addr = clean_hex_address(instr_addr)
        full_parent_start = clean_hex_address(parent_func_start)
        full_target_addr = clean_hex_address(target_addr) if target_addr else ""
        full_target_func_start = clean_hex_address(target_func_start) if target_func_start != "UNKNOWN" else ""

        jump_data.append({
            "jump_instr_address": full_instr_addr,
            "jump_instr": jump_instr,
            "instr_len": instr_len,
            "instr_content": instr_content,
            "instr_bytes": instr_bytes_str,
            "jump_type": jump_type,
            "parent_function_name": parent_func_name,
            "parent_function_start": full_parent_start,
            "target_address": full_target_addr,
            "target_function_name": final_target_func_name,
            "target_function_start": full_target_func_start
        })

    return jump_data

# ===================== 主流程 =====================
if __name__ == "__main__":
    # 1. 读取反汇编文件
    with open(DISASM_FILE, 'r', encoding='utf-8') as f:
        disasm_lines = f.readlines()
    print(f"✅ 成功读取反汇编文件，共{len(disasm_lines)}行")

    # 2. 解析函数映射
    function_map = parse_functions(disasm_lines)
    print(f"✅ 解析到{len(function_map)}个函数")

    # 3. 解析跳转指令
    jump_data = parse_jump_instructions(disasm_lines, function_map)
    print(f"✅ 解析到{len(jump_data)}条跳转指令")

    # 4. 统计跳转指令类型分布
    jump_type_count = {}
    for item in jump_data:
        jtype = item['jump_type']
        jump_type_count[jtype] = jump_type_count.get(jtype, 0) + 1
    print("跳转指令类型分布:")
    for jtype, count in jump_type_count.items():
        print(f"  {jtype}: {count}条")

    # 5. 写入CSV文件
    headers = [
        "jump_instr_address", "jump_instr", "instr_len", "instr_content", "instr_bytes",
        "jump_type", "parent_function_name", "parent_function_start",
        "target_address", "target_function_name", "target_function_start"
    ]
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(jump_data)
    print(f"✅ 结构化数据已保存到 {OUTPUT_CSV}")

    # 显示前几条数据示例
    print("\n前5条数据示例:")
    for i, item in enumerate(jump_data[:5]):
        print(f"{i+1}. 地址: {item['jump_instr_address']}, "
              f"指令: {item['jump_instr']}, "
              f"长度: {item['instr_len']}字节, "
              f"内容: {item['instr_content']}")