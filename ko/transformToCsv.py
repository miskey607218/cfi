import re
import csv
import sys

# ===================== 配置项 =====================
# 跳转指令类型映射（按类型分类）
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

    func_addr_list = [(int(fa, 16), fa) for fa in function_map.keys()]
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
    return f"0x{int(hex_str, 16):x}"


def parse_jump_instructions(disasm_lines, function_map):
    """解析所有跳转指令，返回结构化数据列表"""
    jump_data = []
    jump_pattern = re.compile(
        r'^([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s*)+?)\s+(' +
        '|'.join(JUMP_TYPE_MAP.keys()) +
        r')\s+([0-9a-fA-F]+)(?:\s+<([^+>]+)(?:\+0x[0-9a-fA-F]+)?>)?'
    )

    for line in disasm_lines:
        line_strip = line.strip()
        if not line_strip:
            continue

        match = jump_pattern.match(line_strip)
        if not match:
            continue

        instr_addr = match.group(1)
        instr_bytes_str = match.group(2).strip()
        jump_instr = match.group(3)
        target_addr = match.group(4)
        target_func_name = match.group(5) or "UNKNOWN"

        instr_bytes = instr_bytes_str.split()
        instr_len = len(instr_bytes)

        instr_content = f"{jump_instr} {target_addr}"
        if target_func_name != "UNKNOWN":
            instr_content += f" <{target_func_name}>"

        parent_func_name, parent_func_start = get_parent_function(instr_addr, function_map)
        target_func_name_by_addr, target_func_start = get_parent_function(target_addr, function_map)
        final_target_func_name = target_func_name if target_func_name != "UNKNOWN" else target_func_name_by_addr

        jump_type = JUMP_TYPE_MAP.get(jump_instr, "未知跳转")

        jump_data.append({
            "jump_instr_address": clean_hex_address(instr_addr),
            "jump_instr": jump_instr,
            "instr_len": instr_len,
            "instr_content": instr_content,
            "instr_bytes": instr_bytes_str,
            "jump_type": jump_type,
            "parent_function_name": parent_func_name,
            "parent_function_start": clean_hex_address(parent_func_start),
            "target_address": clean_hex_address(target_addr),
            "target_function_name": final_target_func_name,
            "target_function_start": clean_hex_address(target_func_start)
        })

    return jump_data


# ===================== 主流程 =====================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 transformToCsv.py <模块名>")
        print("示例: python3 transformToCsv.py e1000")
        sys.exit(1)

    module_name = sys.argv[1]
    disasm_file = f"data/txt/{module_name}_disassembly.txt"
    output_csv = f"data/csv/{module_name}_jump_analysis.csv"

    with open(disasm_file, 'r', encoding='utf-8') as f:
        disasm_lines = f.readlines()
    print(f"✅ 成功读取反汇编文件，共{len(disasm_lines)}行")

    function_map = parse_functions(disasm_lines)
    print(f"✅ 解析到{len(function_map)}个函数")

    jump_data = parse_jump_instructions(disasm_lines, function_map)
    print(f"✅ 解析到{len(jump_data)}条跳转指令")

    jump_type_count = {}
    for item in jump_data:
        jtype = item['jump_type']
        jump_type_count[jtype] = jump_type_count.get(jtype, 0) + 1
    print("跳转指令类型分布:")
    for jtype, count in jump_type_count.items():
        print(f"  {jtype}: {count}条")

    headers = [
        "jump_instr_address", "jump_instr", "instr_len", "instr_content", "instr_bytes",
        "jump_type", "parent_function_name", "parent_function_start",
        "target_address", "target_function_name", "target_function_start"
    ]
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(jump_data)
    print(f"✅ 结构化数据已保存到 {output_csv}")

    print("\n前5条数据示例:")
    for i, item in enumerate(jump_data[:5]):
        print(f"{i+1}. 地址: {item['jump_instr_address']}, "
              f"指令: {item['jump_instr']}, "
              f"长度: {item['instr_len']}字节, "
              f"内容: {item['instr_content']}")