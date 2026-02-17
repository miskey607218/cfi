import re
import csv

# ===================== 配置项 =====================
DISASM_FILE = "e1000_disassembly.txt"  # 你的反汇编文件路径
OUTPUT_CSV = "e1000_jump_analysis.csv"  # 输出的CSV文件路径

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
    function_map = {}  # key: 函数起始地址（字符串）, value: 函数名
    func_pattern = re.compile(r'^([0-9a-fA-F]+) <([^>]+)>:$')  # 匹配 "c0001000 <e1000_intr>:"

    for line_num, line in enumerate(disasm_lines, 1):
        line_strip = line.strip()
        match = func_pattern.match(line_strip)
        if match:
            func_addr = match.group(1)  # 函数起始地址（十六进制字符串，如c0001000）
            func_name = match.group(2)  # 函数名（如e1000_intr）
            function_map[func_addr] = func_name
    return function_map


def get_parent_function(addr, function_map):
    """根据指令地址，找到所属的函数名和函数起始地址（修复KeyError）"""
    # 处理异常地址（如空值、非十六进制字符串）
    if not addr or not re.match(r'^[0-9a-fA-F]+$', addr):
        return "UNKNOWN", "UNKNOWN"

    try:
        instr_addr_int = int(addr, 16)
    except ValueError:
        return "UNKNOWN", "UNKNOWN"

    # 转换函数地址为整数并排序
    func_addr_list = []
    for fa_str in function_map.keys():
        try:
            fa_int = int(fa_str, 16)
            func_addr_list.append((fa_int, fa_str))
        except ValueError:
            continue  # 跳过无效的函数地址

    if not func_addr_list:
        return "UNKNOWN", "UNKNOWN"

    # 从大到小排序，找小于等于指令地址的最大函数地址
    func_addr_list.sort(reverse=True, key=lambda x: x[0])

    parent_func_start = "UNKNOWN"
    parent_func_name = "UNKNOWN"
    for fa_int, fa_str in func_addr_list:
        if fa_int <= instr_addr_int:
            parent_func_start = fa_str
            parent_func_name = function_map[fa_str]
            break

    return parent_func_name, parent_func_start


# ========== 工具函数：清理十六进制地址的前导0 ==========
def clean_hex_address(hex_str):
    """
    清理十六进制地址的前导0，返回如0x9e1的格式
    :param hex_str: 原始十六进制字符串（如00000000000009e1、c0001000）
    :return: 简化后的地址（如0x9e1、0xc0001000）
    """
    if hex_str == "UNKNOWN":
        return "UNKNOWN"
    try:
        # 先转整数（自动剔除前导0），再转回十六进制字符串（小写）
        addr_int = int(hex_str, 16)
        # 拼接0x前缀，确保格式正确
        return f"0x{addr_int:x}"
    except ValueError:
        return "UNKNOWN"


def parse_jump_instructions(disasm_lines, function_map):
    """解析所有跳转指令，返回结构化数据列表（新增目标地址所属函数起始地址）"""
    jump_data = []
    # 匹配跳转指令行：格式如 "c0001050:   74 12   je     c0001064 <e1000_intr+0x64>"
    # 分组：1=指令地址, 2=指令码, 3=跳转指令, 4=目标地址, 5=目标函数偏移（可选）
    jump_pattern = re.compile(
        r'^([0-9a-fA-F]+):\s+[0-9a-fA-F\s]+\s+(' +
        '|'.join(JUMP_TYPE_MAP.keys()) +
        r')\s+([0-9a-fA-F]+)(?:\s+<([^+>]+)(?:\+0x[0-9a-fA-F]+)?>)?'
    )

    for line_num, line in enumerate(disasm_lines, 1):
        line_strip = line.strip()
        if not line_strip:
            continue

        match = jump_pattern.match(line_strip)
        if match:
            try:
                # 提取基础信息
                instr_addr = match.group(1)  # 跳转指令地址
                jump_instr = match.group(2)  # 跳转指令（如je）
                target_addr = match.group(3)  # 目标地址
                target_func_name = match.group(4) or "UNKNOWN"  # 目标函数名（可选）

                # 补充跳转指令所属函数信息
                parent_func_name, parent_func_start = get_parent_function(instr_addr, function_map)

                # ========== 关键新增：获取目标地址所属函数信息 ==========
                target_func_name_by_addr, target_func_start = get_parent_function(target_addr, function_map)
                # 优先使用反汇编中的目标函数名，若无则用解析到的
                final_target_func_name = target_func_name if target_func_name != "UNKNOWN" else target_func_name_by_addr

                # 补充跳转类型
                jump_type = JUMP_TYPE_MAP.get(jump_instr, "未知跳转")

                # 清理所有地址的前导0
                full_instr_addr = clean_hex_address(instr_addr)
                full_target_addr = clean_hex_address(target_addr)
                full_parent_start = clean_hex_address(parent_func_start)
                full_target_func_start = clean_hex_address(target_func_start)  # 清理目标函数起始地址

                # 组装结构化数据（新增target_function_start字段）
                jump_data.append({
                    "jump_instr_address": full_instr_addr,
                    "jump_instr": jump_instr,
                    "jump_type": jump_type,
                    "parent_function_name": parent_func_name,
                    "parent_function_start": full_parent_start,
                    "target_address": full_target_addr,
                    "target_function_name": final_target_func_name,
                    "target_function_start": full_target_func_start  # 新增字段：目标地址所在函数开始地址
                })
            except Exception as e:
                # 打印异常行，不中断整体解析
                print(f"⚠️  解析第{line_num}行出错：{e}，行内容：{line_strip}")
                continue
    return jump_data


# ===================== 主流程 =====================
if __name__ == "__main__":
    # 1. 读取反汇编文件
    try:
        with open(DISASM_FILE, 'r', encoding='utf-8') as f:
            disasm_lines = f.readlines()
        print(f"✅ 成功读取反汇编文件，共{len(disasm_lines)}行")
    except FileNotFoundError:
        print(f"❌ 错误：未找到文件 {DISASM_FILE}，请检查路径是否正确")
        exit(1)
    except Exception as e:
        print(f"❌ 读取文件出错：{e}")
        exit(1)

    # 2. 解析函数映射
    function_map = parse_functions(disasm_lines)
    print(f"✅ 解析到{len(function_map)}个函数")

    # 3. 解析跳转指令
    jump_data = parse_jump_instructions(disasm_lines, function_map)
    print(f"✅ 解析到{len(jump_data)}条跳转指令")

    # 4. 写入CSV文件（新增target_function_start表头）
    headers = [
        "jump_instr_address", "jump_instr", "jump_type",
        "parent_function_name", "parent_function_start",
        "target_address", "target_function_name",
        "target_function_start"  # 新增表头字段
    ]
    try:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(jump_data)
        print(f"✅ 结构化数据已保存到 {OUTPUT_CSV}")
    except Exception as e:
        print(f"❌ 写入CSV出错：{e}")
        exit(1)
