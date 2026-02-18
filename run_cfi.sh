#!/bin/bash
# run_cfi.sh – 自动化 e1000 模块 CFI 分析流程

set -e  # 任何命令失败则立即退出

# 颜色输出（可选）
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# 检查必要文件
KO_FILE="e1000.ko"
if [ ! -f "$KO_FILE" ]; then
    echo -e "${RED}错误：找不到 $KO_FILE，请将 e1000.ko 放在当前目录。${NC}"
    exit 1
fi

TRANSFORM_SCRIPT="transformToCsv.py"
if [ ! -f "$TRANSFORM_SCRIPT" ]; then
    echo -e "${RED}错误：找不到 $TRANSFORM_SCRIPT，请确保脚本在当前目录。${NC}"
    exit 1
fi

CFI_SCRIPT="cfi_final.py"
if [ ! -f "$CFI_SCRIPT" ]; then
    echo -e "${RED}错误：找不到 $CFI_SCRIPT，请确保脚本在当前目录。${NC}"
    exit 1
fi

# 检查 llvm-objdump 是否可用
if ! command -v llvm-objdump &> /dev/null; then
    echo -e "${RED}错误：未找到 llvm-objdump，请安装 LLVM 工具链。${NC}"
    exit 1
fi

echo -e "${GREEN}=== 步骤1：生成反汇编文件 e1000_disassembly.txt ===${NC}"
llvm-objdump -d "$KO_FILE" > e1000_disassembly.txt
echo "生成完成。"

echo -e "${GREEN}=== 步骤2：生成跳转分析 CSV e1000_jump_analysis.csv ===${NC}"
python3 "$TRANSFORM_SCRIPT" e1000_disassembly.txt e1000_jump_analysis.csv
echo "生成完成。"

echo -e "${GREEN}=== 步骤3：加载 e1000 模块并启动 CFI 监控 ===${NC}"
sudo modprobe e1000  # 确保模块已加载
sudo python3 "$CFI_SCRIPT"

echo -e "${GREEN}所有步骤执行完毕。${NC}"