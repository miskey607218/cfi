#!/bin/bash
# run_cfi.sh – 自动化内核模块 CFI 分析流程

set -e  # 任何命令失败则立即退出

# 颜色输出（可选）
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# 获取模块名，默认为 e1000
MODULE_NAME="${1:-e1000}"
echo -e "${GREEN}=== 目标模块: $MODULE_NAME ===${NC}"

# 定义文件路径
KO_FILE="data/ko/${MODULE_NAME}.ko"
DISASM_FILE="data/txt/${MODULE_NAME}_disassembly.txt"
CSV_FILE="data/csv/${MODULE_NAME}_jump_analysis.csv"

# 创建必要的目录
mkdir -p data/txt data/csv

# 检查必要文件
if [ ! -f "$KO_FILE" ]; then
    echo -e "${RED}错误：找不到 $KO_FILE，请将 ${MODULE_NAME}.ko 放在当前目录。${NC}"
    exit 1
fi

TRANSFORM_SCRIPT="transformToCsv.py"
if [ ! -f "$TRANSFORM_SCRIPT" ]; then
    echo -e "${RED}错误：找不到 $TRANSFORM_SCRIPT，请确保脚本在当前目录。${NC}"
    exit 1
fi

CFI_SCRIPT="cfi_ko.py"
if [ ! -f "$CFI_SCRIPT" ]; then
    echo -e "${RED}错误：找不到 $CFI_SCRIPT，请确保脚本在当前目录。${NC}"
    exit 1
fi

# 检查反汇编工具（优先使用 objdump，如果不存在则尝试 llvm-objdump）
if command -v objdump &> /dev/null; then
    OBJDUMP="objdump"
elif command -v llvm-objdump &> /dev/null; then
    OBJDUMP="llvm-objdump"
else
    echo -e "${RED}错误：未找到 objdump 或 llvm-objdump，请安装 binutils 或 LLVM。${NC}"
    exit 1
fi
echo -e "${GREEN}使用反汇编工具: $OBJDUMP${NC}"

echo -e "${GREEN}=== 步骤1：生成反汇编文件 $DISASM_FILE ===${NC}"
$OBJDUMP -d "$KO_FILE" > "$DISASM_FILE"
echo "生成完成。"

echo -e "${GREEN}=== 步骤2：生成跳转分析 CSV $CSV_FILE ===${NC}"
python3 "$TRANSFORM_SCRIPT" "$MODULE_NAME"
echo "生成完成。"

echo -e "${GREEN}=== 步骤3：加载模块并启动 CFI 监控 ===${NC}"
# 检查模块是否已加载，若未加载则尝试加载
if ! lsmod | grep -q "^$MODULE_NAME "; then
    echo "模块未加载，正在加载..."
    sudo modprobe "$MODULE_NAME" || echo -e "${RED}警告：无法加载模块 $MODULE_NAME，可能已内建或不存在。${NC}"
fi
sudo python3 "$CFI_SCRIPT" "$MODULE_NAME"

echo -e "${GREEN}所有步骤执行完毕。${NC}"