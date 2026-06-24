#!/bin/bash
# run_cfi.sh - 自动化 test.so CFI/DFI 分析流程
# 用法: cd dfi_rop && bash preprocess/run_cfi.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# 切换到项目根目录 (脚本在 preprocess/ 下)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

SRC_DIR="src"
BUILD_DIR="build"
TOOLS_DIR="tools"
PREPROCESS_DIR="preprocess"

SO_FILE="$SRC_DIR/test.so"
if [ ! -f "$SO_FILE" ]; then
    echo -e "${RED}错误：找不到 $SO_FILE${NC}"
    echo "请先编译: gcc -shared -fPIC -O0 -o $SO_FILE $SRC_DIR/test.c"
    exit 1
fi

if ! command -v objdump &> /dev/null; then
    echo -e "${RED}错误：未找到 objdump，请安装 binutils。${NC}"
    exit 1
fi

mkdir -p "$BUILD_DIR"

echo -e "${GREEN}=== 步骤1：生成反汇编文件 $BUILD_DIR/test.txt ===${NC}"
objdump -d "$SO_FILE" > "$BUILD_DIR/test.txt"
echo "生成 $BUILD_DIR/test.txt 完成。"

echo -e "${GREEN}=== 步骤2：生成跳转分析 CSV ===${NC}"
python3 "$PREPROCESS_DIR/transformToCsv.py"
echo "生成 $BUILD_DIR/test_jump_analysis.csv 完成。"

echo -e "${GREEN}=== 步骤3：数据流分析，生成 DFI CSV ===${NC}"
python3 "$PREPROCESS_DIR/dataflow_analysis.py" "$BUILD_DIR/test.txt"
echo "生成 $BUILD_DIR/register_dfi_instructions.csv 和 $BUILD_DIR/register_dfi_def_use_chains.csv 完成。"

echo -e "${GREEN}=== 步骤4：启动 CFI/DFI 运行时监控 ===${NC}"
sudo python3 "$TOOLS_DIR/dfi.py"
