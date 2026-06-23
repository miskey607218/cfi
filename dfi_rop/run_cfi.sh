#!/bin/bash
# run_cfi.sh - 自动化 test.so CFI/DFI 分析流程

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

SO_FILE="test.so"
if [ ! -f "$SO_FILE" ]; then
    echo -e "${RED}错误：找不到 $SO_FILE${NC}"
    exit 1
fi

if ! command -v objdump &> /dev/null; then
    echo -e "${RED}错误：未找到 objdump，请安装 binutils。${NC}"
    exit 1
fi

echo -e "${GREEN}=== 步骤1：生成反汇编文件 test.txt ===${NC}"
objdump -d "$SO_FILE" > test.txt
echo "生成 test.txt 完成。"

echo -e "${GREEN}=== 步骤2：生成跳转分析 CSV test_jump_analysis.csv ===${NC}"
python3 transformToCsv.py
echo "生成 test_jump_analysis.csv 完成。"

echo -e "${GREEN}=== 步骤3：数据流分析，生成 DFI CSV ===${NC}"
python3 dataflow_analysis.py test.txt
echo "生成 register_dfi_instructions.csv 和 register_dfi_def_use_chains.csv 完成。"

echo -e "${GREEN}=== 步骤4：启动 CFI/DFI 运行时监控 ===${NC}"
sudo python3 dfi.py
