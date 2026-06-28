#!/bin/bash
# run.sh — CFI/DFI 融合监控：一键编译 + 静态分析 + 运行时监控
# 用法: cd final && ./run.sh [CFI_MODE] [OUTPUT_PREFIX]
#   CFI_MODE: train | enforce | hybrid (默认: train)
#   OUTPUT_PREFIX: CSV 输出前缀 (默认: demo)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT_DIR="$SCRIPT_DIR/output"

MODE="${1:-train}"
PREFIX="${2:-demo}"
ITERATIONS="${3:-3}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  CFI/DFI 融合监控 — 一键运行${NC}"
echo -e "${CYAN}  模式: ${MODE}    输出前缀: ${PREFIX}${NC}"
echo -e "${CYAN}============================================${NC}"

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# ── Step 1: 编译 test.so ──
echo -e "\n${GREEN}[1/5] 编译 src/test.c → build/test.so${NC}"
gcc -shared -fPIC -O0 -o "$BUILD_DIR/test.so" "$SRC_DIR/test.c"
echo "  ✓ build/test.so 已生成"

# ── Step 2: 反汇编 ──
echo -e "\n${GREEN}[2/5] 反汇编 → build/test.txt${NC}"
objdump -d "$BUILD_DIR/test.so" > "$BUILD_DIR/test.txt"
echo "  ✓ build/test.txt ($(wc -l < "$BUILD_DIR/test.txt") 行)"

# ── Step 3: 跳转指令分析 ──
echo -e "\n${GREEN}[3/5] 跳转指令分析 → build/test_jump_analysis.csv${NC}"
python3 "$SRC_DIR/transformToCsv.py"

# ── Step 4: 数据流分析 ──
echo -e "\n${GREEN}[4/5] 数据流 def-use 链分析${NC}"
python3 "$SRC_DIR/dataflow_analysis.py" "$BUILD_DIR/test.txt" "$BUILD_DIR/register_dfi"

# ── Step 5: 启动 CFI/DFI 融合监控 ──
echo -e "\n${GREEN}[5/5] 启动 CFI/DFI 融合监控${NC}"
echo -e "  ${CYAN}同时执行: CFI 控制流监督 + DFI 数据流记录${NC}"
echo -e "  输出文件: output/${PREFIX}_dfi_layers.csv"
echo -e "           output/${PREFIX}_cfi_events.csv"
echo ""
sudo python3 "$SRC_DIR/dfi_monitor.py" -m "$MODE" -o "$PREFIX" -n "$ITERATIONS"
