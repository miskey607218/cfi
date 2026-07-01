#!/bin/bash
# run.sh — CFI/DFI 融合监控：一键编译 + 静态分析 + 运行时监控
# 用法: cd final && ./run.sh [CFI_MODE] [OUTPUT_PREFIX] [ITERATIONS]
#   CFI_MODE: train | enforce | hybrid (默认: train)
#   OUTPUT_PREFIX: CSV 输出前缀 (默认: demo)
#   ITERATIONS: 执行次数 (默认: 3)
#
# 攻击模式:
#   ./run.sh -a 3              # 编译并运行攻击场景 #3 (ATTACK 模式)
#   ./run.sh -a 3 -s           # 编译并运行攻击场景 #3 (SAFE 模式)
#   ./run.sh -a all            # 运行所有攻击场景

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
TEST_DIR="$SCRIPT_DIR/test"
BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT_DIR="$SCRIPT_DIR/output"

ATTACK_MODE=false
ATTACK_ID=""
SAFE_FLAG=""

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--attack)
            ATTACK_MODE=true
            ATTACK_ID="$2"
            shift 2
            ;;
        -s|--safe)
            SAFE_FLAG="--safe"
            shift
            ;;
        *)
            MODE="${1:-train}"
            PREFIX="${2:-demo}"
            ITERATIONS="${3:-3}"
            shift 3 2>/dev/null || shift $#
            ;;
    esac
done

MODE="${MODE:-train}"
PREFIX="${PREFIX:-demo}"
ITERATIONS="${ITERATIONS:-3}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  CFI/DFI 融合监控 — 一键运行${NC}"
echo -e "${CYAN}============================================${NC}"

mkdir -p "$TEST_DIR" "$OUTPUT_DIR"

if $ATTACK_MODE; then
    # ═══════════════════════════════════════════════
    #  攻击模式
    # ═══════════════════════════════════════════════
    echo -e "${YELLOW}  攻击模式: ATTACK_ID=${ATTACK_ID}${NC}"
    echo -e "${CYAN}============================================${NC}"

    # ── Step 1: 编译 attack.so ──
    mkdir -p "$BUILD_DIR/attack"
    echo -e "\n${GREEN}[1/5] 编译 src/attack.c → build/attack/attack.so${NC}"
    gcc -shared -fPIC -O0 -o "$BUILD_DIR/attack/attack.so" "$TEST_DIR/attack.c"
    echo "  ✓ build/attack/attack.so 已生成"

    # ── Step 2: 反汇编 ──
    echo -e "\n${GREEN}[2/5] 反汇编 → build/attack/attack.txt${NC}"
    objdump -d "$BUILD_DIR/attack/attack.so" > "$BUILD_DIR/attack/attack.txt"
    echo "  ✓ build/attack/attack.txt ($(wc -l < "$BUILD_DIR/attack/attack.txt") 行)"

    # ── Step 3: 跳转指令分析 ──
    echo -e "\n${GREEN}[3/5] 跳转指令分析 → build/attack/attack_jump_analysis.csv${NC}"
    python3 "$SRC_DIR/transformToCsv.py" --input "$BUILD_DIR/attack/attack.txt" --output "$BUILD_DIR/attack/attack_jump_analysis.csv"

    # ── Step 4: 数据流分析 ──
    echo -e "\n${GREEN}[4/5] 数据流 def-use 链分析${NC}"
    python3 "$SRC_DIR/dataflow_analysis.py" "$BUILD_DIR/attack/attack.txt" "$BUILD_DIR/attack/attack_register_dfi"

    ATTACK_PREFIX="attack_${ATTACK_ID}"
    if [ -n "$SAFE_FLAG" ]; then
        ATTACK_PREFIX="attack_safe_${ATTACK_ID}"
    fi

    # ── Step 5: 启动监控 ──
    echo -e "\n${GREEN}[5/5] 启动 CFI/DFI 攻击监控${NC}"
    echo -e "  攻击场景: ${ATTACK_ID}"
    echo -e "  输出前缀: ${ATTACK_PREFIX}"
    echo ""
    mkdir -p "$OUTPUT_DIR/attack"
    sudo python3 "$SRC_DIR/dfi_monitor.py" \
        -m train \
        -o "attack/$ATTACK_PREFIX" \
        -n "$ITERATIONS" \
        --so "$BUILD_DIR/attack/attack.so" \
        --entry run_attack \
        --param "$ATTACK_ID" \
        --csv "$BUILD_DIR/attack/attack_jump_analysis.csv"

else
    # ═══════════════════════════════════════════════
    #  正常测试模式
    # ═══════════════════════════════════════════════
    echo -e "  模式: ${MODE}    输出前缀: ${PREFIX}    迭代: ${ITERATIONS}${NC}"
    echo -e "${CYAN}============================================${NC}"

    # ── Step 1: 编译 test.so ──
    mkdir -p "$BUILD_DIR/test"
    echo -e "\n${GREEN}[1/5] 编译 src/test.c → build/test/test.so${NC}"
    gcc -shared -fPIC -O0 -o "$BUILD_DIR/test/test.so" "$TEST_DIR/test.c"
    echo "  ✓ build/test/test.so 已生成"

    # ── Step 2: 反汇编 ──
    echo -e "\n${GREEN}[2/5] 反汇编 → build/test/test.txt${NC}"
    objdump -d "$BUILD_DIR/test/test.so" > "$BUILD_DIR/test/test.txt"
    echo "  ✓ build/test/test.txt ($(wc -l < "$BUILD_DIR/test/test.txt") 行)"

    # ── Step 3: 跳转指令分析 ──
    echo -e "\n${GREEN}[3/5] 跳转指令分析 → build/test/test_jump_analysis.csv${NC}"
    python3 "$SRC_DIR/transformToCsv.py" --input "$BUILD_DIR/test/test.txt" --output "$BUILD_DIR/test/test_jump_analysis.csv"

    # ── Step 4: 数据流分析 ──
    echo -e "\n${GREEN}[4/5] 数据流 def-use 链分析${NC}"
    python3 "$SRC_DIR/dataflow_analysis.py" "$BUILD_DIR/test/test.txt" "$BUILD_DIR/test/test_register_dfi"

    # ── Step 5: 启动 CFI/DFI 融合监控 ──
    echo -e "\n${GREEN}[5/5] 启动 CFI/DFI 融合监控${NC}"
    echo -e "  ${CYAN}同时执行: CFI 控制流监督 + DFI 数据流记录${NC}"
    echo -e "  输出文件: output/${PREFIX}_dfi_layers.csv"
    echo -e "           output/${PREFIX}_cfi_events.csv"
    echo ""
    mkdir -p "$OUTPUT_DIR/test"
    sudo python3 "$SRC_DIR/dfi_monitor.py" -m "$MODE" -o "test/$PREFIX" -n "$ITERATIONS" \
        --so "$BUILD_DIR/test/test.so" \
        --csv "$BUILD_DIR/test/test_jump_analysis.csv"
fi
