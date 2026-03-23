#!/bin/bash
# find_and_copy_modules.sh

# 目标目录
TARGET_DIR="/home/miskey/Desktop/cfi/data/ko"

# 创建目标目录（如果不存在）
mkdir -p "$TARGET_DIR"

echo "正在查找并复制正在运行的内核模块..."

# 获取所有正在运行的模块
lsmod | tail -n +2 | while read module_name size used by; do
    # 获取模块文件路径
    module_path=$(modinfo -n "$module_name" 2>/dev/null)
    
    if [ -n "$module_path" ] && [ -f "$module_path" ]; then
        # 复制模块到目标目录
        cp "$module_path" "$TARGET_DIR/"
        echo "✓ 已复制: $module_name ($(basename $module_path))"
    else
        echo "✗ 无法找到模块文件: $module_name"
    fi
done

echo "完成！模块已复制到: $TARGET_DIR"
ls -la "$TARGET_DIR"