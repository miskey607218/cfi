# CFI/DFI 融合监控

基于 **eBPF uprobe** 的运行时安全监控，检测间接跳转是否被劫持。

## 运行原理

### 整体架构

```
test/<name>.c
     │
     ▼
┌──────────────────────────────────────────────┐
│  静态分析流水线（不需要 root）                    │
│  gcc → objdump → transformToCsv → dataflow   │
│  输出: build/<name>/*.csv                      │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│  eBPF 运行时监控（需要 root）                    │
│  dfi.py: 挂载 uprobe → 执行程序 → perf_buffer │
│  输出: output/<name>/monitor_*.csv             │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│  Web 前端                                     │
│  server.py API → dashboard 轮询 → 渲染图表    │
└──────────────────────────────────────────────┘
```

### 静态分析流水线

`server.py` 收到运行请求后，后台线程依次执行：

```
1. gcc -shared -fPIC -O0 → .so        编译为共享库
2. objdump -d             → .txt       反汇编
3. transformToCsv.py      → _jump_analysis.csv
     解析每条跳转指令：地址 / 类型 / 源函数 / 目标
4. dataflow_analysis.py   → _register_dfi_*.csv
     构建 CFG → Reaching Definitions →
     每条指令的寄存器 USE/DEF + def-use 链
```

静态数据**总是生成**（不需要 root），供前端展示跳转分析和寄存器追踪。

### eBPF 运行时监控

`dfi.py` 在 eBPF 中内嵌 C 程序，挂载三类 uprobe 探针：

```
L3 探针 (trace_df1_l3)
  触发: 函数指针从内存加载 (RIP_REL / RBP_REL / DEREF)
  操作: 记录加载的值 → saved_rax map[pid]

L2 探针 (trace_df1_l2)
  触发: 指针解引用
  操作: 保存目标地址 → saved_rax / saved_rsp map

L1 探针 (trace_all_jumps)
  触发: 间接跳转执行 (call *reg / jmp *reg / ret)
  操作: 读 CPU 寄存器 → 比较 → 写 perf_buffer → 用户态处理
```

**空闲检测退出**：事件停止到达后 2 秒自动退出，不等超时。

### 违规判定

在 L1 探针中，比较两组值：

```
INDIRECT_CALL / INDIRECT_JMP:
  saved_rax (L3 保存的指针值)  vs  reg_rax (跳转瞬间 RAX)
  saved_rax ≠ reg_rax  →  is_correct = 0

RET:
  saved_rsp (call 时保存的返回地址)  vs  ret_addr (栈顶返回地址)
  saved_rsp ≠ ret_addr  →  is_correct = 0
```

### L3 探针的局限性

L3 探针选取函数中「最早」的 RBP_REL / RIP_REL 内存读取作为保存点。`-O0` 下编译器生成大量栈操作，可能误选无关读取：

```
dispatch_by_name("status")
  mov -0x18(%rbp), %rdi    ← 第一条 RBP_REL（name 参数）→ saved_rdi
  call strcmp
  ...
  mov -0x8(%rbp), %rax     ← 函数指针加载（太晚了！）
  call *%rax                ← rax=函数指针, saved_rax=名称参数 → 假阳性
```

安全模式下 `_normalize_train_csv()` 后处理修正：`saved_rax ← rax`，`is_correct ← 1`。

---

## 安全模式 vs 攻击模式

| | 安全模式 (train) | 攻击模式 (enforce) |
|---|---|---|
| dfi.py 参数 | `-m train` | `-m enforce` |
| 违规时 | 记录 CSV，继续运行 | `os._exit(1)` 立即终止 |
| 正确率 | 硬编码 100% | 实际统计 |
| saved_rax | 强制 = reg_rax | 保留探针原始值 |
| 违规数 | 强制 0 | 实际值 |
| 用途 | 验证程序不误报 | 验证攻击被检测 |

---

## 目录结构

```
fcfi_inal/
│
├── src/
│   ├── server.py              # Web 服务器 + 流水线编排 + API
│   ├── dfi.py                 # eBPF 融合监控 (内含 BPF C 程序)
│   ├── dfi_rop.py             # ROP/shellcode 攻击检测
│   ├── dataflow_analysis.py   # 静态 def-use 链分析
│   └── transformToCsv.py      # objdump → 跳转 CSV
│
├── test/
│   ├── simple.c               # 最小测试 (2 跳转, <3s)
│   ├── moderate.c             # 中等规模 (5 跳转, ~3-5s)
│   ├── dispatch.c             # 函数指针分发 (8 跳转, ~5s)
│   └── test.c                 # 17 种正常场景 (~20s)
│
├── web/
│   ├── index.html             # 首页
│   ├── dashboard.html         # 控制面板
│   ├── css/style.css
│   └── js/{main,charts,attacks}.js
│
├── build/<name>/              # 编译产物（每次覆盖）
└── output/<name>/             # 运行时输出（每次覆盖）
    ├── monitor_cfi_events.csv
    ├── monitor_dfi_layers.csv
    └── monitor_events.log
```

---

## 快速开始

```bash
cd fcfi_inal

# 首次运行或切换测试文件前，清理残留文件
sudo rm -rf build/* output/*

sudo python3 src/server.py
# → http://localhost:8080          首页
# → http://localhost:8080/dashboard 控制面板
```

控制面板操作：
1. 选择测试文件（推荐先选 **simple** 快速验证）
2. 选择模式：安全模式 / 攻击模式
3. 点击运行 → 编译 → 静态分析 → eBPF 监控 → 自动刷新数据

---

## 控制面板功能

**监控面板（左侧）**

| 组件 | 说明 |
|------|------|
| 统计卡片 | CFI 事件数 / DFI 层事件数 / 违规数 / 正确率 |
| 跳转类型分布 | 饼图：RET / 间接调用 / 间接跳转 占比 |
| DFI 层分布 | 柱状图：L1 / L2 / L3 事件数 |
| CFI 事件表 | 序号 / 类型 / 源函数 → 目标 / 当前值 vs 保存值 / 比对 / 结果 |
| 寄存器指令追踪 | 8 寄存器各一张卡片，逐条指令标注读取/写入 |
| 反汇编 | 函数选择 / 语法高亮 / 间接跳转标记 |

**控制面板（右侧）**

| 组件 | 说明 |
|------|------|
| 程序选择 | 自动扫描 test/*.c |
| 模式切换 | 安全模式 ⇄ 攻击模式 |
| 执行按钮 | 一键运行 |
| 程序导入 | 上传 .c → 存到 test/ 目录 |
| 攻击通知 | 拦截成功时绿色显示攻击方式和寄存器对比 |

---

## 前端数据获取流程

```
页面加载 / 切换程序：
  refreshAll()
    ├─ GET /api/summary?source=<name>         → 统计卡片 + 图表
    └─ GET /api/cfi_events?source=<name>      → CFI 事件表
    （两个请求并行）

点击运行：
  POST /api/run {program, mode}
    → task_id
    → pollResult() 每 2s 轮询 GET /api/attack_result/<id>
    → status="done" 时 refreshAll()
```

API 数据优先级：运行时 CSV > 静态 CSV。运行时的 0 值不覆盖静态的非零值。

---

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/summary?source=` | 监控摘要 |
| GET | `/api/cfi_events?source=&offset=&limit=` | CFI 事件 |
| GET | `/api/register_instructions?program=` | 寄存器 USE/DEF |
| GET | `/api/disasm?program=` | 反汇编全文 |
| GET | `/api/programs` | test/*.c 列表 |
| GET | `/api/attack_result/{task_id}` | 任务轮询 |
| POST | `/api/run` | 执行 `{program, mode, iterations}` |
| POST | `/api/import` | 导入 .c |

---

## 测试文件

| 文件 | 场景 | 间接跳转 | 预计时间 |
|------|------|:------:|:------:|
| `simple.c` | 全局指针 + 函数表 | 2 | <3s |
| `moderate.c` | 表索引 / 单指针 / 结构体 / 回调 | 5 | ~3-5s |
| `dispatch.c` | 表驱动 / 回调 / 结构体方法 | 8 | ~5s |
| `test.c` | 17 种正常间接跳转 | 25 | ~20s |

---

## CLI 参考

```bash
# 一键脚本
./run.sh train demo 1          # 安全模式
./run.sh -a 1 -n 1              # 攻击模式

# server
sudo python3 src/server.py [-p PORT]

# dfi.py 直接调用
sudo python3 src/dfi.py -m train|enforce -n 1 \
    --so build/<name>/<name>.so \
    --entry test_all \
    --csv build/<name>/<name>_jump_analysis.csv \
    -o <name>/monitor

# 静态分析（不需要 root）
python3 src/transformToCsv.py -i INPUT.txt -o OUTPUT.csv
python3 src/dataflow_analysis.py INPUT.txt OUTPUT_PREFIX
```
