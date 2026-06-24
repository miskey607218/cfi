# 模块运行时寄存器数据流追踪

## 做什么

在 `test.so` 运行期间，**按指令执行先后顺序**，记录**每条修改寄存器的指令**以及**寄存器值的变化**，写入文件。

核心输出：一份 CSV 文件，每一行记录一条指令执行后哪个寄存器的值从什么变成了什么。

---

## 文件结构

```
dfi_rop/
├── readme.md
│
├── src/                    # 源码与编译产物
│   ├── test.c              #   测试模块源码（17 个间接跳转场景）
│   └── test.so             #   编译产物
│
├── tools/                  # 主程序（直接运行）
│   ├── trace_registers.py  #   ★ 指令级寄存器追踪（推荐，无需预处理）
│   ├── dfi.py              #   三层 DFI 数据流追踪（需 CSV 预处理）
│
├── preprocess/             # 预处理脚本
│   ├── run_cfi.sh          #   一键脚本（objdump → 预处理 → dfi.py）
│   ├── transformToCsv.py   #   反汇编 → 跳转分析 CSV
│   └── dataflow_analysis.py #  反汇编 → 寄存器定值-使用链 CSV
│
└── build/                  # 中间文件 + 输出产物
    ├── test.txt            #   objdump 反汇编
    ├── test_jump_analysis.csv        #   跳转指令表
    ├── register_dfi_instructions.csv #   指令级寄存器分析
    ├── register_dfi_def_use_chains.csv # 寄存器定值-使用链
    └── register_trace.csv  #   指令级寄存器变化记录（最终输出）
```

---

## 运行方式一：`trace_registers.py`（推荐）

**不需要任何预处理**，只需 `test.so` 和 `objdump`。

### 第一步：编译

```bash
cd dfi_rop
gcc -shared -fPIC -O0 -o src/test.so src/test.c
```

### 第二步：运行（反汇编自动生成）

```bash
sudo python3 tools/trace_registers.py
```

> 注：如果 `build/test.txt` 不存在，脚本会自动调用 `objdump -d` 生成。也可以手动执行：
> ```bash
> objdump -d src/test.so > build/test.txt
> ```

**运行过程：**

```
[*] 生成反汇编: objdump -d test.so > test.txt
[*] 解析反汇编: test.txt
[*] 发现 366 条会修改寄存器的指令
[*] 涉及 28 个函数
    test_all: 32 条探针
    get_target: 26 条探针
    test07_indirect_jump: 22 条探针
    ...

[*] 加载 eBPF 程序...
[*] 模块基址: 0x7f1234560000

[*] 挂载 uprobes (366 个探针点)...
  挂载成功: 366, 失败: 0

[*] 输出文件: build/register_trace.csv
[*] 字段: elapsed_ms, pid, cpu, func, offset, reg, old_value, new_value, instruction

============================================================
  指令级寄存器追踪已启动
  探针点: 366 个
  迭代次数: 3
  输出文件: build/register_trace.csv
  触发完成后按 Ctrl+C 停止
============================================================

[    0.0ms] test_all+0x4  push %rbp
             RSP: ↘ 0x00007ffc1234abc0 → 0x00007ffc1234abb8
[    0.1ms] test_all+0x5  mov %rsp,%rbp
             RBP: → (新) → 0x00007ffc1234abb8
[    0.1ms] test_all+0x8  lea 0x2e91(%rip),%rax
             RAX: → (新) → 0x00007f1234562e9a
[    0.2ms] test_all+0x17  call 11b0 <puts@plt>
             RAX: ↗ 0x00007f1234562e9a → 0x00007f12345611fa
             RSP: ↘ 0x00007ffc1234abb8 → 0x00007ffc1234abb0
    ...

[*] 触发完成 (3 次)，等待缓冲事件写入...
[*] 事件收集完毕，可以按 Ctrl+C 停止
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-n N` | 3 | `test_all()` 执行次数 |
| `-o file.csv` | build/register_trace.csv | 输出文件路径 |
| `-q` | 关闭 | 静默模式：不打印终端，只写文件 |
| `-d file.txt` | build/test.txt | 反汇编文件路径 |
| `-s file.so` | src/test.so | 目标 .so 路径 |

```bash
# 执行 1 次，静默写入 my_trace.csv
sudo python3 tools/trace_registers.py -n 1 -q -o my_trace.csv
```

### 输出文件格式

`build/register_trace.csv` 每行记录一条"指令导致寄存器值改变"的事件：

| 列 | 含义 | 示例 |
|----|------|------|
| `elapsed_ms` | 从启动到该事件的毫秒数 | `0.123` |
| `pid` | 进程 ID | `5678` |
| `cpu` | CPU 编号 | `0` |
| `func` | 所在函数名 | `test_all` |
| `offset` | 指令相对函数起始的偏移 | `0x4` |
| `reg` | 发生变化的寄存器 | `RAX` |
| `old_value` | 变化前的值（首次出现标注"首次"） | `0x00007f1234562e9a` |
| `new_value` | 变化后的值 | `0x00007f12345611fa` |
| `instruction` | 汇编指令文本 | `call 11b0 <puts@plt>` |

**示例数据：**

```csv
elapsed_ms,pid,cpu,func,offset,reg,old_value,new_value,instruction
0.012,5678,0,test_all,0x4,RSP,(首次),0x00007ffc1234abb8,push %rbp
0.015,5678,0,test_all,0x5,RBP,(首次),0x00007ffc1234abb8,mov %rsp,%rbp
0.018,5678,0,test_all,0x8,RAX,(首次),0x00007f1234562e9a,lea 0x2e91(%rip),%rax
0.022,5678,0,test_all,0x17,RAX,0x00007f1234562e9a,0x00007f12345611fa,call 11b0 <puts@plt>
0.022,5678,0,test_all,0x17,RSP,0x00007ffc1234abb8,0x00007ffc1234abb0,call 11b0 <puts@plt>
```

### 原理

```
                     objdump -d test.so
                          │
                          ▼
              解析所有"会写寄存器"的指令
              (mov/lea/add/pop/call/ret ...)
                          │
              共 366 条指令，分布在 28 个函数中
                          │
              ┌───────────┴───────────┐
              │  对每条指令挂载 uprobe  │  ← eBPF 内核探针
              │  (函数名 + 偏移)       │
              └───────────┬───────────┘
                          │
              运行 test_all() × N 次
                          │
              ┌───────────┴───────────┐
              │  每命中一条指令：        │
              │  捕获 RAX~RDI 8 个寄存器 │  ← eBPF perf buffer
              │  发送到用户态           │
              └───────────┬───────────┘
                          │
              ┌───────────┴───────────┐
              │  Python 差分：          │
              │  与上次快照对比          │  ← 只记录变化的寄存器
              │  写入 CSV 文件          │
              └───────────────────────┘
```

### 注意事项

- **uprobe 在指令执行前触发**：捕获的寄存器值是"进入该指令时"的状态。对 `call` 指令，记录的是调用发生前的寄存器（参数在 rdi/rsi 中），而非返回值
- **只追踪 test.so 自身代码**：不追踪 libc 等外部库
- **需要 root 权限**：eBPF 程序加载需要 `sudo`

---

## 运行方式二：`dfi.py`（三层 DFI 追踪）

聚焦于**间接跳转指令**（`call *%reg` / `jmp *%reg` / `ret`），追踪决定跳转目标的寄存器值**经过的三层数据流变换**。

### 第一步：编译

```bash
gcc -shared -fPIC -O0 -o src/test.so src/test.c
```

### 第二步：预处理（生成 CSV 配置）

```bash
objdump -d src/test.so > build/test.txt
python3 preprocess/transformToCsv.py
python3 preprocess/dataflow_analysis.py build/test.txt
```

或直接运行一键脚本：

```bash
bash preprocess/run_cfi.sh
```

`run_cfi.sh` 自动执行：

```
objdump -d src/test.so > build/test.txt                  # 步骤 1
python3 preprocess/transformToCsv.py                     # 步骤 2
python3 preprocess/dataflow_analysis.py build/test.txt   # 步骤 3
sudo python3 tools/dfi.py                                # 步骤 4
```

### 第三步：运行

```bash
sudo python3 tools/dfi.py
```

### 运行过程（终端输出）

#### 阶段 A：启动时 — 打印静态分析结果

```
📊 解析三层 DFI 数据流链...
✅ 发现 5 个基于寄存器的间接跳转站点
   • test_indirect_call @ 0x1234  寄存器=rax  [首次内存读取/保存层 = L2 @ offset=0x1238]
      L1: 0x1234 (offset=0x1234) type=DIRECT → call *%rax
      L2: 0x1238 (offset=0x1238) type=DEREF → mov (%rax),%rax ⭐(保存点)
      L3: 0x1230 (offset=0x1230) type=RIP_REL → mov 0x2dd8(%rip),%rax
   ...

✅ 从 CSV 成功解析 5 个静态跳转规则
✅ 已建立 5 个站点的静态数据流链索引

加载BPF程序...
检测到 test.so 基址: 0x7f1234560000

🔗 挂载三层 DFI 数据流保护 + CFI 校验 uprobes...
  ✓ site#0 DFI+L1(实际目标): test_indirect_call+0x1234  (call *%rax)
  ✓ site#0 CFI:     test_indirect_call+0x1234  (trace_all_jumps)
  ✓ site#0 DFI+L2: test_indirect_call+0x1238  (mov (%rax),%rax) +SAVE(首次内存读取)
  ✓ site#0 DFI+L3: test_indirect_call+0x1230  (mov 0x2dd8(%rip),%rax)
  ...

=== CFI 监控已启动（.so 模式 + 三层 DFI）===
```

#### 阶段 B：运行时 — 三层 DFI 事件实时提示

每触发一层探针，即时输出：

```
  [🟢L3] site#0 test_indirect_call: reg=0x00007f1234567890  target=0x00007f1234567890
  [🟡L2] site#0 test_indirect_call: reg=0x00007f1234567890  target=0x0000000000001234
  [🔵L1] site#0 test_indirect_call: reg=0x0000000000001234  target=0x0000000000001234
```

| 图标 | 含义 |
|------|------|
| 🟢 L3 | 最早执行 — 从数据段/栈首次读取指针 |
| 🟡 L2 | 中间层 — 解引用或寄存器传递 |
| 🔵 L1 | 最晚执行 — 实际发生跳转 |

#### 阶段 C：三层到齐 — 寄存器数据流变换链

当同一个 site 的 L1+L2+L3 全部到齐时，展示完整变换链：

```
╔══════════════════════════════════════════════════════════════════════╗
║  寄存器数据流变换链 — site#0  PID=1234  func=test_indirect_call    ║
║  追踪寄存器: RAX                                                   ║
╠══════════════════════════════════════════════════════════════════════╣
║ 层 │ 指令偏移 │ 指令 (导致寄存器变换)           │ 寄存器值变换       ║
╠══════════════════════════════════════════════════════════════════════╣
║ L3 │ 0x1230  │ mov 0x2dd8(%rip),%rax        │ RAX ← mem[rip+disp] ║
║    │ 类型:   │ RIP_REL (数据段指针)           │ RAX = 0x7f12345678 ║
║    ├─────────┼──────────────────────────────┼─────────────────────╢
║ L2 │ 0x1238  │ mov (%rax),%rax               │ RAX ← *(RAX) (解引用) ║
║    │ 类型:   │ DEREF (解引用 *(reg))          │ RAX: 0x7f12.. → 0x1234 ║
║    ├─────────┼──────────────────────────────┼─────────────────────╢
║ L1 │ 0x123c  │ call *%rax                    │ JUMP → RAX          ║
║    │ 类型:   │ DIRECT (reg值即目标)           │ RAX = 0x1234 (未变) ║
╠══════════════════════════════════════════════════════════════════════╣
║  📊 数据流总结:                                                    ║
║     初始加载值 (L3) : 0x00007f1234567890                            ║
║     最终跳转目标(L1): 0x0000000000001234                            ║
║     RAX 值已变换 (经解引用/内存读取)                                  ║
╚══════════════════════════════════════════════════════════════════════╝
```

**如何读这张表：** 从下往上（L3→L2→L1）是代码执行顺序。"指令"列标注了**是哪条指令导致寄存器值改变**，"寄存器值变换"列标注了变换方向和结果。

#### 阶段 D：CFI 跳转事件（每次间接跳转触发的完整报告）

```
================================================================================
CFI 事件 #1 - ✓
跳转类型: INDIRECT_CALL (4)
================================================================================

📋 CFI 条目信息:
  • 源函数: test_indirect_call  →  目标函数: test_returns

📝 寄存器状态 (↗ 表示相比上次变化):
  • RAX: 0x0000000000001234 [返回值/跳转目标]  (首次记录)
  • RCX: 0x0000000000000001  ↗ 变化: 0x0000... → 0x0000...0001
  • RSP: 0x00007ffc1234abc0 [栈指针]  ↘ 变化: 0x...abd0 → 0x...abc0 (差 0x10)
  ...
  ── 4 个寄存器值发生变化 ──

✅ 验证结果:
  ✓ 此跳转符合CFI规则
```

**寄存器增量追踪说明：**

- `↗` 值变大、`↘` 值变小
- 显示"变化前 → 变化后"的完整值和差值
- 首次出现的寄存器标记为"首次记录"
- 底部统计变化数量

#### 阶段 E：停止时 — 统计汇总

```
=== 最终统计 ===
- CFI规则数: 5
- 处理事件数: 15
- CFI违规数: 0
- 三层DFI事件数: 12
- 违规率: 0.00%
```

---

## 两种方式对比

| | `trace_registers.py` | `dfi.py` |
|---|---|---|
| **探针覆盖** | 所有会修改寄存器的指令（366 点） | 间接跳转的三层数据流链（~10 点） |
| **追踪粒度** | 每条指令的寄存器变化 | 聚焦跳转目标寄存器的来源链路 |
| **预处理** | 无（直接解析 objdump） | 需要 `transformToCsv.py` + `dataflow_analysis.py` |
| **输出** | CSV 文件 | 终端格式化输出 |
| **适用场景** | 完整寄存器变化审计 | 间接跳转安全性分析 |
| **性能开销** | 较高（366 个 uprobes） | 较低（~10 个 uprobes） |

---

## test.c 测试场景（17 个）

| 编号 | 函数 | 间接跳转模式 |
|------|------|------------|
| 01 | `test01_global_fptr_call` | GOT 表全局函数指针 `call *disp(%rip)` |
| 02 | `test02_local_fptr_call` | 局部函数指针 `call *%rax` |
| 03 | `test03_table_fptr_call` | 函数指针数组索引 |
| 04 | `test04_stack_fptr_call` | 栈上函数指针（RBP 相对） |
| 05 | `test05_vtable_call` | 结构体函数指针（vtable 模拟） |
| 06 | `test06_callback_arg` | 参数传入函数指针 `call *%rdi` |
| 07 | `test07_indirect_jump` | 间接跳转 `jmp *%rax` |
| 08 | `test08_indirect_call_with_retval` | 间接调用 + 返回值 |
| 09 | `test09_indirect_call_multiarg` | 多参数间接调用 |
| 10 | `test10_volatile_fptr` | volatile 强制栈路径 |
| 11 | `test11_conditional_indirect` | 条件分支选择函数指针 |
| 12 | `test12_switch_style` | switch-case 分发 |
| 13 | `test13_runtime_computed_target` | 运行时数组索引 |
| 14 | `test14_ret_chain` | 嵌套调用返回链 |
| 15 | `test15_double_indirect` | 指针的指针 |
| 16 | `test16_returned_fptr_call` | call 返回值作为函数指针 |
| 17 | `test17_nested_struct_fptr` | 嵌套结构体函数指针 |
