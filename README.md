# CFI/DFI 融合监控

基于 eBPF uprobe，在挂载探针中**同时监督控制流（CFI）并记录数据流（DFI）**。默认静默运行，事件写入文件，终端仅显示进度和总结。

## 目录结构

```
final/
├── README.md
├── run.sh                          # 一键脚本
├── src/                            # 源程序
│   ├── dfi_monitor.py              #   融合主程序
│   ├── server.py                   #   动态 Web 可视化服务器
│   ├── generate_view.py            #   静态 HTML 可视化生成器
│   ├── dataflow_analysis.py        #   静态数据流分析
│   ├── transformToCsv.py           #   objdump → CSV 转换
│   └── test.c                      #   实验程序（17 种场景）
├── build/                          # 中间文件（编译 + 静态分析产物）
│   ├── test.so                     #   ← gcc
│   ├── test.txt                    #   ← objdump
│   ├── test_jump_analysis.csv      #   ← transformToCsv.py
│   └── register_dfi_*.csv          #   ← dataflow_analysis.py
└── output/                         # 运行时输出
    ├── {prefix}_dfi_layers.csv     #   数据流记录
    ├── {prefix}_cfi_events.csv     #   控制流记录
    ├── {prefix}_events.log         #   完整事件日志
    ├── {prefix}_viewer.html        #   静态可视化页面
    └── cfi_training_data.json      #   train 模式产出
```

## 快速开始

```bash
cd final
pip install bcc capstone

# 一键运行（默认 train 模式，3 次迭代）
./run.sh

# 指定模式、前缀、迭代次数
./run.sh train   my_exp 5     # 训练，5 次
./run.sh enforce my_exp 10    # 强制，10 次
```

`run.sh` 自动完成 5 步：编译 → 反汇编 → 跳转分析 → 数据流分析 → 运行时监控。

## 手动运行

```bash
# 1. 编译 + 静态分析
gcc -shared -fPIC -O0 -o build/test.so src/test.c
objdump -d build/test.so > build/test.txt
python3 src/transformToCsv.py
python3 src/dataflow_analysis.py build/test.txt build/register_dfi

# 2. 启动监控
sudo python3 src/dfi_monitor.py -m train -o demo          # 默认 3 次
sudo python3 src/dfi_monitor.py -m train -o demo -n 10    # 10 次
sudo python3 src/dfi_monitor.py -m train -o demo -v       # 终端显示详情
```

## dfi_monitor.py 用法

```
sudo python3 src/dfi_monitor.py [-m MODE] [-o PREFIX] [-n N] [-v]

-m, --mode       模式（默认 train）
  train         收集 CS/Origin 训练数据
  enforce       基于训练数据强制校验
  hybrid        自适应混合

-o, --output     输出前缀（默认 cfi_runtime_record）

-n, --iterations test_all() 执行次数（默认 3，0=无限循环）

-v, --verbose    终端显示详细事件（默认仅写入日志）
```

## Web 可视化

```bash
# 启动动态 Web 服务器（固定端口 8080）
python3 src/server.py

# 生成静态 HTML（无需服务器）
python3 src/generate_view.py -p demo
# → output/demo_viewer.html，浏览器直接打开
```

**动态页面**功能：
- 统计卡片（CFI/DFI 事件数、违规数、正确率）
- Chart.js 图表（跳转类型饼图、DFI 层柱状图、正确率折线图）
- CFI 事件表（搜索、类型过滤、分页）
- DFI 数据流链展示（每站点 L1→L2→L3）
- 手动刷新按钮，不自动轮询

## 运行时输出

| 输出 | 路径 | 说明 |
|------|------|------|
| 进度条 | 终端 | `CFI: 200 \| DFI: 168 \| 违规: 12` |
| 事件日志 | `output/{prefix}_events.log` | 所有 CFI/DFI 事件详情 |
| 数据流 CSV | `output/{prefix}_dfi_layers.csv` | L1/L2/L3：reg_value、target_addr、instr_type |
| 控制流 CSV | `output/{prefix}_cfi_events.csv` | 全部寄存器、is_correct、CS/Origin |
| 训练数据 | `output/cfi_training_data.json` | train 模式产出 |
| 可视化 | `output/{prefix}_viewer.html` | 静态 HTML 页面 |

## test.c 场景（17 种）

| # | 场景 | 数据流特征 |
|---|------|-----------|
| 01 | 全局函数指针调用 | GOT 间接 (`call *ptr(%rip)`) |
| 02 | 局部函数指针调用 | 寄存器间接 (`call *%rax`) |
| 03 | 函数指针表调用 | `mov array(%rip),%rax → call *%rax` |
| 04 | 栈上函数指针调用 | RBP 相对寻址 (`mov -N(%rbp),%rax`) |
| 05 | vtable 模拟 | 结构体成员函数指针 |
| 06 | 回调函数指针传参 | rdi 传入 → `call *%rdi` |
| 07 | 间接跳转 | jmp *%reg（尾调用） |
| 08 | 带返回值的间接调用 | rax 返回值覆盖验证 |
| 09 | 多参数间接调用 | rdi/rsi/rdx 传参 |
| 10 | volatile 函数指针 | 强制内存路径 |
| 11 | 条件选择间接调用 | jcc + 间接调用混合 |
| 12 | switch-case 分发 | 跳转表风格 |
| 13 | LEA 计算目标地址 | `lea target(%rip),%rax → call *%rax` |
| 14 | 嵌套返回链 | 多层 call/ret，返回地址栈追踪 |
| 15 | 双重指针间接调用 | `mov (%rax),%rax → call *%rax` |
| 16 | 函数返回指针再调用 | rax 由上层 call 定义 |
| 17 | 嵌套结构体函数指针 | 多层 struct 成员 |

## 核心机制

### 三层 DFI 数据流

```
L3 (指针加载)  →  L2 (解引用)  →  L1 (间接跳转)  →  校验
mov 0x2f(%rip),%rax  mov (%rax),%rbx  call *%rbx     target ∈ func_heads?
```

### 等价类缩小

| 级别 | 合法目标数 | 方法 |
|------|-----------|------|
| 全地址空间 | 2⁴⁸ | — |
| 静态 EC | ~数百 | func_heads 集合 |
| 调用点敏感 (CS) | 1-5 | 调用栈哈希 → 历史目标集 |
| 起源敏感 (Origin) | 1-2 | 指针赋值指令 → 历史目标集 |

### 运行模式

| 模式 | 行为 |
|------|------|
| `train` | 收集正常运行的 CS/Origin → `output/cfi_training_data.json` |
| `enforce` | 加载训练数据，违规即 `SIGKILL` |
| `hybrid` | 自适应选择策略（EC 越小越严格） |
