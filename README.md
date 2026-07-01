# CFI/DFI 融合监控

基于 **eBPF uprobe** 的运行时安全监控系统，检测间接跳转（函数指针调用/跳转/返回）是否被劫持。

| 功能 | 说明 |
|------|------|
| **CFI 校验** | 监督间接调用/跳转/返回的目标地址是否合法，标记 is_correct |
| **DFI 追踪** | 追踪函数指针的数据流（加载→解引用→跳转），比较 saved_rax vs rax |
| **安全模式** | 正常执行程序，展示 CFI/DFI 数据流，验证不误报 |
| **攻击模式** | 8 种 ROP/shellcode 攻击，通过 eBPF + 等价类校验实时拦截 |
| **Web 面板** | 统计卡片 / 图表 / CFI 事件表 / 寄存器详情 / 程序导入 |
| **文件导入** | 上传 .c → 自动编译 → objdump → 跳转分析 → DFI 分析 → eBPF 监控 |

---

## 目录结构

```
fcfi_inal/
│
├── run.sh
├── README.md
│
├── src/                                 # 源代码
│   ├── server.py                        #   Web 服务器 + 执行管理 API
│   ├── dfi_monitor.py                   #   eBPF 融合监控（安全模式）
│   ├── dfi_rop.py                       #   ROP/shellcode 攻击检测（攻击模式）
│   ├── dataflow_analysis.py             #   静态数据流 def-use 链分析
│   ├── transformToCsv.py                #   objdump → CSV 跳转表
│   └── bpf_program.c                    #   eBPF C 程序
│
├── test/                                # 测试源文件
│   ├── test.c                           #   17 种正常间接跳转场景
│   ├── attack.c                         #   7 种 CFI 违规攻击场景
│   ├── a.c                              #   综合（17 正常 + 7 攻击）
│   └── *.c (上传文件)
│
├── web/                                 # Web 前端
│   ├── index.html
│   ├── dashboard.html
│   └── js/{main,charts,attacks}.js
│
├── build/                               # 编译产物（运行时生成，按文件名分目录）
│   └── <name>/                          #   .so / .txt / _jump_analysis.csv / _register_dfi_*.csv
│
└── output/                              # 运行时输出（按文件名分目录）
    └── <name>/                          #   run_*_cfi_events.csv / run_*_dfi_layers.csv / run_*_events.log
```

---

## 快速开始

### 环境

- Linux x86-64，Python 3.8+
- `pip install bcc capstone pwntools`

### Web 模式

```bash
cd fcfi_inal
sudo python3 src/server.py
# → http://localhost:8080          首页
# → http://localhost:8080/dashboard  控制面板
```

控制面板操作：
1. 选择测试文件
2. 选择模式：**安全模式**（正常执行）或 **攻击模式**（ROP/shellcode 攻击）
3. 攻击模式下选择攻击方式（sh / rop / exit0 / ...）
4. 点击运行 → 自动编译 → 静态分析 → eBPF 监控 → 结果展示

### 命令行

```bash
# 一键脚本
./run.sh train demo 1       # 安全模式
./run.sh -a 1 -n 1           # 攻击模式

# 手动执行
sudo python3 src/dfi_monitor.py -m train -n 1 \
    --so build/test/test.so --entry test_all \
    --csv build/test/test_jump_analysis.csv

# ROP 攻击
sudo python3 src/dfi_rop.py -a sh -m enforce
sudo python3 src/dfi_rop.py --list
```

---

## 控制面板功能

**左栏 — 监控面板**

| 组件 | 说明 |
|------|------|
| 统计卡片 | CFI 事件数 / DFI 层事件数 / 违规数 / 正确率 |
| 跳转类型饼图 | RET / INDIRECT_CALL / INDIRECT_JMP 分布 |
| DFI 层柱状图 | L1 / L2 / L3 事件分布 |
| CFI 事件表 | 搜索 / 类型过滤 / 正确/违规筛选 / 分页 |
| 寄存器详情 | 按寄存器分组，展示数值变化过程及对应指令 |

**右栏 — 控制面板**

| 组件 | 说明 |
|------|------|
| 程序选择 | 自动扫描 test/*.c，只显示文件名 |
| 模式切换 | 安全模式 ⇄ 攻击模式 |
| 攻击列表 | 8 种 ROP/shellcode 攻击，单选 |
| 执行按钮 | 编译 → 静态分析 → eBPF 监控，默认 1 次 |
| 结果展示 | 违规检测结果 / 统计摘要 / 违规事件详情 |
| 程序导入 | 上传 .c → 自动编译分析 |

---

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/summary?source=` | 监控摘要 |
| GET | `/api/cfi_events?source=&offset=&limit=&jump_type=&is_correct=&search=` | CFI 事件查询 |
| GET | `/api/dfi_events?source=` | DFI 层事件查询 |
| GET | `/api/dfi_detail?source=test` | DFI def-use 链（静态） |
| GET | `/api/programs` | 自动扫描 test/*.c 列表 |
| GET | `/api/attack_result/{task_id}` | 执行结果轮询 |
| POST | `/api/run` | 安全模式 `{program, mode:'safe', iterations}` |
| POST | `/api/rop_attack` | 攻击模式 `{attack_type, target, mode}` |
| POST | `/api/import` | 导入 .c `{filename, data(base64)}` |

---

## 测试文件

### test.c — 17 种正常场景

| # | 场景 | 间接调用模式 |
|---|------|-------------|
| 01 | 全局函数指针调用 | `call *ptr(%rip)` |
| 02 | 局部函数指针调用 | `call *%rax` |
| 03 | 函数指针表调用 | 数组索引间接 |
| 04 | 栈上函数指针 | RBP 相对寻址 |
| 05 | vtable 模拟 | 结构体成员间接 |
| 06 | 回调函数指针传参 | `call *%rdi` |
| 07 | 间接跳转（尾调用） | `jmp *%rax` |
| 08 | 带返回值的间接调用 | rax 返回值覆盖 |
| 09 | 多参数间接调用 | rdi/rsi/rdx 传参 |
| 10 | volatile 强制内存路径 | 栈加载后调用 |
| 11 | 条件选择间接调用 | jcc + 间接混合 |
| 12 | switch-case 分发 | 跳转表风格 |
| 13 | LEA 计算目标地址 | `lea → call *%rax` |
| 14 | 嵌套返回链 | 多层 call/ret |
| 15 | 双重指针间接调用 | 两级解引用 |
| 16 | 函数返回指针再调用 | 跨调用数据流 |
| 17 | 嵌套结构体函数指针 | 深层成员访问 |

### attack.c — 7 种 CFI 攻击

| # | 攻击 | 原理 |
|---|------|------|
| 01 | 全局指针劫持 | setup 合法指针 → ATTACK 篡改为 evil → saved≠rax |
| 02 | 双重指针劫持 | 二级指针间接修改调用目标 |
| 03 | 条件分支劫持 | 控制分支走入恶意路径 |
| 04 | 结构体函数指针替换 | vtable 破坏：action 成员被篡改 |
| 05 | 返回指针劫持 | 返回合法指针后被替换 |
| 06 | 堆回调替换 | malloc 后 callback 被篡改 |
| 07 | 函数指针表投毒 | 初始化表后篡改某一槽位 |

### 攻击模式 — 8 种 ROP/shellcode

| 方式 | 说明 |
|------|------|
| `sh` | pwntools /bin/sh |
| `exit0` | 安全退出 exit(0) |
| `simplenop` | NOP 滑板 + shellcode |
| `nonop` | 纯 shellcode (RIPE) |
| `polynop` | 多态 NOP + shellcode |
| `createfile` | 创建文件攻击 |
| `returnintolibc` | 返回到 libc |
| `rop` | ROP 链 execve |

---

## 检测原理

### 四层递进检测

| 层 | 方法 | 精度 |
|----|------|:--:|
| DFI 数据流 | 追踪指针从加载到跳转的完整链路，比较 saved_rax vs rax | 指令级 |
| 静态 CFI | cfi_map 白名单校验跳转目标 | 函数级 |
| 调用点敏感 (CS) | 调用栈哈希 → 历史目标集 | 1–5 目标 |
| 起源敏感 (Origin) | 指针赋值指令 → 历史目标集 | 1–2 目标 |

### DFI 核心机制

```
保存点（最早内存读取）           跳转点（L1）
mov g_ptr(%rip),%rax          call *%rax
  → saved_rax = legit_a         → rax = evil_x
                                  saved ≠ rax → 违规
```

保存点选取执行顺序**最早**的内存读取指令（RIP_REL / RBP_REL / DEREF），确保捕获函数指针的原始值。

---

## CLI 参考

```
# server.py
python3 src/server.py [-p PORT]

# dfi_monitor.py
sudo python3 src/dfi_monitor.py -m train|enforce|hybrid -n 1
    --so PATH --entry SYMBOL --csv PATH [-o PREFIX]

# dfi_rop.py
sudo python3 src/dfi_rop.py -a sh|rop|exit0|... -m enforce [--list]

# transformToCsv.py
python3 src/transformToCsv.py -i INPUT.txt -o OUTPUT.csv

# dataflow_analysis.py
python3 src/dataflow_analysis.py INPUT.txt OUTPUT_PREFIX
```
