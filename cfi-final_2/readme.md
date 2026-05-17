1.通过其他技术减少EC(等价类)(创新点)，论文[46]-[48]

2.条件跳转(switch case/if else)，
3.ebpf动态插桩(创新点)，
4.dfi细化(原来的计算有缺陷),
    从数据段读取的指令


5.前端实时数据流图,
6.针对不同程序进行大规模测试(EC等价类(安全性)/bpf时间)。
7.word,PPT


dfi_rop/dfi.py为演示程序，不计时和攻击


## 运行流程

### 环境依赖

```bash
# 安装 Python 依赖
pip install bcc capstone
```

### 步骤 1：生成 test_jump_analysis.csv

```bash
cd dfi_rop

# 1.1 反汇编 test.so
objdump -d test.so > test.txt

# 1.2 从反汇编生成跳转分析 CSV
python3 transformToCsv.py
```

### 步骤 2：生成 register DFI CSV

`dataflow_analysis.py` 对反汇编文本进行寄存器级数据流分析，生成两个 CSV：

- `register_dfi_instructions.csv` — 每条指令的寄存器 USE/DEF 及 DFI 违规信息
- `register_dfi_def_use_chains.csv` — 寄存器 def-use 链（含 eflags 条件跳转依赖）

```bash
# 从反汇编生成寄存器 DFI 分析 CSV
python3 dataflow_analysis.py test.txt register_dfi
```

### 步骤 3：运行

```bash
# 需要 root 权限（eBPF）
sudo python3 dfi.py
```

### 生成文件依赖关系

```
test.c ──gcc──▶ test.so ──objdump──▶ test.txt ──transformToCsv.py──▶ test_jump_analysis.csv
                                        │                                      │
                                        └──dataflow_analysis.py──▶ register_dfi_instructions.csv
                                                                   register_dfi_def_use_chains.csv
                                                                          │
          上述三个 CSV ─────────────────────────────────────────────────────┘
                                        │
                                        ▼
                                    dfi.py ◀── test.so
```