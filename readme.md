其他ko模块的验证也部分完成
前端已经部分完成
TODO:处理逻辑要完善:

本质虚拟机.
rax rbx是否被篡改？是,每次的寄存器状态不完全一致.
我知道该位置静态cfi的代码/运行时我知道寄存器的状态与该位置的代码. 已完成.
挂载的第二个字节开始
内核栈情况

关于间接跳转的检验

1. 寄存器间接（最常见）
目标地址直接存储在寄存器中：

assembly
jmp *rax      # 目标地址 = RAX的值
call *rcx     # 目标地址 = RCX的值
jmp *r8       # 目标地址 = R8的值
计算方式：target = 寄存器的值

2. 内存间接（通过寄存器寻址）
目标地址存储在内存中，内存地址由寄存器计算得出：

assembly
jmp *(%rax)               # 目标地址 = [RAX]
jmp *0x10(%rbx)           # 目标地址 = [RBX + 0x10]
jmp *(,%rsi,8)            # 目标地址 = [RSI * 8]
jmp *0x20(%rsp,%rcx,4)    # 目标地址 = [RSP + RCX*4 + 0x20]
计算方式：

先计算内存地址：mem_addr = base_reg + index_reg*scale + displacement

再从该内存地址读取目标：target = [mem_addr]

3. RIP相对寻址（特殊形式）
assembly
jmp *0x123456(%rip)       # 目标地址 = [RIP + 0x123456]
计算方式：mem_addr = RIP + displacement，然后读取内存

4. 绝对地址（较少见）
assembly
jmp *0x12345678            # 目标地址 = [0x12345678]
但即使这种形式，在64位模式下通常也需要通过寄存器间接实现。


处理方式:根据解析出的 ModRM、SIB、位移计算实际目标

目前有E8 E9与返回指令C2 C3 CA CB 间接跳转/调用 (FF /2, /3, /4, /5)未解决
E8 E9的前4位有问题 E8都指向call 0x5f0001，E9的都是cc cc cc cc(占位指令)
返回指令C2 C3 CA CB与间接跳转/调用 (FF /2, /3, /4, /5)需要构造
cfi_simple.py的前4位是乱码