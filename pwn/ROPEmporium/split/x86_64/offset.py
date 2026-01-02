#!/usr/bin/env python3
from pwn import *

# Auto-find offset
p = process("./split")
p.sendline(cyclic(500))
p.wait()

core = p.corefile
offset = cyclic_find(core.read(core.rsp, 8))
print(f"Offset: {offset}")
