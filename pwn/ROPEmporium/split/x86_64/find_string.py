from pwn import *

elf = ELF("./split")
print(hex(next(elf.search(b"/bin/cat flag.txt"))))
print(hex(elf.plt["system"]))
