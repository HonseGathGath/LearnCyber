#!/usr/bin/env python3

# Array 1 bytes (32 bytes)
array1 = [
    0x5e, 0x36, 0x32, 0x28, 0x41, 0x79, 0x26, 0x33,
    0x60, 0x72, 0x37, 0x6a, 0x7c, 0x51, 0x7d, 0x3e
]
# Note: The decompilation shows 16 bytes for array1, but loop runs until &var_78h
# Let me check the actual memory layout...

# Actually, looking at the loop condition (piVar3 != &var_78h)
# and the fact that piVar3 starts at &iStack_88
# The loop runs 16 times (16 bytes per array)

# Array 2 bytes
array2 = [
    0x36, 0x69, 0x75, 0x37, 0x28, 0x69, 0x55, 0x42,
    0x70, 0x44, 0x24, 0x39, 0x4b, 0x6c, 0x49, 0x43
]

# Array 3 bytes  
array3 = [
    0x3a, 0x76, 0x54, 0x33, 0x3f, 0x5b, 0x5a, 0x7d,
    0x63, 0x56, 0x27, 0x6f, 0x66, 0x38, 0x3f, 0x43
]

# Array 4 bytes
array4 = [
    0x33, 0x4b, 0x70, 0x2a, 0x33, 0x2b, 0x4e, 0x64,
    0x6a, 0x78, 0x5f, 0x29, 0x40, 0x6b, 0x64, 0x4e
]

# Compute the flag: array1[i] ^ array2[i] ^ array3[i] ^ array4[i] ^ 0x20
flag = ""
for i in range(16):
    # XOR all four arrays with 0x20
    char_val = array1[i] ^ array2[i] ^ array3[i] ^ array4[i] ^ 0x20
    flag += chr(char_val)
    print(f"Position {i:2d}: {array1[i]:02x} ^ {array2[i]:02x} ^ {array3[i]:02x} ^ {array4[i]:02x} ^ 20 = {char_val:02x} ('{chr(char_val)}')")

print(f"\n🔑 Flag: {flag}")
print(f"   Command: ./crackme \"{flag}\"")

# Let's also try if array1 has more than 16 bytes
# The loop runs until piVar3 != &var_78h
# Starting address: &iStack_88
# Ending address: &var_78h
# In 64-bit, addresses are 8 bytes apart
# So (&var_78h - &iStack_88) / 8 = number of iterations?
# Actually, piVar3 is incremented by 1 (byte pointer), not 8
