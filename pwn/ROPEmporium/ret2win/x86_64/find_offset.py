#!/usr/bin/env python3
from pwn import *
import time
import sys


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)

    binary = sys.argv[1]

    # Check if binary exists and is executable
    if not os.path.exists(binary):
        print(f"[-] Binary {binary} not found")
        sys.exit(1)

    # Wait if binary is busy
    for _ in range(5):
        try:
            elf = ELF(binary)
            print(f"[*] Binary: {binary}")
            print(f"[*] Arch: {elf.arch}")
            print(f"[*] Bits: {elf.bits}")
            break
        except Exception as e:
            print(f"[!] Could not load binary, retrying... ({e})")
            time.sleep(0.5)

    # Method 1: Use debugger
    print("\n[+] Method 1: Using debugger")
    try:
        p = gdb.debug(
            binary,
            """
            break main
            run
            continue
        """,
        )
        pattern = cyclic(200)
        p.sendline(pattern)
        p.wait_for_close()

        if p.corefile:
            if elf.bits == 32:
                eip = p.corefile.eip
                offset = cyclic_find(eip & 0xFFFFFFFF)
            else:
                rip = p.corefile.rip
                offset = cyclic_find(rip & 0xFFFFFFFF)

            if offset != -1:
                print(f"[✓] Offset found: {offset} bytes")
                return offset
    except:
        pass

    # Method 2: Manual pattern testing
    print("\n[+] Method 2: Manual pattern testing")
    pattern_sizes = [100, 200, 300, 500]

    for size in pattern_sizes:
        print(f"[*] Testing pattern size: {size}")
        try:
            # Make sure no process is running
            os.system("pkill -f " + binary.split("/")[-1] + " 2>/dev/null")
            time.sleep(0.2)

            p = process(binary, stdin=PTY)
            pattern = cyclic(size)
            p.sendline(pattern)

            # Check if crashed
            try:
                p.recv(timeout=0.5)
                p.close()
                print(f"  [-] No crash with {size} bytes")
            except:
                print(f"  [+] Crash with {size} bytes!")

                # Try to find exact offset with binary search
                low = max(0, size - 100)
                high = size
                while low <= high:
                    mid = (low + high) // 2
                    try:
                        p = process(binary, stdin=PTY)
                        p.sendline(cyclic(mid))
                        try:
                            p.recv(timeout=0.3)
                            p.close()
                            low = mid + 1  # No crash
                        except:
                            p.close()
                            high = mid - 1  # Crash
                            exact_offset = mid
                    except:
                        pass

                print(f"[✓] Exact offset: {exact_offset} bytes")
                return exact_offset

        except Exception as e:
            print(f"  [!] Error: {e}")
            continue

    print("\n[!] Could not determine offset automatically")
    return None


if __name__ == "__main__":
    main()
