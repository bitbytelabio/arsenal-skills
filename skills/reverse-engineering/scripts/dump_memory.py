#!/usr/bin/env python3
"""
dump_memory.py - Live process and container memory region dumper.
Provides safe, passive memory extraction for Linux (/proc/<pid>/mem), macOS (mach vm / lldb),
and Windows minidumps for unpacking, decrypted payload carving, and heap inspection.
"""

import argparse
import os
import re
import subprocess
import sys


def dump_linux_proc_mem(pid, output_dir, permissions_filter="w"):
    """
    Dumps memory mappings of a Linux process matching specific permissions (default: writable 'w' or 'all').
    """
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    if not os.path.exists(maps_path) or not os.path.exists(mem_path):
        print(
            f"[!] Error: /proc/{pid} maps or mem not found. Are you root/owner?",
            file=sys.stderr,
        )
        return False

    os.makedirs(output_dir, exist_ok=True)
    regions_dumped = 0

    print(f"[*] Reading memory maps for PID {pid} from {maps_path}...")
    with open(maps_path, "r") as maps_file:
        for line in maps_file:
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            addr_range = parts[0]
            perms = parts[1]
            pathname = parts[5] if len(parts) > 5 else "[anon]"

            # Check permissions filter
            match = True
            for char in permissions_filter:
                if char not in perms:
                    match = False
                    break

            if not match and permissions_filter != "all":
                continue

            start_str, end_str = addr_range.split("-")
            start_addr = int(start_str, 16)
            end_addr = int(end_str, 16)
            region_size = end_addr - start_addr

            # Cap single segment dump at 256MB to avoid out-of-memory or huge disk fills
            if region_size > 256 * 1024 * 1024:
                print(
                    f"[-] Skipping oversized region {addr_range} ({region_size / (1024*1024):.2f} MB)"
                )
                continue

            safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", pathname.strip("[]"))
            out_filename = os.path.join(
                output_dir, f"mem_{start_str}_{end_str}_{perms}_{safe_name}.bin"
            )

            try:
                with open(mem_path, "rb", buffering=0) as mem_file:
                    mem_file.seek(start_addr)
                    chunk = mem_file.read(region_size)
                    if chunk:
                        with open(out_filename, "wb") as out_file:
                            out_file.write(chunk)
                        print(
                            f"[+] Dumped {addr_range} ({perms}) {pathname} -> {out_filename} ({len(chunk)} bytes)"
                        )
                        regions_dumped += 1
            except (IOError, OSError):
                # Some kernel regions or guard pages may fail to read
                pass

    print(
        f"[*] Completed: Dumped {regions_dumped} memory regions to {output_dir}"
    )
    return regions_dumped > 0


def dump_macos_mach(pid, output_dir):
    """
    Uses lldb or vmmap on macOS to dump process memory ranges safely.
    """
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, f"process_{pid}.core")
    print(f"[*] Dumping macOS PID {pid} memory using lldb...")
    cmd = [
        "lldb",
        "--batch",
        "-o",
        f"process attach --pid {pid}",
        "-o",
        f"process save-core {out_file}",
        "-o",
        "detach",
        "-o",
        "quit",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            print(
                f"[+] Dumped full core to {out_file} ({os.path.getsize(out_file)} bytes)"
            )
            return True
        else:
            print(f"[-] LLDB core dump failed: {res.stderr}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"[!] Error executing lldb: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="dump_memory.py - Process memory extraction tool"
    )
    parser.add_argument("pid", type=int, help="Target process PID")
    parser.add_argument(
        "-o",
        "--output",
        default="memory_dump",
        help="Output directory (default: memory_dump)",
    )
    parser.add_argument(
        "-p",
        "--perms",
        default="w",
        help="Permissions filter on Linux (e.g. 'w' for writable/heap, 'rwx', 'r-x', 'all')",
    )
    parser.add_argument(
        "--gdb", action="store_true", help="Use GDB gcore fallback on Linux"
    )

    args = parser.parse_args()

    success = False
    if sys.platform.startswith("linux"):
        if args.gdb:
            os.makedirs(args.output, exist_ok=True)
            core_out = os.path.join(args.output, f"core_{args.pid}")
            cmd = ["gcore", "-o", core_out, str(args.pid)]
            res = subprocess.run(cmd)
            success = (res.returncode == 0)
        else:
            success = dump_linux_proc_mem(args.pid, args.output, args.perms)
    elif sys.platform == "darwin":
        success = dump_macos_mach(args.pid, args.output)
    elif sys.platform == "win32":
        print(
            "[!] Windows memory dumping should be performed using procdump.exe or WinDbg .dump command.",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print(f"[!] Unsupported platform: {sys.platform}", file=sys.stderr)
        sys.exit(1)

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
