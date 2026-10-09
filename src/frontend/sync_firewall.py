import ipaddress
import json
import os
import subprocess
from pathlib import Path
BPF_MAP_PATH = "/sys/fs/bpf/blocklist_map"
IP_FILE_PATH = Path(__file__).resolve().parents[2] / "blocked_ips.txt"

def read_map_keys() -> set[str]:
    dump = subprocess.run(
        ["bpftool", "-j", "map", "dump", "pinned", BPF_MAP_PATH],
        check=True, capture_output=True, text=True,
    )
    # Each entry's "key" is a list of byte strings such as ["0x08", "0x02", ...].
    return {" ".join(f"0x{int(b, 16):02x}" for b in entry["key"])
            for entry in json.loads(dump.stdout)}

def sync_firewall():
    if not os.path.exists(BPF_MAP_PATH):
        print("Firewall map not found")
        return
    print("Reading blocklist")
    wanted = {}
    with open(IP_FILE_PATH, "r") as file:
        for line in file:
            ip_str = line.strip()
            if not ip_str or ip_str.startswith('#'):
                continue
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                raw_bytes = ip_obj.packed
                hex_bytes = " ".join(f"0x{b:02x}" for b in reversed(raw_bytes))
                wanted[hex_bytes] = ip_str

            except ValueError:
                print(f"Error at {line}")
    stale = read_map_keys() - wanted.keys()
    # One bpftool process applies every update and delete.
    batch = [f"map update pinned {BPF_MAP_PATH} key {k} value 0x01" for k in wanted]
    batch += [f"map delete pinned {BPF_MAP_PATH} key {k}" for k in stale]
    subprocess.run(["bpftool", "batch", "file", "-"],
                   input="\n".join(batch) + "\n", check=True, text=True)
    for ip_str in wanted.values():
        print(f" Blocked {ip_str}")
    for key in stale:
        # Keys hold the address in host byte order, and this script assumes a
        # little-endian host, so reversing the bytes recovers network order.
        ip_obj = ipaddress.IPv4Address(bytes(int(b, 16) for b in reversed(key.split())))
        print(f" Unblocked {ip_obj}")
if __name__ == "__main__":
    sync_firewall()
    print("Kernel firewall maps updated successfully")
