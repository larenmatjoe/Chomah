import ipaddress
import os
import subprocess
from pathlib import Path
BPF_MAP_PATH = "/sys/fs/bpf/blocklist_map"
IP_FILE_PATH = Path(__file__).resolve().parents[2] / "blocked_ips.txt"

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
    # One bpftool process applies every update.
    batch = [f"map update pinned {BPF_MAP_PATH} key {k} value 0x01" for k in wanted]
    subprocess.run(["bpftool", "batch", "file", "-"],
                   input="\n".join(batch) + "\n", check=True, text=True)
    for ip_str in wanted.values():
        print(f" Blocked {ip_str}")
if __name__ == "__main__":
    sync_firewall()
    print("Kernel firewall maps updated successfully")
