import ipaddress
import os
import subprocess
BPF_MAP_PATH = "/sys/fs/bpf/blocklist_map"
IP_FILE_PATH = "blocked_ips.txt"

def sync_firewall():
    if not os.path.exists(BPF_MAP_PATH):
        print("Firewall map not found")
        return
    print("Reading blocklist")
    with open(IP_FILE_PATH, "r") as file:
        for line in file:
            ip_str = line.strip()
            if not ip_str or ip_str.startswith('#'):
                continue
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                raw_bytes = ip_obj.packed
                hex_bytes = " ".join(f"0x{b:02x}" for b in reversed(raw_bytes))
                cmd = f"sudo bpftool map update pinned {BPF_MAP_PATH} key {hex_bytes} value 0x01"
                subprocess.run(cmd, shell=True, check=True)
                print(f" Blocked {ip_str}")

            except ValueError:
                print(f"Error at {line}")
if __name__ == "__main__":
    sync_firewall()
    print("Kernel firewall maps updated successfully")
