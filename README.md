# XDP Firewall — IP Blocklist at the Driver Level

A **high-performance** XDP (eXpress Data Path) BPF program that drops packets
from blocked IP addresses at the NIC driver level — before the kernel network
stack, before connection tracking, before any socket overhead. JIT-compiled to
native instructions with O(1) hash-table lookups, it can drop millions of
packets per second at line rate.

## Files

| File | Purpose |
|------|---------|
| `xdp_firewall.c` | BPF/XDP C program — loaded into the kernel |
| `sync_firewall.py` | Userspace script — reads `blocked_ips.txt` and writes entries into the BPF map |
| `blocked_ips.txt` | One IP per line (lines starting with `#` are ignored) |
| `xdp_firewall.o` | Compiled BPF object file |
| `firewall.md` | Line-by-line explanation of `xdp_firewall.c` |

---

## Requirements

- **Linux kernel** 4.8+ with `CONFIG_BPF_SYSCALL=y` and `CONFIG_BPF=y`
- **clang** (for compiling BPF)
- **libbpf-dev** / `linux-libc-dev` (kernel + BPF headers)
- **bpftool** (typically in `linux-tools-common` or `bpftool` package)
- **Root** (or `CAP_BPF` + `CAP_NET_ADMIN`)
- `/sys/fs/bpf/` mounted as a bpf filesystem

### Install Dependencies

```bash
# Debian / Ubuntu
sudo apt install -y clang llvm linux-headers-$(uname -r) linux-tools-$(uname -r) bpftool

# Alpine
apk add clang llvm libbpf-dev linux-headers bpftool

# Arch
sudo pacman -S clang llvm bpftool linux-headers
```

---

## Quick Start

### 1. Compile the BPF program

```bash
clang -O2 -g -Wall -target bpf -c xdp_firewall.c -o xdp_firewall.o
```

### 2. Mount BPF filesystem (if not already mounted)

```bash
sudo mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true
```

### 3. Load the program and pin the map

```bash
sudo bpftool prog load xdp_firewall.o /sys/fs/bpf/xdp_firewall pinmaps /sys/fs/bpf/
```

This creates:
- `/sys/fs/bpf/xdp_firewall` — pinned program
- `/sys/fs/bpf/blocklist_map` — pinned map

### 4. Attach to a network interface

Find your interface name:
```bash
ip addr
```

Attach (generic mode — works on any driver):
```bash
sudo bpftool net attach xdp name xdp_firewall_filter dev enp7s0
```

Verify it's attached:
```bash
sudo bpftool net list
sudo ip link show enp7s0   # look for "xdpgeneric"
```

### 5. Block IPs

Edit `blocked_ips.txt`:
```
192.168.2.8
10.0.0.55
```

Run the sync script:
```bash
sudo python3 sync_firewall.py
```

### 6. Test

From the blocked machine, try to connect:
```bash
# Should fail / hang
curl http://192.168.2.2:8000
ping 192.168.2.2
```

On the host, verify the map contents:
```bash
sudo bpftool map dump pinned /sys/fs/bpf/blocklist_map
```

---

## Stopping / Removing the Firewall

### Detach from interface

```bash
sudo bpftool net detach xdp dev enp7s0
```

### Remove pinned files

```bash
sudo rm /sys/fs/bpf/xdp_firewall /sys/fs/bpf/blocklist_map
```

### Unload the program (if still loaded)

```bash
sudo bpftool prog show name xdp_firewall_filter  # note the ID
sudo bpftool prog del id <ID>
```

---

## Full Reload Cycle

Use this to rebuild, reload, and reattach after changing `xdp_firewall.c`:

```bash
clang -O2 -g -Wall -target bpf -c xdp_firewall.c -o xdp_firewall.o
sudo bpftool net detach xdp dev enp7s0 2>/dev/null || true
sudo rm /sys/fs/bpf/xdp_firewall /sys/fs/bpf/blocklist_map 2>/dev/null || true
sudo mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true
sudo bpftool prog load xdp_firewall.o /sys/fs/bpf/xdp_firewall pinmaps /sys/fs/bpf/
sudo bpftool net attach xdp name xdp_firewall_filter dev enp7s0
sudo python3 sync_firewall.py
```

---

## Managing the Blocklist

### Add an IP

```bash
echo "10.0.0.99" | sudo tee -a blocked_ips.txt
sudo python3 sync_firewall.py
```

### Remove an IP

Edit `blocked_ips.txt` to remove the line, then delete the entry from the map:

```bash
# Find the key value first
sudo bpftool map dump pinned /sys/fs/bpf/blocklist_map
# Delete the key — provide raw bytes like the sync script does
# For 192.168.2.8:
sudo bpftool map delete pinned /sys/fs/bpf/blocklist_map key 0x08 0x02 0xa8 0xc0
```

Then run the sync script again, or manually update the txt file.

---

## Troubleshooting

### Compile Error: `asm/types.h not found`

Missing kernel headers:
```bash
# Debian/Ubuntu
sudo apt install linux-headers-$(uname -r)
# Alpine
apk add linux-headers
# Arch
sudo pacman -S linux-headers
```

### Compile Error: `bpf/bpf_helpers.h not found`

Missing libbpf headers:
```bash
# Debian/Ubuntu
sudo apt install libbpf-dev
# Alpine
apk add libbpf-dev
# Arch
sudo pacman -S bpf
```

### `bpftool: command not found`

```bash
# Debian/Ubuntu
sudo apt install linux-tools-common linux-tools-$(uname -r) bpftool
# Alpine
apk add bpftool
# Arch
sudo pacman -S bpftool
```

### `Couldn't load trivial BPF program` / `-EPERM`

Causes and fixes:
1. **RLIMIT_MEMLOCK too low** → `ulimit -l unlimited` or use `bpftool` as root
2. **Kernel lacks BPF support** → check `grep CONFIG_BPF_SYSCALL /boot/config-$(uname -r)`
3. **Missing capabilities** → in containers, add `--privileged` or `--cap-add=BPF --cap-add=NET_ADMIN`

### `unknown field 'max_entires'`

Typo in source — must be `max_entries`. Fix it and recompile.

### `invalid devname eth0`

Your interface is not named `eth0`. Find the real name with `ip addr` and use that
(e.g. `enp7s0`, `wlp0s20f3`, `ens3`).

### `Underlying driver does not support XDP in native mode`

The NIC driver doesn't support hardware-offloaded or native-driver XDP.
Use generic mode instead (drop `drv` suffix):
```bash
sudo bpftool net attach xdp name xdp_firewall_filter dev enp7s0
```

### Traffic is not being blocked (program is attached)

1. **Check which interface the traffic arrives on**
   ```bash
   ip neigh | grep <blocked-ip>
   ```
   Attach XDP to that interface.

2. **Check the map contents**
   ```bash
   sudo bpftool map dump pinned /sys/fs/bpf/blocklist_map
   ```
   Verify the IP is present.

3. **Check the program is loaded and attached**
   ```bash
   sudo bpftool net list
   sudo bpftool prog show name xdp_firewall_filter
   ```

### `map not found` when running sync_firewall.py

The program hasn't been loaded yet, or the map wasn't pinned. Run:
```bash
sudo bpftool prog load xdp_firewall.o /sys/fs/bpf/xdp_firewall pinmaps /sys/fs/bpf/
```

### BPF filesystem not mounted

```bash
sudo mount -t bpf bpf /sys/fs/bpf/
```

Make it permanent by adding to `/etc/fstab`:
```
none  /sys/fs/bpf  bpf  defaults  0  0
```

---

## Useful Commands Reference

| Command | What it does |
|---------|-------------|
| `sudo bpftool net list` | Show all XDP/TX/TC attachments |
| `sudo bpftool prog show name xdp_firewall_filter` | Show program details (ID, map IDs, jited size) |
| `sudo bpftool map dump pinned /sys/fs/bpf/blocklist_map` | Dump all blocked IPs |
| `sudo bpftool map update pinned /sys/fs/bpf/blocklist_map key HEX value HEX` | Manually add an entry |
| `sudo bpftool map delete pinned /sys/fs/bpf/blocklist_map key HEX` | Manually remove an entry |
| `sudo bpftool net detach xdp dev enp7s0` | Detach XDP from interface |
| `sudo bpftool prog show` | List all loaded BPF programs |
| `sudo bpftool prog del id N` | Unload program with ID N |
| `sudo ip link show enp7s0` | Check if XDP is attached to an interface |
| `sudo cat /sys/kernel/debug/tracing/trace_pipe` | Debug output from `bpf_printk` (if added) |
| `ulimit -l unlimited` | Raise RLIMIT_MEMLOCK (fixes EPERM on load) |

---

## Architecture

```
                         ┌─────────────────────────────────────────────────┐
                         │                  Userspace                       │
                         │                                                  │
                         │  sync_firewall.py                                │
                         │    └─ bpftool map update ──► blocklist_map       │
                         │                                                  │
                         │  blocked_ips.txt (source of truth)               │
                         └──────────────┬──────────────────────────────────┘
                                        │
                      ┌─────────────────▼──────────────────────┐
                      │             Kernel / BPF                │
                      │                                         │
                      │  blocklist_map (BPF_MAP_TYPE_HASH)      │
                      │    key: __u32 (IP, host byte order)     │
                      │    value: __u8 (1 = blocked)            │
                      │         ▲                               │
                      │         │ lookup                         │
                      │  ┌──────┴──────┐                        │
                      │  │ xdp_firewall_filter                  │
                      │  │  (XDP program)                       │
                      │  └──────┬──────┘                        │
                      └─────────┼───────────────────────────────┘
                                │
          Packet ───────────────▼──────────────────────────────► Stack
               incoming     XDP_DROP?                     XDP_PASS
```

The XDP program runs on **every incoming packet** on the attached interface.
It parses the Ethernet + IP headers, looks up the source IP in the
`blocklist_map`, and either drops (`XDP_DROP`) or passes (`XDP_PASS`).

---

## Notes

- **XDP drops at ingress only** — it cannot block locally-originated
  outgoing traffic, only packets arriving on the interface.
- **Generic mode** (`xdpgeneric`) works on any NIC but has slightly more
  overhead than native/driver mode (`xdpdrv`).
- The BPF map persists until the program is unloaded or the system reboots.
  For a persistent setup, add the load/attach commands to a systemd service
  or init script.
- The `blocked_ips.txt` file is the source of truth — the map is rebuilt
  from it each time `sync_firewall.py` runs.
