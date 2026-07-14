# `xdp_firewall.c` — Line-by-Line Explanation

This is an **XDP (eXpress Data Path)** BPF program that runs in the kernel's network driver layer before the main networking stack. It drops packets from blocked IPs.

---

## Includes

```c
1: #include <linux/bpf.h>
```
Includes the BPF kernel header, which defines BPF helper function prototypes, map types, and the `xdp_md` context struct.

```c
2: #include <bpf/bpf_helpers.h>
```
Includes BPF helper macros (e.g. `SEC`, `__uint`, `__type`) used to annotate sections and define maps.

```c
3: #include <linux/if_ether.h>
```
Includes the Ethernet header struct (`struct ethhdr`) and constants like `ETH_P_IP`.

```c
4: #include <linux/ip.h>
```
Includes the IPv4 header struct (`struct iphdr`).

```c
5: #include <linux/in.h>
```
Includes IP protocol constants (e.g. `IPPROTO_TCP`, though not directly used here).

---

## Blocklist Map

```c
7: struct {
8:   __uint(type, BPF_MAP_TYPE_HASH);
9:   __uint(max_entires, 10240);
10:   __type(key, __u32);
11:   __type(value, __u8);
12: } blocklist_map SEC(".maps");
```

- `line 7-12`: Defines a **BPF hash map** named `blocklist_map` placed in the `.maps` ELF section.
- **type** = `BPF_MAP_TYPE_HASH` → a generic hash table (key → value).
- **max_entries** = 10240 → maximum 10,240 entries.
- **key** = `__u32` → a 32-bit unsigned integer (an IPv4 address).
- **value** = `__u8` → a single byte (used as a boolean flag: 1 = blocked).
- **SEC(".maps")** → the linker section that the BPF loader (e.g. `iproute2` or `libbpf`) parses to create the map at load time.

The map is populated from **userspace** (e.g. by a control-plane program that inserts IPs to block).

---

## XDP Program Entry Point

```c
14: SEC("xdp")
```
Tells the BPF loader that the following function belongs to the `"xdp"` ELF section, so it is attached as an XDP program to a network interface.

```c
15: int xdp_firewall_filter(struct xdp_md *ctx) {
```
The function name is `xdp_firewall_filter`. It receives a single argument:
- `ctx` — a pointer to `struct xdp_md`, which contains `data` (pointer to the start of the packet) and `data_end` (pointer to the end of the packet).

The return value is an `int` — one of the XDP action codes (`XDP_DROP`, `XDP_PASS`, etc.).

---

## Packet Boundary Pointers

```c
16:   void *data = (void *)(long)ctx->data;
17:   void *data_end = (void *)(long)ctx->data_end;
```

- `line 16`: Casts `ctx->data` (a `__u32` offset in some kernel versions, or a pointer) to a `void*` — the start of the raw packet data in memory.
- `line 17`: Casts `ctx->data_end` to a `void*` — the byte immediately after the end of the packet.

These two pointers define the packet's valid memory region. All pointer arithmetic must be bounds-checked against `data_end`, otherwise the BPF verifier rejects the program.

---

## Ethernet Header Parsing

```c
19:   struct ethhdr *eth = data;
```
Treats the start of the packet as an Ethernet header (`struct ethhdr`). This struct contains:
- `h_dest[6]` — destination MAC address
- `h_source[6]` — source MAC address
- `h_proto` — EtherType (e.g. `ETH_P_IP` = 0x0800 for IPv4)

```c
20:   if ((void *)(eth + 1) > data_end) return XDP_PASS;
```
**Bounds check**: `eth + 1` points just past the Ethernet header (pointer arithmetic on `struct ethhdr*` advances by `sizeof(struct ethhdr)` bytes). If that exceeds `data_end`, the packet is too short to contain a full Ethernet header → pass it through unmodified. This satisfies the BPF verifier's safety requirements.

```c
21:   if (eth->h_proto != __constant_htons(ETH_P_IP)) return  XDP_PASS;
```
Reads the EtherType field. `__constant_htons(ETH_P_IP)` converts `ETH_P_IP` (0x0800) to network byte order at compile time. If the packet is **not** IPv4, pass it through — this program only filters IPv4.

---

## IP Header Parsing

```c
23:   struct iphdr *iph = (void *)(eth + 1);
```
Points `iph` to the byte immediately after the Ethernet header — the start of the IP header.

```c
24:   if ((void *)(iph + 1) > data_end) return XDP_PASS;
```
**Bounds check**: `iph + 1` points just past the IP header (advances by `sizeof(struct iphdr)`). If the packet is too short to contain a full IP header, pass it through.

---

## Blocklist Lookup

```c
26:   __u32 src_ip = iph->saddr;
```
Reads the **source IP address** from the IP header. `iph->saddr` is a `__u32` in network byte order.

```c
27:   __u8 *is_blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
```
Calls `bpf_map_lookup_elem()` — a BPF helper that looks up `src_ip` in `blocklist_map`.
- Returns **NULL** if the key is not found.
- Returns a **pointer to the value** (`__u8`) if the key exists.

```c
29:   if (is_blocked && *is_blocked == 1) {
```
- First checks `is_blocked` is non-NULL (the key exists in the map).
- Then checks the value is exactly `1` (blocked).

```c
30:     return XDP_DROP;
```
If the source IP is blocked, return `XDP_DROP`, which causes the kernel to discard the packet immediately at the driver level — no further processing.

---

## Default Action

```c
32:   return XDP_PASS;
```
If none of the drop conditions were met, return `XDP_PASS` — the packet continues to the normal network stack.

---

## License Section

```c
35: char _license[] SEC("license") = "GPL";
```
BPF programs must declare a license in a special ELF section. GPL is required to use certain BPF helpers (like `bpf_map_lookup_elem`). Without this, the kernel may refuse to load the program or restrict helper availability.

---

## Summary

| Line(s) | Purpose |
|---------|---------|
| 1-5 | Kernel headers for BPF, Ethernet, and IP |
| 7-12 | Hash map of blocked IPs (key: `__u32`, value: `__u8`) |
| 14-15 | XDP program entry point |
| 16-17 | Packet start/end pointers |
| 19-21 | Parse Ethernet header; skip non-IPv4 |
| 23-24 | Parse IP header; bounds check |
| 26-27 | Look up source IP in blocklist map |
| 29-31 | Drop if blocked |
| 32 | Pass otherwise |
| 35 | GPL license declaration |
