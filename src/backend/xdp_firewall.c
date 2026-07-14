#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, __u8);
} blocklist_map SEC(".maps");

SEC("xdp")
int xdp_firewall_filter(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return XDP_PASS;
  if (eth->h_proto != __constant_htons(ETH_P_IP)) return  XDP_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) return XDP_PASS;

  __u32 src_ip = __builtin_bswap32(iph->saddr);
  __u8 *is_blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);

  if (is_blocked && *is_blocked == 1) {
    return XDP_DROP;
  }
  return XDP_PASS;

}
char _license[] SEC("license") = "GPL";
