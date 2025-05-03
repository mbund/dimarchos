//go:build ignore

#include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

__u64 ingress_pkt_count = 0;
__u64 egress_pkt_count  = 0;

SEC("netkit/primary")
int netkit_primary(struct __sk_buff *skb) {
    bpf_printk("netkit/primary %d", ingress_pkt_count);
    __sync_fetch_and_add(&ingress_pkt_count, 1);
    return TCX_NEXT;
}

SEC("netkit/peer")
int netkit_peer(struct __sk_buff *skb) {
    bpf_printk("netkit/peer %d", egress_pkt_count);
    __sync_fetch_and_add(&egress_pkt_count, 1);
    return TCX_NEXT;
}
