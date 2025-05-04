//go:build ignore

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

__u64 ingress_pkt_count = 0;
__u64 egress_pkt_count  = 0;

#define IP4_TO_BE32(a, b, c, d) ((__be32)(((d) << 24) + ((c) << 16) + ((b) << 8) + (a)))

#define CONTAINER_IP IP4_TO_BE32(173, 18, 0, 5)
#define HOST_IP IP4_TO_BE32(10, 23, 29, 109)
#define SERVER_IP IP4_TO_BE32(1, 1, 1, 1)

SEC("netkit/primary")
int netkit_primary(struct __sk_buff *skb) {
    // bpf_printk("netkit/primary %d", ingress_pkt_count);
    __sync_fetch_and_add(&ingress_pkt_count, 1);

    void *data_end = (void *)(__u64)skb->data_end;
    void *data     = (void *)(__u64)skb->data;

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TCX_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TCX_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TCX_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return TCX_PASS;

    bpf_printk("netkit/primary: %pI4 -> %pI4", &ip->saddr, &ip->daddr);

    return TCX_PASS;
}

SEC("netkit/peer")
int netkit_peer(struct __sk_buff *skb) {
    // bpf_printk("netkit/peer %d", egress_pkt_count);
    __sync_fetch_and_add(&egress_pkt_count, 1);

    void *data_end = (void *)(__u64)skb->data_end;
    void *data     = (void *)(__u64)skb->data;

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TCX_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TCX_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TCX_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return TCX_PASS;

    bpf_printk("netkit/peer: %pI4 -> %pI4", &ip->saddr, &ip->daddr);

    if (ip->daddr == SERVER_IP) {
        return bpf_redirect_neigh(2, NULL, 0, 0);
    }

    return TCX_PASS;
}
