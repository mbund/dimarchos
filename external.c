//go:build ignore

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

volatile __u32 netkit_ifindex = 0;

#define IP4_TO_BE32(a, b, c, d) ((__be32)(((d) << 24) + ((c) << 16) + ((b) << 8) + (a)))

#define CONTAINER_IP IP4_TO_BE32(173, 18, 0, 5)
#define HOST_IP IP4_TO_BE32(10, 23, 29, 109)
#define SERVER_IP IP4_TO_BE32(1, 1, 1, 1)

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define IS_PSEUDO 0x10

static inline void set_tcp_ip_src(struct __sk_buff *skb, __u32 old_ip, __u32 new_ip) {
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &new_ip, sizeof(new_ip), 0);
}

static inline void set_tcp_ip_dst(struct __sk_buff *skb, __u32 old_ip, __u32 new_ip) {
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, IP_DST_OFF, &new_ip, sizeof(new_ip), 0);
}

SEC("tcx/ingress")
int tcx_ingress(struct __sk_buff *skb) {
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

    if (ip->saddr == SERVER_IP) {
        bpf_printk("tcx/ingress: rewriting %pI4 -> %pI4", &ip->saddr, &ip->daddr);
        set_tcp_ip_dst(skb, HOST_IP, CONTAINER_IP);
        bpf_printk("tcx/ingress: rewrote %pI4 -> %pI4", &ip->saddr, &ip->daddr);
        return bpf_redirect_peer(netkit_ifindex, 0);
    }

    return TCX_PASS;
}

SEC("tcx/egress")
int tcx_egress(struct __sk_buff *skb) {
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

    if (ip->saddr == CONTAINER_IP) {
        bpf_printk("tcx/egress: rewriting %pI4 -> %pI4", &ip->saddr, &ip->daddr);
        set_tcp_ip_src(skb, CONTAINER_IP, HOST_IP);
        bpf_printk("tcx/egress: rewrote %pI4 -> %pI4", &ip->saddr, &ip->daddr);
    }

    return TCX_PASS;
}
