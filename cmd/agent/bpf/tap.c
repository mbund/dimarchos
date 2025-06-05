//go:build ignore

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define unlikely(x) __builtin_expect(!!(x), 0)

struct arphdr {
    __be16 ar_hrd;        /* format of hardware address	*/
    __be16 ar_pro;        /* format of protocol address	*/
    unsigned char ar_hln; /* length of hardware address	*/
    unsigned char ar_pln; /* length of protocol address	*/
    __be16 ar_op;         /* ARP opcode (command)		*/
};

SEC("tcx/ingress")
int tcx_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(__u64)skb->data_end;
    void *data     = (void *)(__u64)skb->data;

    if (skb->protocol == bpf_htons(ETH_P_ARP)) {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return TCX_PASS;

        struct arphdr *arp = (struct arphdr *)(eth + 1);
        if ((void *)(arp + 1) > data_end)
            return TCX_PASS;

        bpf_printk("tcx/ingress tap: arp: op: %d, ifindex %d, ingress_ifindex %d", arp->ar_op, skb->ifindex, skb->ingress_ifindex);
    } else if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return TCX_PASS;

        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TCX_PASS;

        bpf_printk("tcx/ingress tap: ip: %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);
    } else {
        bpf_printk("tcx/ingress tap: unknown: ifindex %d, ingress_ifindex %d", skb->ifindex, skb->ingress_ifindex);
    }

    return TCX_PASS;
}

SEC("tcx/egress")
int tcx_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(__u64)skb->data_end;
    void *data     = (void *)(__u64)skb->data;

    if (skb->protocol == bpf_htons(ETH_P_ARP)) {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return TCX_PASS;

        struct arphdr *arp = (struct arphdr *)(eth + 1);
        if ((void *)(arp + 1) > data_end)
            return TCX_PASS;

        bpf_printk("tcx/egress tap: arp: op: %d, ifindex %d, ingress_ifindex %d", arp->ar_op, skb->ifindex, skb->ingress_ifindex);
    } else if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return TCX_PASS;

        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TCX_PASS;

        bpf_printk("tcx/egress tap: ip: %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);
    } else {
        bpf_printk("tcx/egress tap: unknown: ifindex %d, ingress_ifindex %d", skb->ifindex, skb->ingress_ifindex);
    }

    return TCX_PASS;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data     = (void *)(__u64)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        struct arphdr *arp = (struct arphdr *)(eth + 1);
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;

        bpf_printk("xdp tap: arp: op: %d", arp->ar_op);
    } else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        bpf_printk("xdp tap: ip: %pI4 -> %pI4", &ip->saddr, &ip->daddr);

        // struct bpf_fib_lookup params = {
        //     .ipv4_src = ip->saddr,
        //     .ipv4_dst = ip->daddr,
        // };

        // long ret = bpf_fib_lookup(ctx, &params, sizeof(params), 0);
        // bpf_printk("xdp tap: ret: %d", ret);
    } else {
        bpf_printk("xdp tap: unknown");
    }

    return XDP_PASS;
}
