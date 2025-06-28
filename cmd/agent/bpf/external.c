//go:build ignore

#include "linux/types.h"
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define IP4_TO_BE32(a, b, c, d) ((__be32)(((d) << 24) + ((c) << 16) + ((b) << 8) + (a)))

#define HOST_IP IP4_TO_BE32(10, 19, 27, 26)
#define API_SERVER_IP IP4_TO_BE32(169, 254, 169, 254)

#define unlikely(x) __builtin_expect(!!(x), 0)

struct nat_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
};

struct nat_value {
    __be32 new_src_ip;
    __be16 new_src_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 55535);
    __type(key, struct nat_key);
    __type(value, struct nat_value);
} nat_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __be32);  // ipv4 address
    __type(value, __u32); // netkit ifindex
} ip_to_container SEC(".maps");

static __always_inline struct nat_value *source_nat(struct iphdr *ip, __be16 src_port, __be16 dst_port) {
    bpf_printk("tcx/ingress: will nat %pI4:%d -> %pI4:%d %s", &ip->saddr, __builtin_bswap16(src_port), &ip->daddr, __builtin_bswap16(dst_port), ip->protocol == IPPROTO_TCP ? "tcp" : "udp");

    struct nat_key key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto    = ip->protocol,
    };

    struct nat_value *entry = bpf_map_lookup_elem(&nat_table, &key);
    if (!entry) {
        struct nat_value new_entry = {
            .new_src_ip   = HOST_IP,
            .new_src_port = bpf_htons(10000 + (bpf_ktime_get_ns() % 55535)),
        };
        bpf_map_update_elem(&nat_table, &key, &new_entry, BPF_ANY);
        entry = &new_entry;
        bpf_printk("tcx/egress: inserting nat %pI4:%d -> %pI4:%d %s, new src %pI4:%d", &key.src_ip, __builtin_bswap16(key.src_port), &key.dst_ip, __builtin_bswap16(key.dst_port), ip->protocol == IPPROTO_TCP ? "tcp" : "udp", &entry->new_src_ip, __builtin_bswap16(entry->new_src_port));
        struct nat_key reverse_key = {
            .src_ip   = ip->daddr,
            .dst_ip   = HOST_IP,
            .src_port = dst_port,
            .dst_port = new_entry.new_src_port,
            .proto    = ip->protocol,
        };
        struct nat_value reverse_new_entry = {
            .new_src_ip   = ip->saddr,
            .new_src_port = src_port,
        };
        bpf_map_update_elem(&nat_table, &reverse_key, &reverse_new_entry, BPF_ANY);
        bpf_printk("tcx/egress: inserting reverse nat %pI4:%d -> %pI4:%d %s, new src %pI4:%d", &reverse_key.src_ip, __builtin_bswap16(reverse_key.src_port), &reverse_key.dst_ip, __builtin_bswap16(reverse_key.dst_port), ip->protocol == IPPROTO_TCP ? "tcp" : "udp", &reverse_new_entry.new_src_ip, __builtin_bswap16(reverse_new_entry.new_src_port));
    } else {
        bpf_printk("tcx/egress: nat found %pI4:%d -> %pI4:%d %s, new src %pI4:%d", &key.src_ip, __builtin_bswap16(key.src_port), &key.dst_ip, __builtin_bswap16(key.dst_port), ip->protocol == IPPROTO_TCP ? "tcp" : "udp", &entry->new_src_ip, __builtin_bswap16(entry->new_src_port));
    }

    return entry;
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

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TCX_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if (unlikely((void *)(tcp + 1) > data_end))
            return TCX_PASS;

        struct nat_key key = {
            .src_ip   = ip->saddr,
            .dst_ip   = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
            .proto    = ip->protocol,
        };

        // bpf_printk("tcx/ingress: trying nat %pI4:%d -> %pI4:%d %s", &key.src_ip, __builtin_bswap16(key.src_port), &key.dst_ip, __builtin_bswap16(key.dst_port), ip->protocol == IPPROTO_TCP ? "tcp" : "udp");

        struct nat_value *entry = bpf_map_lookup_elem(&nat_table, &key);
        if (!entry)
            return TCX_PASS;

        bpf_printk("tcx/ingress: tcp %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);

        bpf_printk("tcx/ingress: nat found %pI4:%d -> %pI4:%d %s, new src %pI4:%d", &key.src_ip, __builtin_bswap16(key.src_port), &key.dst_ip, __builtin_bswap16(key.dst_port), ip->protocol == IPPROTO_TCP ? "tcp" : "udp", &entry->new_src_ip, __builtin_bswap16(entry->new_src_port));

        ip->daddr = entry->new_src_ip;
        tcp->dest = entry->new_src_port;
        bpf_printk("tcx/ingress: nat rewrote %pI4:%d -> %pI4:%d %s", &ip->saddr, __builtin_bswap16(tcp->source), &ip->daddr, __builtin_bswap16(tcp->dest), ip->protocol == IPPROTO_TCP ? "tcp" : "udp");
        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), key.dst_ip, entry->new_src_ip, sizeof(__be32));
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), key.dst_ip, entry->new_src_ip, sizeof(__be32) | BPF_F_PSEUDO_HDR);
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), key.dst_port, entry->new_src_port, sizeof(__be16));

        __u32 *netkit_ifindex = bpf_map_lookup_elem(&ip_to_container, &entry->new_src_ip);
        if (unlikely(!netkit_ifindex))
            return TCX_PASS;

        bpf_printk("tcx/ingress: tcp netkit_ifindex %d", *netkit_ifindex);
        return bpf_redirect_peer(*netkit_ifindex, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if (unlikely((void *)(udp + 1) > data_end))
            return TCX_PASS;

        struct nat_key key = {
            .src_ip   = ip->saddr,
            .dst_ip   = ip->daddr,
            .src_port = udp->source,
            .dst_port = udp->dest,
            .proto    = ip->protocol,
        };

        struct nat_value *entry = bpf_map_lookup_elem(&nat_table, &key);
        if (!entry)
            return TCX_PASS;

        bpf_printk("tcx/ingress: udp %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);

        ip->daddr = entry->new_src_ip;
        udp->dest = entry->new_src_port;
        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), key.dst_ip, entry->new_src_ip, sizeof(__be32));
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), key.dst_ip, entry->new_src_ip, sizeof(__be32) | BPF_F_PSEUDO_HDR);
        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), key.dst_port, entry->new_src_port, sizeof(__be16));

        __u32 *netkit_ifindex = bpf_map_lookup_elem(&ip_to_container, &entry->new_src_ip);
        bpf_printk("tcx/ingress: udp entry->new_src_ip=%pI4:%d=%d, found=%p", &entry->new_src_ip, entry->new_src_port, entry->new_src_ip, netkit_ifindex);
        if (unlikely(!netkit_ifindex))
            return TCX_PASS;

        bpf_printk("tcx/ingress: udp netkit_ifindex %d", *netkit_ifindex);
        return bpf_redirect_peer(*netkit_ifindex, 0);
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

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TCX_PASS;

    if ((bpf_ntohl(ip->saddr) & 0xFFFFFF00) == 0x0A000200 && ip->daddr != API_SERVER_IP) {
        bpf_printk("tcx/egress: %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if ((void *)(tcp + 1) > data_end)
                return TCX_PASS;

            __be16 src_port         = tcp->source;
            __be32 src_ip           = ip->saddr;
            struct nat_value *entry = source_nat(ip, src_port, tcp->dest);

            ip->saddr   = entry->new_src_ip;
            tcp->source = entry->new_src_port;
            bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), src_ip, entry->new_src_ip, sizeof(__be32));
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), src_ip, entry->new_src_ip, sizeof(__be32) | BPF_F_PSEUDO_HDR);
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), src_port, entry->new_src_port, sizeof(__be16));
            return TCX_PASS;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if ((void *)(udp + 1) > data_end)
                return TCX_PASS;

            __be16 src_port         = udp->source;
            __be32 src_ip           = ip->saddr;
            struct nat_value *entry = source_nat(ip, src_port, udp->dest);

            ip->saddr   = entry->new_src_ip;
            udp->source = entry->new_src_port;
            bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), src_ip, entry->new_src_ip, sizeof(__be32));
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), src_ip, entry->new_src_ip, sizeof(__be32) | BPF_F_PSEUDO_HDR);
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), src_port, entry->new_src_port, sizeof(__be16));
            return TCX_PASS;
        }
    }

    return TCX_PASS;
}
