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

__u32 container_ifindex = 0;

#define CONTAINER_0_IP IP4_TO_BE32(10, 0, 2, 5)
#define IP4_TO_BE32(a, b, c, d) ((__be32)(((d) << 24) + ((c) << 16) + ((b) << 8) + (a)))

#define unlikely(x) __builtin_expect(!!(x), 0)

struct arphdr {
    __be16 ar_hrd;        /* format of hardware address	*/
    __be16 ar_pro;        /* format of protocol address	*/
    unsigned char ar_hln; /* length of hardware address	*/
    unsigned char ar_pln; /* length of protocol address	*/
    __be16 ar_op;         /* ARP opcode (command)		*/
};

struct arp_data {
    __u8 sha[6]; // Sender hardware address
    __u32 spa;   // Sender protocol address
    __u8 tha[6]; // Target hardware address
    __u32 tpa;   // Target protocol address
} __attribute__((packed));

struct routing_value {
    __u8 mac[6];
    __u32 ifindex;
};

__u8 default_mac[6];

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct routing_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 1024);
} routing_table SEC(".maps");

#define ARPHRD_ETHER 1  /* Ethernet 10Mbps		*/
#define ARPOP_REQUEST 1 /* ARP request			*/
#define ARPOP_REPLY 2   /* ARP reply			*/

static __always_inline void safe_memcpy(void *dst, const void *src, __u32 len) {
    __u32 i;
    for (i = 0; i < len; i++) {
        ((volatile __u8 *)dst)[i] = ((volatile __u8 *)src)[i];
    }
}

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

        if (ip->daddr == CONTAINER_0_IP) {
            bpf_printk("tcx/ingress tap %d: ip: %pI4 -> %pI4: redirect to container ifindex %d", skb->ingress_ifindex, &ip->saddr, &ip->daddr, container_ifindex);
            return bpf_redirect_peer(container_ifindex, 0);
        }

        // bpf_printk("tcx/ingress tap: ip: %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);

        struct routing_value *entry = bpf_map_lookup_elem(&routing_table, &ip->daddr);
        if (entry != NULL) {
            // bpf_printk("tcx/ingress tap %d: ip: %pI4 -> %pI4: redirect to ifindex %d", skb->ingress_ifindex, &ip->saddr, &ip->daddr, entry->ifindex);
            return bpf_redirect(entry->ifindex, 0);
        }
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

        // bpf_printk("tcx/egress tap: ip: %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);
    } else {
        bpf_printk("tcx/egress tap: unknown: ifindex %d, ingress_ifindex %d", skb->ifindex, skb->ingress_ifindex);
    }

    return TCX_PASS;
}

#define MAX_UDP_SIZE 1480

static __always_inline void set_udp_csum(struct iphdr *iph, struct udphdr *udph, void *data_end) {
    __u32 csum_buffer = 0;
    __u16 *buf        = (void *)udph;

    udph->check = 0;

    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += udph->len;

    for (int i = 0; i < MAX_UDP_SIZE; i += 2) {
        if ((void *)(buf + 1) > data_end) {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) {
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum       = ~csum;

    udph->check = csum;
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

        struct arp_data *arp_data = (struct arp_data *)(arp + 1);
        if ((void *)(arp_data + 1) > data_end)
            return XDP_PASS;

        bpf_printk("xdp tap %d: arp: op: %d", ctx->ingress_ifindex, arp->ar_op);

        // only handle ipv4 ARP requests
        if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER) || arp->ar_pro != bpf_htons(ETH_P_IP) || arp->ar_hln != 6 || arp->ar_pln != 4 || arp->ar_op != bpf_htons(ARPOP_REQUEST))
            return XDP_PASS;

        __u8 *target_mac = default_mac;

        struct routing_value *entry = bpf_map_lookup_elem(&routing_table, &arp_data->tpa);
        if (entry != NULL) {
            target_mac = entry->mac;
            bpf_printk("xdp tap %d: arp: entry found for ip %pI4 -> %pM", ctx->ingress_ifindex, &arp_data->tpa, target_mac);
        }

        __u8 requester_mac[6];
        __u32 requester_ip = arp_data->spa;
        __u32 requested_ip = arp_data->tpa;
        safe_memcpy(requester_mac, arp_data->sha, 6);

        safe_memcpy(eth->h_dest, requester_mac, 6);
        safe_memcpy(eth->h_source, target_mac, 6);

        arp->ar_op = bpf_htons(ARPOP_REPLY);

        safe_memcpy(arp_data->sha, target_mac, 6);
        arp_data->spa = requested_ip;

        safe_memcpy(arp_data->tha, requester_mac, 6);
        arp_data->tpa = requester_ip;

        return XDP_TX;
    } else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // bpf_printk("xdp tap %d: ip: %pI4 -> %pI4", ctx->ingress_ifindex, &ip->saddr, &ip->daddr);

        // struct routing_value *entry = bpf_map_lookup_elem(&routing_table, &ip->daddr);
        // if (entry != NULL) {
        //     // bpf_printk("xdp tap %d: ip: %pI4 -> %pI4: redirect to ifindex %d", ctx->ingress_ifindex, &ip->saddr, &ip->daddr, entry->ifindex);

        //     if (ip->protocol == IPPROTO_UDP) {
        //         struct udphdr *udp = (struct udphdr *)(ip + 1);
        //         if ((void *)(udp + 1) > data_end)
        //             return XDP_PASS;

        //         udp->check = 0;
        //     } else if (ip->protocol == IPPROTO_TCP) {
        //         struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        //         if ((void *)(tcp + 1) > data_end)
        //             return XDP_PASS;

        //         // set_tcp_csum(ip, tcp, data_end);
        //     }

        //     // __s64 value = bpf_csum_diff(NULL, 0, (void *)udp, udp->len, 0);
        //     // bpf_printk("xdp tap %d: ip: udp: checksum-value %x", ctx->ingress_ifindex, value);

        //     // bpf_printk("xdp tap %d: ip: udp: checksum %x", ctx->ingress_ifindex, udp->check);

        //     return bpf_redirect(entry->ifindex, 0);
        // }
    } else {
        bpf_printk("xdp tap %d: unknown", ctx->ingress_ifindex);
    }

    return XDP_PASS;
}
