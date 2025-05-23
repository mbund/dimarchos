//go:build ignore

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

__u64 ingress_pkt_count = 0;
__u64 egress_pkt_count  = 0;

#define IP4_TO_BE32(a, b, c, d) ((__be32)(((d) << 24) + ((c) << 16) + ((b) << 8) + (a)))

#define CONTAINER_IP IP4_TO_BE32(173, 18, 0, 5)
#define HOST_IP IP4_TO_BE32(10, 23, 29, 149)

#define DNS_SERVER_IP IP4_TO_BE32(173, 18, 0, 2)
#define API_SERVER_IP IP4_TO_BE32(169, 254, 169, 254)

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

static inline void set_tcp_ip_src(struct __sk_buff *skb, __u32 old_ip, __u32 new_ip) {
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &new_ip, sizeof(new_ip), 0);
}

static inline void set_tcp_ip_dst(struct __sk_buff *skb, __u32 old_ip, __u32 new_ip) {
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, IP_DST_OFF, &new_ip, sizeof(new_ip), 0);
}

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

    bpf_printk("netkit/primary: %pI4 -> %pI4", &ip->saddr, &ip->daddr);

    if (ip->protocol != IPPROTO_TCP)
        return TCX_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return TCX_PASS;

    if (ip->saddr == HOST_IP && ip->daddr == CONTAINER_IP) {
        __be16 sport = __builtin_bswap16(tcp->source);
        __be16 dport = __builtin_bswap16(tcp->dest);
        bpf_printk("netkit/primary: redirect magic ip %pI4:%d -> %pI4:%d", &ip->saddr, sport, &ip->daddr, dport);
        __be32 saddr = ip->saddr;
        __be32 daddr = ip->daddr;
        set_tcp_ip_src(skb, saddr, API_SERVER_IP);
        bpf_printk("netkit/primary: redirect magic ip %pI4:%d -> %pI4:%d", &ip->saddr, sport, &ip->daddr, dport);
    }

    return TCX_PASS;
}

static __always_inline void safe_memcpy(void *dst, const void *src, __u32 len) {
    __u32 i;
    for (i = 0; i < len; i++) {
        ((volatile __u8 *)dst)[i] = ((volatile __u8 *)src)[i];
    }
}

struct qname_key {
    __u8 qname[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct qname_key);
    __type(value, __be32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 1024);
} qname_map SEC(".maps");

struct dns_flags {
    __u8 RD : 1;
    __u8 TC : 1;
    __u8 AA : 1;
    __u8 OPCODE : 4;
    __u8 QR : 1;
    __u8 RCODE : 4;
    __u8 CD : 1;
    __u8 AD : 1;
    __u8 Z : 1;
    __u8 RA : 1;
} __attribute__((packed));

struct dns_header {
    __be16 transaction_id;
    struct dns_flags flags;
    __be16 num_questions;
    __be16 num_answers;
    __be16 num_authority_rrs;
    __be16 num_additional_rrs;
} __attribute__((packed));

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

    if (ip->protocol == IPPROTO_UDP && ip->daddr == DNS_SERVER_IP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            bpf_printk("netkit/peer: dying %d", 1);
            goto pass;
        }

        __be32 tmp_ip = ip->saddr;
        ip->saddr     = ip->daddr;
        ip->daddr     = tmp_ip;

        __be16 tmp_port = udp->source;
        udp->source     = udp->dest;
        udp->dest       = tmp_port;

        struct dns_header *dns_header = (struct dns_header *)(udp + 1);
        if ((void *)(dns_header + 1) > data_end) {
            bpf_printk("netkit/peer: dying %d", 2);
            return TCX_PASS;
        }

        // DNS records with multiple questions are very uncommon these days
        if (dns_header->num_questions != __builtin_bswap16(1)) {
            bpf_printk("netkit/peer: dying %d", 3);
            return TCX_PASS;
        }

        __u8 *question = (__u8 *)(dns_header + 1);
        if ((void *)(question + 1) > data_end) {
            bpf_printk("netkit/peer: dying %d", 4);
            return TCX_PASS;
        }

        bpf_printk("netkit/peer: %s", question);

        // response
        __u32 question_len = 0;
        while (question + question_len < (__u8 *)data_end && question[question_len] != 0 && question_len < 256)
            question_len++;

        __u8 qname_key[256] = {0};
        safe_memcpy(qname_key, question, question_len);
        __be32 *ip_addr = bpf_map_lookup_elem(&qname_map, qname_key);
        if (ip_addr == NULL)
            return TCX_PASS;

        question_len += 5;

        dns_header->flags.QR           = 1;
        dns_header->flags.RA           = dns_header->flags.RD;
        dns_header->num_answers        = __builtin_bswap16(1);
        dns_header->num_additional_rrs = 0;

        bpf_skb_change_tail(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + question_len + 16, 0);

        data_end = (void *)(__u64)skb->data_end;
        data     = (void *)(__u64)skb->data;
        question = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

        if ((__u8 *)question + question_len + 16 > (__u8 *)data_end) {
            bpf_printk("netkit/peer: dying %p %p", question + question_len + 16, (__u8 *)data_end);
            return TCX_DROP;
        }

        ip  = (struct iphdr *)(data + sizeof(struct ethhdr));
        udp = (struct udphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));

        __be16 old_tot_len = ip->tot_len;
        __be16 new_tot_len = __builtin_bswap16(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + question_len + 16);
        ip->tot_len        = new_tot_len;

        __be16 old_len = udp->len;
        __be16 new_len = __builtin_bswap16(sizeof(struct udphdr) + sizeof(struct dns_header) + question_len + 16);
        udp->len       = new_len;

        __u8 answer[] = {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
        safe_memcpy(answer + 12, ip_addr, sizeof(*ip_addr));
        __u32 offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + question_len;
        bpf_skb_store_bytes(skb, offset, answer, 16, BPF_F_RECOMPUTE_CSUM);
        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_tot_len, new_tot_len, sizeof(__be16));
        // bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), old_len, new_len, sizeof(__be16) | BPF_F_PSEUDO_HDR);

        return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
    }
pass:

    bpf_printk("netkit/peer: %pI4 -> %pI4", &ip->saddr, &ip->daddr);

    if (ip->daddr == API_SERVER_IP) {
        if (ip->protocol != IPPROTO_TCP)
            return TCX_PASS;

        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TCX_PASS;

        __be16 sport = __builtin_bswap16(tcp->source);
        __be16 dport = __builtin_bswap16(tcp->dest);
        bpf_printk("netkit/peer: redirect magic ip %pI4:%d -> %pI4:%d", &ip->saddr, sport, &ip->daddr, dport);
        __be32 daddr = ip->daddr;
        set_tcp_ip_dst(skb, daddr, HOST_IP);
        bpf_printk("netkit/peer: redirect magic ip %pI4:%d -> %pI4:%d", &ip->saddr, sport, &ip->daddr, dport);
        return TCX_PASS;
    }

    return bpf_redirect_neigh(3, NULL, 0, 0);
}
