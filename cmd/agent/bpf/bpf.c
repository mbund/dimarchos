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

#define IP4_TO_BE32(a, b, c, d) ((__be32)(((d) << 24) + ((c) << 16) + ((b) << 8) + (a)))

#define HOST_IP IP4_TO_BE32(10, 19, 27, 26)
#define DNS_SERVER_IP IP4_TO_BE32(173, 18, 0, 2)
#define API_SERVER_IP IP4_TO_BE32(169, 254, 169, 254)

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define unlikely(x) __builtin_expect(!!(x), 0)

enum endpoint_kind {
    ENDPOINT_KIND_CONTAINER = 0,
    ENDPOINT_KIND_QEMU_VM,
};

struct ip_info {
    // `enum endpoint_kind`
    __u8 kind;
    __u8 mac[6];
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32); // ipv4 address
    __type(value, struct ip_info);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 1024);
} ip_info SEC(".maps");

SEC("netkit/primary")
int netkit_primary(struct __sk_buff *skb) {
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

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            bpf_printk("netkit/peer: udp %pI4:%d -> %pI4:%d, ifindex %d, mark %x", &ip->saddr, __builtin_bswap16(udp->source), &ip->daddr, __builtin_bswap16(udp->dest), skb->ifindex, skb->mark);
        }
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            bpf_printk("netkit/peer: tcp %pI4:%d -> %pI4:%d, ifindex %d, mark %x", &ip->saddr, __builtin_bswap16(tcp->source), &ip->daddr, __builtin_bswap16(tcp->dest), skb->ifindex, skb->mark);
        }
    }

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

        // https://blog.apnic.net/2020/09/02/journeying-into-xdp-part-0

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

        return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
    }
pass:

    if (ip->daddr == API_SERVER_IP) {
        // verify the source ip address, because the api server uses it as implicit authentication
        struct ip_info *info = bpf_map_lookup_elem(&ip_info, &ip->saddr);
        if (!info) {
            bpf_printk("netkit/peer: cannot find source ifindex");
            return TCX_DROP;
        }

        if (info->ifindex != skb->ifindex) {
            bpf_printk("netkit/peer: ifindex != skb->ifindex, %d != %d", info->ifindex, skb->ifindex);
            return TCX_DROP;
        }

        return TCX_PASS;
    }

    if ((bpf_ntohl(ip->daddr) & 0xFFFFFF00) == 0x0A000200) {
        bpf_printk("netkit/peer: peer route");

        struct ip_info *info = bpf_map_lookup_elem(&ip_info, &ip->daddr);
        if (!info)
            return TCX_PASS;

        bpf_printk("netkit/peer: tcp ifindex %d, size=%d, size2=%d", info->ifindex, skb->len, data_end - data);
        return bpf_redirect_neigh(info->ifindex, NULL, 0, 0);
    }

    bpf_printk("netkit/peer: bpf_redirect_neigh size=%d", skb->len);
    return bpf_redirect_neigh(2, NULL, 0, 0);
}

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
int external_tcx_ingress(struct __sk_buff *skb) {
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

        bpf_printk("tcx/ingress: trying nat %pI4:%d -> %pI4:%d %s", &key.src_ip, __builtin_bswap16(key.src_port), &key.dst_ip, __builtin_bswap16(key.dst_port), ip->protocol == IPPROTO_TCP ? "tcp" : "udp");

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

        struct ip_info *info = bpf_map_lookup_elem(&ip_info, &entry->new_src_ip);
        if (!info)
            return TCX_PASS;

        bpf_printk("tcx/ingress: tcp ifindex %d", info->ifindex);
        if (info->kind == ENDPOINT_KIND_CONTAINER) {
            return bpf_redirect_peer(info->ifindex, 0);
        } else if (info->kind == ENDPOINT_KIND_QEMU_VM) {
            return bpf_redirect_neigh(info->ifindex, NULL, 0, 0);
        }
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

        struct ip_info *info = bpf_map_lookup_elem(&ip_info, &entry->new_src_ip);
        if (!info)
            return TCX_PASS;

        bpf_printk("tcx/ingress: udp ifindex %d", info->ifindex);
        if (info->kind == ENDPOINT_KIND_CONTAINER) {
            return bpf_redirect_peer(info->ifindex, 0);
        } else if (info->kind == ENDPOINT_KIND_QEMU_VM) {
            return bpf_redirect_neigh(info->ifindex, NULL, 0, 0);
        }
    }

    return TCX_PASS;
}

SEC("tcx/egress")
int external_tcx_egress(struct __sk_buff *skb) {
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

struct sock_key {
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_port;
    __u32 local_port;
    __u32 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, void *);
} sockhash SEC(".maps");

SEC("sockops")
int sockops_logger(struct bpf_sock_ops *skops) {
    int op = skops->op;

    struct sock_key key = {
        .family      = skops->family,
        .local_ip4   = skops->local_ip4,
        .local_port  = skops->local_port,
        .remote_ip4  = skops->remote_ip4,
        .remote_port = bpf_ntohl(skops->remote_port),
    };

    // bpf_printk("sockops: src=%pI4:%d dst=%pI4:%d op=%d", &skops->local_ip4, bpf_ntohs(skops->local_port), &skops->remote_ip4, bpf_ntohs(skops->remote_port), op);

    bpf_printk("sockops: src=%pI4:%d dst=%pI4:%d, op=%d skb_len=%d, args[0]=%d args[1]=%d args[2]=%d args[3]=%d", &key.local_ip4, key.local_port, &key.remote_ip4, key.remote_port, op, skops->skb_len, skops->args[0], skops->args[1], skops->args[2], skops->args[3]);

    if (op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
        bpf_printk("sockops: tcp_connect_cb: src=%pI4:%d dst=%pI4:%d", &key.local_ip4, key.local_port, &key.remote_ip4, key.remote_port);
    }

    if ((bpf_ntohl(key.local_ip4) & 0xFFFFFF00) != 0x0A000200 || (bpf_ntohl(key.remote_ip4) & 0xFFFFFF00) != 0x0A000200)
        return BPF_OK;

    switch (op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_printk("sockops: identified socket for acceleration: %pI4:%d -> %pI4:%d", &key.local_ip4, key.local_port, &key.remote_ip4, key.remote_port);
        bpf_sock_hash_update(skops, &sockhash, &key, BPF_ANY);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) {
            bpf_map_delete_elem(&sockhash, &key);
            bpf_printk("sockops: deleted closed tcp socket: %pI4:%d -> %pI4:%d", &key.local_ip4, key.local_port, &key.remote_ip4, key.remote_port);
        }
        break;
    }

    return BPF_OK;
}

SEC("sk_msg")
int prog_msg_verdict(struct sk_msg_md *msg) {
    struct sock_key peer_key = {
        .family      = msg->family,
        .local_ip4   = msg->remote_ip4,
        .local_port  = bpf_ntohl(msg->remote_port),
        .remote_ip4  = msg->local_ip4,
        .remote_port = msg->local_port,
    };

    bpf_printk("sk_msg: message: %pI4:%d -> %pI4:%d, size=%d", &peer_key.local_ip4, peer_key.local_port, &peer_key.remote_ip4, peer_key.remote_port, msg->size);

    __u64 ret = bpf_msg_redirect_hash(msg, &sockhash, &peer_key, BPF_F_INGRESS);
    if (ret == SK_PASS) {
        bpf_printk("sk_msg: accelerated message: %pI4:%d -> %pI4:%d, size=%d", &peer_key.local_ip4, peer_key.local_port, &peer_key.remote_ip4, peer_key.remote_port, msg->size);
    }

    return SK_PASS;
}

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

__u8 default_mac[6] = {0xa2, 0x14, 0x11, 0xe6, 0x0b, 0x95};

#define ARPHRD_ETHER 1  /* Ethernet 10Mbps		*/
#define ARPOP_REQUEST 1 /* ARP request			*/
#define ARPOP_REPLY 2   /* ARP reply			*/

SEC("tcx/ingress")
int tap_tcx_ingress(struct __sk_buff *skb) {
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

        // bpf_printk("tcx/ingress tap: ip: %pI4 -> %pI4, ifindex %d, ingress_ifindex %d", &ip->saddr, &ip->daddr, skb->ifindex, skb->ingress_ifindex);

        if ((bpf_ntohl(ip->daddr) & 0xFFFFFF00) != 0x0A000200) {
            bpf_printk("tcx/ingress tap: ip: external %pI4 -> %pI4", &ip->saddr, &ip->daddr);
            // return bpf_redirect(2, 0);
            return bpf_redirect_neigh(2, NULL, 0, 0);
        }

        struct ip_info *info = bpf_map_lookup_elem(&ip_info, &ip->daddr);
        if (info != NULL) {
            // bpf_printk("tcx/ingress tap %d: ip: %pI4 -> %pI4: redirect to ifindex %d", skb->ingress_ifindex, &ip->saddr, &ip->daddr, entry->ifindex);
            if (info->kind == ENDPOINT_KIND_CONTAINER) {
                return bpf_redirect_peer(info->ifindex, 0);
            } else if (info->kind == ENDPOINT_KIND_QEMU_VM) {
                return bpf_redirect(info->ifindex, 0);
            }
        }
    } else {
        bpf_printk("tcx/ingress tap: unknown: ifindex %d, ingress_ifindex %d", skb->ifindex, skb->ingress_ifindex);
    }

    return TCX_PASS;
}

SEC("tcx/egress")
int tap_tcx_egress(struct __sk_buff *skb) {
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

        struct ip_info *info = bpf_map_lookup_elem(&ip_info, &arp_data->tpa);
        if (info != NULL) {
            target_mac = info->mac;
            __u32 tpa  = arp_data->tpa;
            bpf_printk("xdp tap %d: arp: entry found for ip %pI4 -> %pM", ctx->ingress_ifindex, &tpa, target_mac);
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
    } else {
        bpf_printk("xdp tap %d: unknown", ctx->ingress_ifindex);
    }

    return XDP_PASS;
}
