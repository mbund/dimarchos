//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define unlikely(x) __builtin_expect(!!(x), 0)

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
    // msg->sk->mark = 0xdeadbeef;

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