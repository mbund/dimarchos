//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define unlikely(x) __builtin_expect(!!(x), 0)

SEC("sockops")
int sockops_logger(struct bpf_sock_ops *skops) {
    int op = skops->op;

    if (op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
        bpf_printk("TCP_CONNECT_CB: src=%pI4:%d dst=%pI4:%d\n", &skops->local_ip4, bpf_ntohs(skops->local_port), &skops->remote_ip4, bpf_ntohs(skops->remote_port));
        bpf_printk("TCP_CONNECT_CB: src=%x:%d dst=%x:%d\n", skops->local_ip4, bpf_ntohs(skops->local_port), skops->remote_ip4, bpf_ntohs(skops->remote_port));
    }

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_printk("ESTABLISHED: %pI4:%d <-> %pI4:%d\n", &skops->local_ip4, bpf_ntohs(skops->local_port), &skops->remote_ip4, bpf_ntohs(skops->remote_port));
        bpf_printk("ESTABLISHED: %x:%d <-> %x:%d\n", skops->local_ip4, bpf_ntohs(skops->local_port), skops->remote_ip4, bpf_ntohs(skops->remote_port));
    }

    return 0;
}
