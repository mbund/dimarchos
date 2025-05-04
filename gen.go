package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux container container.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux external external.c
