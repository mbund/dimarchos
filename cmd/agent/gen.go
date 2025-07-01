package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir bpf/objs -go-package objs -tags linux Bpf bpf/bpf.c
