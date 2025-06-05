package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir bpf/objs -go-package objs -tags linux Container bpf/container.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir bpf/objs -go-package objs -tags linux External bpf/external.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir bpf/objs -go-package objs -tags linux Sockets bpf/sockets.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir bpf/objs -go-package objs -tags linux Tap bpf/tap.c
