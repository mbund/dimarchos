package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/digitalocean/go-libvirt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"

	"github.com/mbund/dimarchos/cmd/agent/bpf/objs"
	pb "github.com/mbund/dimarchos/pkg/agent"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	pb.UnimplementedAgentServer
	client    *containerd.Client
	namespace context.Context

	containers []container
	vms        []vm

	ips []net.IP

	bpfObjs         objs.BpfObjects
	externalIngress link.Link
	externalEgress  link.Link
	sockOpts        link.Link
	sockMsg         link.Link
}

type container struct {
	id            string
	netkitPrimary link.Link
	netkitPeer    link.Link
	netkitIndex   int
}

type vm struct {
	xdpLink        link.Link
	tcxIngressLink link.Link
	tcxEgressLink  link.Link
}

func (s *server) nextIp() (net.IP, error) {
	if len(s.ips) == 0 {
		return nil, fmt.Errorf("no more ips available")
	}
	ip := s.ips[len(s.ips)-1]
	s.ips = s.ips[:len(s.ips)-1]
	return ip, nil
}

func upsertDummyInterface() error {
	if link, _ := netlink.LinkByName("dimmeta0"); link != nil {
		return nil
	}

	if err := netlink.LinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: "dimmeta0",
		},
	}); err != nil {
		return fmt.Errorf("failed to create dummy interface: %w", err)
	}

	link, err := netlink.LinkByName("dimmeta0")
	if err != nil {
		return fmt.Errorf("failed to find dummy interface link: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set dummy interface up: %w", err)
	}

	ipnet := net.IPNet{
		IP:   net.ParseIP("169.254.169.254"),
		Mask: net.CIDRMask(32, 32),
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &ipnet,
	}); err != nil {
		return fmt.Errorf("failed to add address to interface: %w", err)
	}

	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &ipnet,
	}); err != nil {
		return fmt.Errorf("failed to add address to interface: %w", err)
	}

	return nil
}

func newServer() (*server, error) {
	if err := upsertDummyInterface(); err != nil {
		return nil, err
	}

	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return nil, err
	}

	ctx := namespaces.WithNamespace(context.Background(), "dimarchos")

	s := &server{
		client:     client,
		namespace:  ctx,
		containers: make([]container, 0),
		vms:        make([]vm, 0),
		ips: []net.IP{
			net.IPv4(10, 0, 2, 4),
			net.IPv4(10, 0, 2, 5),
			net.IPv4(10, 0, 2, 6),
			net.IPv4(10, 0, 2, 7),
		},
	}

	if err := objs.LoadBpfObjects(&s.bpfObjs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	s.bpfObjs.BpfMaps.QnameMap.Update(append([]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}, make([]byte, 256-12)...), []byte{2, 2, 2, 2}, ebpf.UpdateAny)
	s.bpfObjs.BpfMaps.QnameMap.Update(append([]byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm'}, make([]byte, 256-11)...), []byte{3, 3, 3, 3}, ebpf.UpdateAny)
	s.bpfObjs.BpfMaps.QnameMap.Update(append([]byte{6, 't', 'h', 'a', 'n', 'o', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}, make([]byte, 256-19)...), []byte{3, 3, 3, 3}, ebpf.UpdateAny)

	s.bpfObjs.DefaultMac.Set([6]byte{0xa2, 0x14, 0x11, 0xe6, 0x0b, 0x95})

	linkExternalIngress, err := link.AttachTCX(link.TCXOptions{
		Interface: 2,
		Program:   s.bpfObjs.ExternalTcxIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tcx ingress: %v", err)
	}
	s.externalIngress = linkExternalIngress

	linkExternalEgress, err := link.AttachTCX(link.TCXOptions{
		Interface: 2,
		Program:   s.bpfObjs.ExternalTcxEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tcx egress: %v", err)
	}
	s.externalEgress = linkExternalEgress

	linkSockOpts, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/dimarchos",
		Program: s.bpfObjs.SockopsLogger,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return nil, fmt.Errorf("attach socket ops: %v", err)
	}
	s.sockOpts = linkSockOpts

	skMsgLink, err := link.AttachRawLink(link.RawLinkOptions{
		Attach:  ebpf.AttachSkMsgVerdict,
		Target:  s.bpfObjs.Sockhash.FD(),
		Program: s.bpfObjs.ProgMsgVerdict,
	})
	if err != nil {
		return nil, fmt.Errorf("attach sk_msg: %v", err)
	}
	s.sockMsg = skMsgLink

	return s, nil
}

func (s *server) Close() error {
	defer s.bpfObjs.Close()
	defer s.externalIngress.Close()
	defer s.externalEgress.Close()
	defer s.sockOpts.Close()
	defer s.sockMsg.Close()
	for _, container := range s.containers {
		slog.Info("deleting container", "id", container.id)
		container.netkitPeer.Close()
		container.netkitPrimary.Close()
	}
	return s.client.Close()
}

func (s *server) CreateContainer(ctx context.Context, in *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	slog.Info("create container", "name", in.GetName())

	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "unable to get peer from context")
	}

	slog.Info("peer", "addr", p.Addr.String())

	image, err := s.client.Pull(s.namespace, "docker.io/library/alpine:latest", containerd.WithPullUnpack)
	if err != nil {
		return nil, err
	}
	slog.Info("pulled", "image", image.Name())

	resolvConfContent := `# Dimarchos DNS Configuration
nameserver 1.1.1.1
`

	container, err := s.client.NewContainer(
		s.namespace,
		in.GetName(),
		containerd.WithNewSnapshot(in.GetName()+"-snapshot", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),
			withCustomResolvConf(resolvConfContent),
		),
	)
	if err != nil {
		return nil, err
	}
	slog.Info("created container", "id", container.ID(), "snapshot", in.GetName()+"-snapshot")

	task, err := container.NewTask(s.namespace, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return nil, err
	}

	slog.Info("task", "pid", task.Pid())
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", task.Pid())
	slog.Info("task", "netns_path", netnsPath)

	ip, err := s.nextIp()
	if err != nil {
		return nil, err
	}

	err = s.Add(netnsPath, container.ID(), "eth0", ip)
	if err != nil {
		return nil, err
	}

	if err := task.Start(s.namespace); err != nil {
		return nil, err
	}

	return &pb.CreateContainerResponse{Id: container.ID()}, nil
}

func (s *server) DeleteContainer(_ context.Context, in *pb.DeleteContainerRequest) (*pb.DeleteContainerResponse, error) {
	slog.Info("delete container", "name", in.GetName())

	container, err := s.client.LoadContainer(s.namespace, in.GetName())
	if err != nil {
		return nil, err
	}
	defer container.Delete(s.namespace, containerd.WithSnapshotCleanup)

	task, err := container.Task(s.namespace, cio.NewAttach(cio.WithStdio))
	if err != nil {
		return nil, err
	}
	defer task.Delete(s.namespace)

	if err := task.Kill(s.namespace, syscall.SIGTERM); err != nil {
		return nil, err
	}

	exitStatusC, err := task.Wait(s.namespace)
	if err != nil {
		return nil, err
	}

	select {
	case status := <-exitStatusC:
		code, _, err := status.Result()
		if err != nil {
			return nil, err
		}
		slog.Info("exited", "container_id", container.ID(), "code", code)
	case <-time.After(10 * time.Second):
		if err := task.Kill(s.namespace, syscall.SIGKILL); err != nil {
			return nil, err
		}
		status := <-exitStatusC
		code, _, err := status.Result()
		if err != nil {
			return nil, err
		}
		slog.Info("exited", "container_id", container.ID(), "code", code)
	}

	return &pb.DeleteContainerResponse{Id: in.GetName()}, nil
}

func main() {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				source, _ := a.Value.Any().(*slog.Source)
				if source != nil {
					source.File = filepath.Base(source.File)
				}
			}
			return a
		},
	}))
	slog.SetDefault(logger)

	uri, _ := url.Parse(string(libvirt.QEMUSystem))
	virConn, err := libvirt.ConnectToURI(uri)
	if err != nil {
		slog.Error("failed to connect", "err", err)
		return
	}

	s := grpc.NewServer()
	reflection.Register(s)
	server, err := newServer()
	if err != nil {
		slog.Error("failed to build server", "err", err)
		return
	}
	defer server.Close()
	pb.RegisterAgentServer(s, server)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		slog.Error("failed to listen", "err", err)
		return
	}

	err = server.createVM(virConn, "example0", "vmtap0", "52:54:00:4b:95:7a", "52:54:00:4b:95:7b", "/var/lib/libvirt/images/ubuntu24.04.qcow2")
	if err != nil {
		slog.Error("failed to create vm", "err", err)
	}

	err = server.createVM(virConn, "example1", "vmtap1", "52:54:00:4b:95:7e", "52:54:00:4b:95:7f", "/var/lib/libvirt/images/ubuntu24.04-2.qcow2")
	if err != nil {
		slog.Error("failed to create vm", "err", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		slog.Info("cleaning up...")

		if link, _ := netlink.LinkByName("dimmeta0"); link != nil {
			if err := netlink.LinkDel(link); err != nil {
				slog.Error("failed to delete link dimmeta0", "err", err)
			}
		}

		if err := server.Close(); err != nil {
			slog.Error("failed to close server", "err", err)
		}

		slog.Info("Initiating graceful shutdown...")
		timer := time.AfterFunc(10*time.Second, func() {
			slog.Error("Server couldn't stop gracefully in time. Doing force stop.")
			s.Stop()
		})
		defer timer.Stop()

		s.GracefulStop()
		slog.Info("Server stopped gracefully")
	}()

	slog.Info("server listening", "addr", lis.Addr())
	if err := s.Serve(lis); err != nil {
		slog.Error("failed to serve", "err", err)
	}
}

func withCustomResolvConf(content string) oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, container *containers.Container, s *specs.Spec) error {
		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("dimarchos-%s-", container.ID))
		if err != nil {
			return fmt.Errorf("failed to create tmp dir for resolv.conf: %w", err)
		}

		resolvConfPath := filepath.Join(tmpDir, "resolv.conf."+container.ID)
		if err := os.WriteFile(resolvConfPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write resolv.conf: %w", err)
		}

		if s.Mounts == nil {
			s.Mounts = []specs.Mount{}
		}

		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      resolvConfPath,
			Options:     []string{"rbind", "ro"},
		})

		return nil
	}
}
