package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"google.golang.org/grpc"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/opencontainers/runtime-spec/specs-go"

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

	ips []net.IP

	containerObjs   objs.ContainerObjects
	externalObjs    objs.ExternalObjects
	sockObjs        objs.SocketsObjects
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

func (s *server) nextIp() (net.IP, error) {
	if len(s.ips) == 0 {
		return nil, fmt.Errorf("no more ips available")
	}
	ip := s.ips[len(s.ips)-1]
	s.ips = s.ips[:len(s.ips)-1]
	return ip, nil
}

func newServer() (*server, error) {
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return nil, err
	}

	ctx := namespaces.WithNamespace(context.Background(), "dimarchos")

	s := &server{
		client:     client,
		namespace:  ctx,
		containers: make([]container, 2),
		ips: []net.IP{
			net.IPv4(240, 0, 0, 2),
			net.IPv4(240, 0, 0, 3),
		},
	}

	if err := objs.LoadContainerObjects(&s.containerObjs, nil); err != nil {
		return nil, fmt.Errorf("loading container eBPF objects: %w", err)
	}

	s.containerObjs.ContainerMaps.QnameMap.Update(append([]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}, make([]byte, 256-12)...), []byte{2, 2, 2, 2}, ebpf.UpdateAny)
	s.containerObjs.ContainerMaps.QnameMap.Update(append([]byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm'}, make([]byte, 256-11)...), []byte{3, 3, 3, 3}, ebpf.UpdateAny)
	s.containerObjs.ContainerMaps.QnameMap.Update(append([]byte{6, 't', 'h', 'a', 'n', 'o', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}, make([]byte, 256-19)...), []byte{3, 3, 3, 3}, ebpf.UpdateAny)

	if err := objs.LoadExternalObjects(&s.externalObjs, nil); err != nil {
		return nil, fmt.Errorf("loading external eBPF objects: %w", err)
	}

	linkExternalIngress, err := link.AttachTCX(link.TCXOptions{
		Interface: 3,
		Program:   s.externalObjs.TcxIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tcx ingress: %v", err)
	}
	s.externalIngress = linkExternalIngress

	linkExternalEgress, err := link.AttachTCX(link.TCXOptions{
		Interface: 3,
		Program:   s.externalObjs.TcxEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tcx egress: %v", err)
	}
	s.externalEgress = linkExternalEgress

	if err := objs.LoadSocketsObjects(&s.sockObjs, nil); err != nil {
		return nil, fmt.Errorf("loading external eBPF objects: %w", err)
	}

	linkSockOpts, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/dimarchos",
		Program: s.sockObjs.SockopsLogger,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return nil, fmt.Errorf("attach socket ops: %v", err)
	}
	s.sockOpts = linkSockOpts

	skMsgLink, err := link.AttachRawLink(link.RawLinkOptions{
		Attach:  ebpf.AttachSkMsgVerdict,
		Target:  s.sockObjs.Sockhash.FD(),
		Program: s.sockObjs.ProgMsgVerdict,
	})
	if err != nil {
		return nil, fmt.Errorf("attach sk_msg: %v", err)
	}
	s.sockMsg = skMsgLink

	return s, nil
}

func (s *server) Close() error {
	defer s.containerObjs.Close()
	defer s.externalObjs.Close()
	defer s.externalIngress.Close()
	defer s.externalEgress.Close()
	defer s.sockObjs.Close()
	defer s.sockOpts.Close()
	defer s.sockMsg.Close()
	for _, container := range s.containers {
		container.netkitPeer.Close()
		container.netkitPrimary.Close()
	}
	return s.client.Close()
}

func (s *server) CreateContainer(_ context.Context, in *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	log.Printf("Received create: %v", in.GetName())

	image, err := s.client.Pull(s.namespace, "docker.io/library/alpine:latest", containerd.WithPullUnpack)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	log.Printf("Successfully pulled %s image\n", image.Name())

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
		log.Fatalln(err)
		return nil, err
	}
	log.Printf("Successfully created container with ID %s and snapshot with ID %s-snapshot", container.ID(), in.GetName())

	task, err := container.NewTask(s.namespace, cio.NewCreator(cio.WithStdio))
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	log.Printf("pid: %d", task.Pid())
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", task.Pid())
	log.Printf("netns path: %s", netnsPath)

	ip, err := s.nextIp()
	if err != nil {
		return nil, err
	}

	err = s.Add(netnsPath, container.ID(), "eth0", ip)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	if err := task.Start(s.namespace); err != nil {
		log.Fatalln(err)
		return nil, err
	}

	return &pb.CreateContainerResponse{Id: container.ID()}, nil
}

func (s *server) DeleteContainer(_ context.Context, in *pb.DeleteContainerRequest) (*pb.DeleteContainerResponse, error) {
	log.Printf("Received delete: %v", in.GetName())

	container, err := s.client.LoadContainer(s.namespace, in.GetName())
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	log.Printf("A")
	defer container.Delete(s.namespace, containerd.WithSnapshotCleanup)

	task, err := container.Task(s.namespace, cio.NewAttach(cio.WithStdio))
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	defer task.Delete(s.namespace)
	log.Printf("B")

	if err := task.Kill(s.namespace, syscall.SIGTERM); err != nil {
		log.Fatalln(err)
		return nil, err
	}

	log.Printf("C")

	// make sure we wait before calling start
	exitStatusC, err := task.Wait(s.namespace)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	log.Printf("D")

	status := <-exitStatusC
	code, _, err := status.Result()
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	fmt.Printf("%s exited with status: %d\n", container.ID(), code)

	return &pb.DeleteContainerResponse{Id: in.GetName()}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	server, err := newServer()
	if err != nil {
		log.Fatalf("failed to build server: %v", err)
	}
	defer server.Close()
	pb.RegisterAgentServer(s, server)
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
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
