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

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/opencontainers/runtime-spec/specs-go"

	pb "github.com/mbund/dimarchos/pkg/agent"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	pb.UnimplementedAgentServer
	client    *containerd.Client
	namespace context.Context

	containerId string
}

func newServer() (*server, error) {
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return nil, err
	}

	ctx := namespaces.WithNamespace(context.Background(), "dimarchos")

	return &server{
		client:    client,
		namespace: ctx,
	}, nil
}

func (s *server) Close() error {
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

	resolvConfContent := `# Dimarchos DNS Configuraiton
nameserver 1.1.1.1
`

	container, err := s.client.NewContainer(
		s.namespace,
		"alpine-4",
		containerd.WithNewSnapshot("alpine-4-snapshot", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),
			withCustomResolvConf(resolvConfContent),
		),
	)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	log.Printf("Successfully created container with ID %s and snapshot with ID alpine-4-snapshot", container.ID())

	task, err := container.NewTask(s.namespace, cio.NewCreator(cio.WithStdio))
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	log.Printf("pid: %d", task.Pid())
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", task.Pid())
	log.Printf("netns path: %s", netnsPath)

	err = Add(netnsPath, container.ID(), "eth0")
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	// call start on the task to execute the redis server
	if err := task.Start(s.namespace); err != nil {
		log.Fatalln(err)
		return nil, err
	}

	s.containerId = container.ID()

	return &pb.CreateContainerResponse{Id: container.ID()}, nil
}

func (s *server) DeleteContainer(_ context.Context, in *pb.DeleteContainerRequest) (*pb.DeleteContainerResponse, error) {
	log.Printf("Received delete: %v", in.GetName())

	container, err := s.client.LoadContainer(s.namespace, s.containerId)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	defer container.Delete(s.namespace, containerd.WithSnapshotCleanup)

	task, err := container.Task(s.namespace, cio.NewAttach(cio.WithStdio))
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	defer task.Delete(s.namespace)

	if err := task.Kill(s.namespace, syscall.SIGTERM); err != nil {
		log.Fatalln(err)
		return nil, err
	}

	// make sure we wait before calling start
	exitStatusC, err := task.Wait(s.namespace)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	status := <-exitStatusC
	code, _, err := status.Result()
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	fmt.Printf("alpine-4 exited with status: %d\n", code)

	return &pb.DeleteContainerResponse{Id: s.containerId}, nil
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
