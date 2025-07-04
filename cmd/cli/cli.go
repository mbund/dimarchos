package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	pb "github.com/mbund/dimarchos/pkg/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultName = "world"
)

var (
	addr   = flag.String("addr", "localhost:50051", "the address to connect to")
	name   = flag.String("name", defaultName, "Name to greet")
	delete = flag.Bool("delete", false, "Should delete running container")
)

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

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("did not connect", "err", err)
		return
	}
	defer conn.Close()
	c := pb.NewAgentClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	if *delete {
		r, err := c.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: *name})
		if err != nil {
			slog.Error("could not delete container", "err", err)
			return
		}
		slog.Info("Delete container", "id", r.GetId())
	} else {
		r, err := c.CreateContainer(ctx, &pb.CreateContainerRequest{Name: *name})
		if err != nil {
			slog.Error("could not create container", "err", err)
			return
		}
		slog.Info("Created container with", "id", r.GetId())
	}
}
