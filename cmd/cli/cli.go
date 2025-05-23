package main

import (
	"context"
	"flag"
	"log"
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
	// Set up a connection to the server.
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAgentClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if *delete {
		r, err := c.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: *name})
		if err != nil {
			log.Fatalf("could not delete container: %v", err)
		}
		log.Printf("Delete container with id: %s", r.GetId())
	} else {
		r, err := c.CreateContainer(ctx, &pb.CreateContainerRequest{Name: *name})
		if err != nil {
			log.Fatalf("could not create container: %v", err)
		}
		log.Printf("Created container with id: %s", r.GetId())
	}
}
