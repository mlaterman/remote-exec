// exec-client starts the remote executor client.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/mlaterman/remote-exec/pkg/proto"
)

func main() {
	// Client config flags; gather through env vars/file in the future.
	cert := flag.String("cert", "certs/client-cert.pem", "The client's public cert.")
	key := flag.String("key", "certs/client-key.pem", "The client's private key.")
	cas := flag.String("cas", "certs/server-cert.pem", "The server CA.")
	address := flag.String("address", "localhost:8334", "The server address")

	// grpc arguements; should be defined through some other library in the future.
	call := flag.String("call", "status", "The procedure call name. REQUIRED, one of [start,stop,status,output].")
	id := flag.String("id", "", "The process ID. Required for [stop,status,output].")
	cmd := flag.String("command", "", "The executable to run. Required for [start].")
	args := flag.String("args", "", "A comma seperated list of arguments. Optional, used for [start].")
	cpu := flag.Uint64("cpu", 0, "The CPU time in ms allocated to the process. Optional, used for [start].")
	mem := flag.Uint64("mem", 0, "The memory quota in bytes allocated to the process. Optional, used for [start].")
	dio := flag.Uint64("io", 0, "The disk read/write limit in bytes/s allocated to the process. Optional, used for [start].")

	flag.Parse()
	log.Println("Starting exec-client.")
	validateFlags(*call)

	log.Printf("config: cert=%s", *cert)
	log.Printf("config: key=%s", *key)
	log.Printf("config: cas=%s", *cas)
	log.Printf("config: address=%s", *address)

	cred, err := creds(*cert, *key, *cas)
	if err != nil {
		log.Fatalf("Unable to create tls credentials: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := grpc.DialContext(ctx, *address, grpc.WithTransportCredentials(cred), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Unable to connect to server: %v", err)
	}
	defer conn.Close()

	client := pb.NewExecutorClient(conn)

	switch *call {
	case "start":
		resp, err := client.Start(ctx, startParams(*cmd, *args, *cpu, *mem, *dio))
		if err != nil {
			log.Fatalf("Start call failed: %v", err)
		}
		log.Printf("Start call succeeded: %v", resp)
	case "stop":
		resp, err := client.Stop(ctx, &pb.ProcessID{Id: *id})
		if err != nil {
			log.Fatalf("Stop call failed: %v", err)
		}
		log.Printf("Stop call succeeded: %v", resp)
	case "status":
		resp, err := client.Status(ctx, &pb.ProcessID{Id: *id})
		if err != nil {
			log.Fatalf("Status call failed: %v", err)
		}
		log.Printf("Status call succeeded: %v", resp)
	case "output":
		stream, err := client.Output(ctx, &pb.ProcessID{Id: *id})
		if err != nil {
			log.Fatalf("Output call failed: %v", err)
		}
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatalf("Output encountered an error when recieving stream data: %v", err)
			}
			log.Printf("stdout: %s\nstderr: %s", msg.Stdout, msg.Stderr)
		}
	}
}

func creds(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	p, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(p); !ok {
		return nil, fmt.Errorf("unable to add server ca to pool")
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

func passedFlag(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func validateFlags(call string) error {
	if !passedFlag("call") {
		return fmt.Errorf("call flag required.")
	}
	switch call {
	case "start":
		if !passedFlag("command") {
			return fmt.Errorf("command flag required for call start")
		}
	case "stop", "status", "output":
		if !passedFlag("id") {
			return fmt.Errorf("id flag required for call %s", call)
		}
	default:
		return fmt.Errorf("unrecognized call: %s", call)
	}
	return nil
}

func startParams(cmd, args string, cpuFlag, memFlag, ioFlag uint64) *pb.StartProcess {
	sp := &pb.StartProcess{
		Cmd:  cmd,
		Args: strings.Split(args, ","),
	}
	if passedFlag("cpu") {
		sp.Cpu = &pb.ResourceLimit{Value: cpuFlag}
	}
	if passedFlag("mem") {
		sp.Mem = &pb.ResourceLimit{Value: memFlag}
	}
	if passedFlag("io") {
		sp.Io = &pb.ResourceLimit{Value: ioFlag}
	}
	return sp
}
