// exec-server starts the remote executor server.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/mlaterman/remote-exec/pkg/proto"
	"github.com/mlaterman/remote-exec/pkg/server"
)

func main() {
	cert := flag.String("cert", "certs/server-cert.pem", "The server's public cert.")
	key := flag.String("key", "certs/server-key.pem", "The server's private key.")
	cas := flag.String("cas", "certs/client-cert.pem", "The client CA.")
	port := flag.Int("port", 8443, "The port the server listens on.")
	flag.Parse()

	log.Println("Starting exec-server.")
	log.Printf("cert=%s", *cert)
	log.Printf("key=%s", *key)
	log.Printf("cas=%s", *cas)
	log.Printf("port=%d", port)

	tlsC, err := tlsConfig(*cert, *key, *cas)
	if err != nil {
		log.Fatalf("Unable to create tls config: %v", err)
	}

	creds := credentials.NewTLS(tlsC)
	srv := server.New()
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterExecutorServer(grpcServer, srv)

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatalf("Unable to listen to port: %v", err)
	}
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Unable to serve gprc: %v", err)
	}
}

func tlsConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
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
		return nil, fmt.Errorf("unable to add client ca to pool")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
