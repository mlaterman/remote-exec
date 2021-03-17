// package server is an implementation of the remote-exec server.
package server

import (
	"context"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/mlaterman/remote-exec/pkg/auth"
	pb "github.com/mlaterman/remote-exec/pkg/proto"
)

type ExecServer struct {
	pb.UnimplementedExecutorServer
}

func New() *ExecServer {
	return &ExecServer{}
}

func (e *ExecServer) checkCert(ctx context.Context) error {
	cert, err := getClientCert(ctx)
	if err != nil {
		return err
	}
	name := "" // TODO get name value
	return auth.Authz(cert, name)
}

func getClientCert(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("call has no peer information")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("unable to gather tls info")
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no peer certificates found")
	}
	return certs[0], nil
}

func (e *ExecServer) Start(ctx context.Context, startProc *pb.StartProcess) (*pb.ProcessID, error) {
	err := e.checkCert(ctx)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("start not implemented")
}
func (e *ExecServer) Stop(ctx context.Context, id *pb.ProcessID) (*pb.StopResponse, error) {
	err := e.checkCert(ctx)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("stop not implemented")
}

func (e *ExecServer) Status(ctx context.Context, id *pb.ProcessID) (*pb.StatusResponse, error) {
	err := e.checkCert(ctx)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("status not implemented")
}

func (e *ExecServer) Output(id *pb.ProcessID, stream pb.Executor_OutputServer) error {
	err := e.checkCert(stream.Context())
	if err != nil {
		return err
	}
	return fmt.Errorf("output not implemented")
}
