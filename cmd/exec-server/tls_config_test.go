// test for TLS configuration and certificate validation
// requires make all-certs to be ran from project root.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"testing"
)

const (
	certPath   = "../../certs/"
	clientKey  = certPath + "client-key.pem"
	clientCert = certPath + "client-cert.pem"
	serverKey  = certPath + "server-key.pem"
	serverCert = certPath + "server-cert.pem"
	testKey    = certPath + "test-key.pem"
	testCert   = certPath + "test-cert.pem"
)

func clientTLS(t *testing.T, certFile, keyFile, caFile string, version uint16) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Unable to load client keypair: %v", err)
	}
	p, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("Unable to read client CA: %v", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(p); !ok {
		t.Fatal("Unable to add client CA to pool.")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   version,
		MaxVersion:   version,
	}
}

func TestTLSConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config, err := tlsConfig(testCert, testKey, testCert)
		if err != nil {
			t.Fatal(err)
		}
		if config.Certificates == nil {
			t.Errorf("TLS Config has no certificates!")
		}
	})
	t.Run("unable to load key", func(t *testing.T) {
		_, err := tlsConfig(testCert, "fake.key", testCert)
		if err == nil {
			t.Fatalf("expected an error.")
		}
	})
}

func TestClientConnection(t *testing.T) {
	serverTLS, err := tlsConfig(serverCert, serverKey, clientCert)
	if err != nil {
		t.Fatalf("Unable to create server TLS config: %v", err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer l.Close()
	t.Log("Starting test server")
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Server error: %v", err)
			}
			if errors.Is(err, net.ErrClosed) {
				break
			}
			conn.Write([]byte("hello, world."))
			conn.Close()
		}
	}()

	t.Run("Client connection OK", func(t *testing.T) {
		conn, err := tls.Dial("tcp", l.Addr().String(), clientTLS(t, clientCert, clientKey, serverCert, tls.VersionTLS13))
		if err != nil {
			t.Fatalf("Client connection error: %v", err)
		}
		conn.Close()
	})
	t.Run("Client connection wrong CA", func(t *testing.T) {
		conn, err := tls.Dial("tcp", l.Addr().String(), clientTLS(t, clientCert, clientKey, testCert, tls.VersionTLS13))
		if err != nil && err.Error() != "x509: certificate signed by unknown authority" {
			t.Fatalf("expected \"x509: certificate signed by unknown authority\" got: %v", err)
		}
		if err == nil {
			t.Error("expected \"x509: certificate signed by unknown authority\" got: nil")
			conn.Close()
		}
	})
	t.Run("Client connection wrong cert", func(t *testing.T) {
		conn, err := tls.Dial("tcp", l.Addr().String(), clientTLS(t, testCert, testKey, serverCert, tls.VersionTLS13))
		if err != nil && err.Error() != "cert error" {
			t.Fatalf("unexpected error: %v", err)
		}
		if err == nil {
			t.Errorf("nil error") // FIXME test fails, nil error
			conn.Close()
		}
	})
	t.Run("Client connection wrong TLS version", func(t *testing.T) {
		conn, err := tls.Dial("tcp", l.Addr().String(), clientTLS(t, clientCert, clientKey, serverCert, tls.VersionTLS12))
		if err != nil && err.Error() != "remote error: tls: protocol version not supported" {
			t.Fatalf("expected \"remote error: tls: protocol version not supported\", got: %v", err)
		}
		if err == nil {
			t.Error("Expected \"remote error: tls: protocol version not supported\", got: nil.")
			conn.Close()
		}
	})
	t.Run("Client connection has no cert", func(t *testing.T) {
		p, err := os.ReadFile(serverCert)
		if err != nil {
			t.Fatalf("Unable to read client CA: %v", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(p); !ok {
			t.Fatal("Unable to add client CA to pool.")
		}
		conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		})
		if err != nil && err.Error() != "requires client cert" {
			t.Fatalf("unexpected error: %v", err)
		}
		if err == nil {
			t.Errorf("nil error") // FIXME test fails, nil error
			conn.Close()
		}
	})
}
