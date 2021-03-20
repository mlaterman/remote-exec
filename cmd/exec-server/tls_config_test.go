// test for TLS configuration and certificate validation
// requires make all-certs to be ran from project root.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	certPath   = "../../certs/"
	clientKey  = certPath + "client-key.pem"
	clientCert = certPath + "client-cert.pem"
	clientCA   = certPath + "ca-client-cert.pem"
	serverKey  = certPath + "server-key.pem"
	serverCert = certPath + "server-cert.pem"
	serverCA   = certPath + "ca-server-cert.pem"
	testKey    = certPath + "test-key.pem"
	testCert   = certPath + "test-cert.pem"
	testCA     = certPath + "ca-test-cert.pem"
)

func client(t *testing.T, certFile, keyFile, caFile string, version uint16) *http.Client {
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
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				MinVersion:   version,
				MaxVersion:   version,
			},
		},
	}
}

func TestTLSConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config, err := tlsConfig(testCert, testKey, testCA)
		if err != nil {
			t.Fatal(err)
		}
		if config.Certificates == nil {
			t.Errorf("TLS Config has no certificates!")
		}
	})
	t.Run("unable to load key", func(t *testing.T) {
		_, err := tlsConfig(testCert, "fake.key", testCA)
		if err == nil {
			t.Fatalf("expected an error.")
		}
	})
}

func TestClientConnection(t *testing.T) {
	serverTLS, err := tlsConfig(serverCert, serverKey, clientCA)
	if err != nil {
		t.Fatalf("Unable to create server TLS config: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, World!")
	}))
	ts.TLS = serverTLS
	ts.StartTLS()
	defer ts.Close()
	t.Log("Starting test server")

	t.Run("Client connection OK", func(t *testing.T) {
		c := client(t, clientCert, clientKey, serverCA, tls.VersionTLS13)
		resp, err := c.Get(ts.URL)
		if err != nil {
			t.Fatalf("Client connection error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("expected status code 200 got %d", resp.StatusCode)
		}
	})
	t.Run("Client connection wrong CA", func(t *testing.T) {
		c := client(t, clientCert, clientKey, testCA, tls.VersionTLS13)
		resp, err := c.Get(ts.URL)
		if err != nil && errors.Unwrap(err).Error() != "x509: certificate signed by unknown authority" {
			t.Fatalf("expected \"x509: certificate signed by unknown authority\" got: %v", err)
		}
		if err == nil {
			resp.Body.Close()
			t.Error("expected \"x509: certificate signed by unknown authority\" got: nil")
		}
	})
	t.Run("Client connection wrong cert", func(t *testing.T) {
		c := client(t, testCert, testKey, serverCA, tls.VersionTLS13)
		resp, err := c.Get(ts.URL)
		if err != nil && errors.Unwrap(err).Error() != "remote error: tls: bad certificate" {
			t.Fatalf("unexpected error: %v", err)
		}
		if err == nil {
			resp.Body.Close()
			t.Errorf("nil error")
		}
	})
	t.Run("Client connection wrong TLS version", func(t *testing.T) {
		c := client(t, clientCert, clientKey, serverCA, tls.VersionTLS12)
		resp, err := c.Get(ts.URL)
		if err != nil && errors.Unwrap(err).Error() != "remote error: tls: protocol version not supported" {
			t.Fatalf("expected \"remote error: tls: protocol version not supported\", got: %v", err)
		}
		if err == nil {
			resp.Body.Close()
			t.Error("Expected \"remote error: tls: protocol version not supported\", got: nil.")
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
		c := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS13,
					MaxVersion: tls.VersionTLS13,
				},
			},
		}
		resp, err := c.Get(ts.URL)
		if err != nil && errors.Unwrap(err).Error() != "remote error: tls: bad certificate" {
			t.Fatalf("unexpected error: %v", err)
		}
		if err == nil {
			resp.Body.Close()
			t.Errorf("nil error")
		}
	})
}
