package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestAuthz(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testing",
		},
	}
	t.Run("name matches", func(t *testing.T) {
		err := Authz(cert, "testing")
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("name mismatch", func(t *testing.T) {
		err := Authz(cert, "testing1")
		if err == nil || err.Error() != "unable to authorize Subject.CommonName: testing" {
			t.Errorf("expected \"unable to authorize Subject.CommonName: testing\" got %v", err)
		}
	})
}
