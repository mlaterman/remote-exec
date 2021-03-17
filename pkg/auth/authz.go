// package auth applies a trivial serverside authorization layer.
package auth

import (
	"crypto/x509"
	"fmt"
)

// Authz applies authorization to the client cert.
//
// It is set to authorize only for Subject.CommonName against the passed name
// This could be replaced with an OPA call that validates more setting in the future
func Authz(cert *x509.Certificate, name string) error {
	if cert.Subject.CommonName != name {
		return fmt.Errorf("unable to authorize Subject.CommonName: %s", cert.Subject.CommonName)
	}
	return nil
}
