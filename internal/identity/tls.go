package identity

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"argos/internal/network"
)

// ProbeTLS intercepte le Handshake pour extraire le nom de domaine caché (Common Name)
func ProbeTLS(ctx context.Context, ip string, port int, dialer network.ContextDialer, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Frappe réseau initiale via le Tunnel/Direct
	rawConn, err := dialer.DialContext(ctxTimeout, "tcp", addr)
	if err != nil {
		return ""
	}
	defer rawConn.Close()

	// 2. Surcouche TLS manuelle
	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
	})

	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.HandshakeContext(ctxTimeout); err != nil {
		return ""
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		return certs[0].Subject.CommonName
	}
	return ""
}
