package identity

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"argos/internal/network"
)

// bufferPool est notre usine d'allocation zéro-déchet.
// Au lieu d'allouer 1024 octets par port ouvert, les workers empruntent et rendent des tampons.
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1024)
		return &b
	},
}

// GrabBanner capture la réponse initiale d'un service TCP.
func GrabBanner(ctx context.Context, ip string, port int, dialer network.ContextDialer, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(ctxTimeout, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Timeout de lecture impitoyable
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Emprunt d'un tampon dans le pool
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr) // Restitution garantie
	buf := *bufPtr

	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	return cleanBanner(buf[:n])
}

// cleanBanner supprime les caractères de contrôle toxiques qui pourraient corrompre l'UI
func cleanBanner(data []byte) string {
	var sb strings.Builder
	sb.Grow(len(data)) // Pré-allocation de capacité pour éviter le re-sizing
	for _, b := range data {
		if b >= 32 && b <= 126 {
			sb.WriteByte(b)
		}
	}
	return strings.TrimSpace(sb.String())
}
