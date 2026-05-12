package network

import (
	"context"
	"net"
	"strings"

	"golang.org/x/net/proxy"

	"argos/internal/models"
)

// ContextDialer est le contrat absolu pour nos sockets.
// Il exige la prise en charge de l'annulation via le Context Go.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// BuildDialer forge le point de sortie réseau.
// Si le mode Ghost est actif (ProxyDef fourni), la socket est mutée via SOCKS5.
func BuildDialer(p *models.ProxyDef) ContextDialer {
	// BaseDialer optimisé : on refuse le KeepAlive car on fait du "Hit & Run".
	baseDialer := &net.Dialer{
		KeepAlive: -1,
	}

	// Si un noeud de rebond SOCKS5 est injecté, on l'encapsule.
	if p != nil && strings.HasPrefix(p.Protocol, "socks5") {
		d, err := proxy.SOCKS5("tcp", p.Address, nil, baseDialer)
		if err == nil {
			// On s'assure que le wrapper SOCKS5 respecte notre contrat d'annulation
			if ctxDialer, ok := d.(proxy.ContextDialer); ok {
				return ctxDialer
			}
		}
	}

	// Fallback implicite : Frappe directe (IP réelle exposée).
	return baseDialer
}
