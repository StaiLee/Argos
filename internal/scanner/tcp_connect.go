package scanner

import (
	"context"
	"net"
	"strconv"
	"time"

	"argos/internal/models"
	"argos/internal/network"
)

// TCPConnectProbe est le scanner classique, bruyant mais fiable à 100%.
// Il supporte le routage via les proxies SOCKS5 (Ghost Mode).
type TCPConnectProbe struct{}

// NewTCPConnectProbe initialise l'ogive TCP.
func NewTCPConnectProbe() *TCPConnectProbe {
	return &TCPConnectProbe{}
}

func (p *TCPConnectProbe) Name() string {
	return "tcp-connect"
}

func (p *TCPConnectProbe) Scan(ctx context.Context, target models.Target, dialer network.ContextDialer, timeout time.Duration) *models.ScanResult {
	// 1. Fail-fast : Si l'opération globale est annulée (Ctrl+C), on avorte immédiatement.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	addr := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))

	// 2. Limitation stricte du temps de vol du paquet
	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 3. Frappe réseau
	conn, err := dialer.DialContext(ctxTimeout, "tcp", addr)
	if err != nil {
		// PORT FERMÉ OU FILTRÉ : Retour nil absolu. ZÉRO allocation mémoire.
		return nil
	}

	// Si on arrive ici, le port est OUVERT. On ferme la connexion proprement.
	conn.Close()

	// 4. Construction de l'artefact de renseignement (Alloué uniquement en cas de succès)
	svc := models.CommonPorts[target.Port]
	if svc == "" {
		svc = "TCP"
	}

	risk := models.RiskWeights[target.Port]
	if risk == 0 {
		risk = 1
	}

	return &models.ScanResult{
		IP:        target.IP,
		Port:      target.Port,
		Service:   svc,
		State:     "open", // On ne renvoie que les ports ouverts
		RiskScore: risk,
		Timestamp: time.Now(),
	}
}
