package scanner

import (
	"context"
	"time"

	"argos/internal/models"
	"argos/internal/network"
)

// Probe définit le comportement standard d'un module de balayage réseau.
type Probe interface {
	// Name retourne l'identifiant tactique du scanner (ex: "tcp-connect").
	Name() string

	// Scan exécute la frappe. Si le port est fermé, DOIT retourner nil pour préserver la RAM.
	Scan(ctx context.Context, target models.Target, dialer network.ContextDialer, timeout time.Duration) *models.ScanResult
}
