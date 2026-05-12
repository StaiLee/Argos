package core

import (
	"context"
	"math/rand"
	"time"

	"argos/internal/models"
	"argos/internal/network"
)

// GenerateJobs est le Feeder. Il génère les cibles à la volée.
func GenerateJobs(ctx context.Context, ips []string, ports []int, randomize bool, skipPing bool) (<-chan models.Target, uint64) {
	jobs := make(chan models.Target, 5000)
	var actualJobs uint64 // On va recalculer le vrai nombre de cibles

	go func() {
		defer close(jobs)

		if randomize {
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			r.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
		}

		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// OPTIMISATION MILITAIRE : Host Discovery
			// Si on scanne un subnet entier, on vérifie si la cible est en vie.
			if len(ips) > 1 && !skipPing {
				if !network.IsAlive(ctx, ip, 400*time.Millisecond) {
					continue // CIBLE MORTE : On économise des milliers de requêtes
				}
			}

			// La cible est vivante (ou on a forcé le scan avec skipPing)
			for _, port := range ports {
				target := models.Target{IP: ip, Port: port}
				select {
				case <-ctx.Done():
					return
				case jobs <- target:
				}
			}
		}
	}()

	// Si le Ping est actif, le nombre de jobs réel sera calculé dynamiquement,
	// mais pour la barre de progression initiale, on renvoie le max théorique (ou une estimation).
	actualJobs = uint64(len(ips) * len(ports))
	return jobs, actualJobs
}
