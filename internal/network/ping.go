package network

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// IsAlive effectue un "TCP Ping Sweep" ultra-rapide.
// Retourne true si l'hôte répond sur au moins l'un des ports vitaux.
func IsAlive(ctx context.Context, ip string, timeout time.Duration) bool {
	// Les artères principales d'un réseau
	vitalPorts := []int{80, 443, 22, 445, 3389, 8080}

	alive := make(chan bool, 1)
	var wg sync.WaitGroup

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, port := range vitalPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, strconv.Itoa(p))

			// Dial direct sans proxy pour le ping sweep
			dialer := &net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctxTimeout, "tcp", addr)

			if err == nil {
				conn.Close()
				select {
				case alive <- true: // Le premier qui répond gagne
				default:
				}
				cancel() // On annule les autres sondes instantanément
			}
		}(port)
	}

	// Goroutine pour fermer le channel proprement une fois tous les tests finis
	go func() {
		wg.Wait()
		close(alive)
	}()

	// Si on reçoit 'true', il est en vie. Sinon le canal se ferme = false.
	return <-alive
}
