package core

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"argos/internal/identity"
	"argos/internal/models"
	"argos/internal/network"
	"argos/internal/scanner"
)

// Engine est le chef d'orchestre. Il coordonne les frappes.
type Engine struct {
	Profile  models.Profile
	Scanner  scanner.Probe
	ProxyMgr *network.ProxyManager

	TotalJobs uint64
	Completed uint64 // Compteur lock-free ultra-rapide pour l'UI

	ResultsChan chan *models.ScanResult
}

func NewEngine(p models.Profile, s scanner.Probe, pm *network.ProxyManager, total uint64) *Engine {
	return &Engine{
		Profile:   p,
		Scanner:   s,
		ProxyMgr:  pm,
		TotalJobs: total,
		// Buffer généreux pour les Pépites (les ports trouvés ouverts)
		ResultsChan: make(chan *models.ScanResult, 2000),
	}
}

// Run déploie le régiment. C'est une méthode non-bloquante.
func (e *Engine) Run(ctx context.Context, jobs <-chan models.Target) {
	var wg sync.WaitGroup

	// 1. Déploiement massif des Goroutines (jusqu'à 2000 en mode BLITZ)
	for i := 0; i < e.Profile.Threads; i++ {
		wg.Add(1)
		go e.worker(ctx, jobs, &wg)
	}

	// 2. Superviseur fantôme : attend la fin des combats pour sceller les rapports
	go func() {
		wg.Wait()
		close(e.ResultsChan) // Signale au TUI que la mission est terminée
	}()
}

// worker est l'unité de base. Elle boucle tant que le canal jobs n'est pas fermé.
func (e *Engine) worker(ctx context.Context, jobs <-chan models.Target, wg *sync.WaitGroup) {
	defer wg.Done()

	for target := range jobs {
		// 1. Jitter (Délai tactique) pour le mode SHADOW
		if e.Profile.Delay > 0 {
			jitter := time.Duration(rand.Int63n(int64(e.Profile.Delay)))
			// On utilise un select pour que le délai soit interruptible si le scan est annulé
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter):
			}
		}

		// 2. Demande d'un Dialer (Potentiellement muté en SOCKS5 via le Ghost Engine)
		var proxyDef *models.ProxyDef
		if e.ProxyMgr != nil && e.ProxyMgr.Count() > 0 {
			proxyDef = e.ProxyMgr.GetRandom()
		}
		dialer := network.BuildDialer(proxyDef)

		// 3. Frappe Principale (Zéro-allocation si fermé)
		result := e.Scanner.Scan(ctx, target, dialer, e.Profile.Timeout)

		// 4. Mode TITAN : Si la porte est ouverte, on enfonce l'Intelligence Artificielle
		if result != nil && e.Profile.DeepScan {
			enrichIdentity(ctx, result, dialer, e.Profile.Timeout)
		}

		// 5. Incrémentation Lock-Free du compteur (Lu par le TUI)
		atomic.AddUint64(&e.Completed, 1)

		// 6. Signalement (Uniquement si c'est une trouvaille validée)
		if result != nil {
			select {
			case <-ctx.Done():
				return
			case e.ResultsChan <- result:
			}
		}
	}
}

// enrichIdentity effectue l'escalade de reconnaissance (Deep Scan).
func enrichIdentity(ctx context.Context, res *models.ScanResult, dialer network.ContextDialer, timeout time.Duration) {
	if res.Port == 80 || res.Port == 443 || res.Port == 8080 || res.Port == 8443 {
		// Vecteur Web
		title, srv := identity.ProbeHTTP(ctx, res.IP, res.Port, dialer, timeout)
		res.WebTitle = title
		if srv != "Unknown" && srv != "" {
			res.Banner = srv
		}

		// Vecteur TLS
		if res.Port == 443 || res.Port == 8443 {
			cn := identity.ProbeTLS(ctx, res.IP, res.Port, dialer, timeout)
			if cn != "" && res.WebTitle == "No Title" {
				res.WebTitle = "[TLS] " + cn
			}
		}
	} else {
		// Vecteur Brut (SSH, FTP, etc)
		res.Banner = identity.GrabBanner(ctx, res.IP, res.Port, dialer, timeout)
	}
}
