package network

import (
	"encoding/json"
	"math/rand"
	"os"
	"sync"

	"argos/internal/models"
)

// ProxyManager gère le pool d'IP de rebond (Ghost Engine).
// Il est conçu pour résister à la concurrence extrême de la phase BLITZ.
type ProxyManager struct {
	pool []models.ProxyDef
	mu   sync.RWMutex // Autorise des milliers de lectures simultanées
}

// NewProxyManager initialise le moteur de rebond.
func NewProxyManager() *ProxyManager {
	return &ProxyManager{
		pool: make([]models.ProxyDef, 0),
	}
}

// Load charge la liste JSON en mémoire.
func (pm *ProxyManager) Load(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	var proxies []models.ProxyDef
	if err := json.Unmarshal(data, &proxies); err != nil {
		return err
	}

	// Lock exclusif uniquement pendant l'écriture initiale
	pm.mu.Lock()
	pm.pool = proxies
	pm.mu.Unlock()

	return nil
}

// GetRandom extrait un noeud de rebond aléatoire sans bloquer les autres workers.
func (pm *ProxyManager) GetRandom() *models.ProxyDef {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.pool) == 0 {
		return nil
	}
	return &pm.pool[rand.Intn(len(pm.pool))]
}

// Count retourne le nombre de proxies armés.
func (pm *ProxyManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.pool)
}
