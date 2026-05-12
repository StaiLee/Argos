package ui

import (
	"argos/internal/core"
	"argos/internal/models"

	tea "github.com/charmbracelet/bubbletea"
)

// Start déploie l'interface utilisateur TUI (God Eye)
func Start(e *core.Engine) ([]*models.ScanResult, error) {
	// Instanciation du modèle (défini dans dashboard.go)
	d := newDashboard(e)

	// Lancement en mode AltScreen (Plein écran dédié, restaure le terminal à la fin)
	p := tea.NewProgram(d, tea.WithAltScreen())

	_, err := p.Run()

	// On retourne les pépites capturées pour l'export HTML/JSON
	return d.resultsList, err
}
