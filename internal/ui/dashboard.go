package ui

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"argos/internal/core"
	"argos/internal/models"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tickMsg time.Time
type resultMsg *models.ScanResult

type Dashboard struct {
	engine      *core.Engine
	theme       Theme
	viewport    viewport.Model
	logs        []string // Utilisation d'un tableau (Ring Buffer) au lieu d'un Builder
	startTime   time.Time
	width       int
	height      int
	critical    int
	high        int
	low         int
	done        bool
	quitting    bool
	resultsList []*models.ScanResult
}

func newDashboard(e *core.Engine) *Dashboard {
	return &Dashboard{
		engine:    e,
		theme:     GetTheme(e.Profile.ThemeName),
		startTime: time.Now(),
		viewport:  viewport.New(0, 0),
		logs:      make([]string, 0, 100), // Pré-allocation de la capacité
	}
}

func (d *Dashboard) Init() tea.Cmd {
	return tea.Batch(d.tickCmd(), d.listenResults())
}

func (d *Dashboard) tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (d *Dashboard) listenResults() tea.Cmd {
	return func() tea.Msg {
		res, ok := <-d.engine.ResultsChan
		if !ok {
			return nil
		}
		return resultMsg(res)
	}
}

func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.Type == tea.KeyCtrlC {
			d.quitting = true
			return d, tea.Quit
		}
		var cmd tea.Cmd
		d.viewport, cmd = d.viewport.Update(msg)
		return d, cmd

	case tea.WindowSizeMsg:
		d.width, d.height = msg.Width, msg.Height
		d.viewport.Width = d.width - 4
		d.viewport.Height = d.height - 8
		return d, nil

	case tickMsg:
		completed := atomic.LoadUint64(&d.engine.Completed)
		if completed >= d.engine.TotalJobs && !d.done {
			d.done = true
			return d, nil // On stoppe les ticks, mais on laisse l'UI ouverte
		}
		if !d.done {
			return d, d.tickCmd()
		}
		return d, nil

	case resultMsg:
		if msg != nil {
			d.resultsList = append(d.resultsList, msg)
			if msg.RiskScore >= 20 {
				d.critical++
			} else if msg.RiskScore >= 10 {
				d.high++
			} else {
				d.low++
			}

			primaryStyle := lipgloss.NewStyle().Foreground(d.theme.Primary)

			line := fmt.Sprintf("[%s] %-15s:%-5d | %s | %s",
				msg.Timestamp.Format("15:04:05"), msg.IP, msg.Port,
				primaryStyle.Render(msg.Service), msg.Banner)

			// MÉCANIQUE DU RING BUFFER : Protection de la RAM
			d.logs = append(d.logs, line)
			if len(d.logs) > 100 {
				d.logs = d.logs[1:] // On supprime l'élément le plus ancien
			}

			d.viewport.SetContent(strings.Join(d.logs, "\n"))
			d.viewport.GotoBottom()
		}
		return d, d.listenResults()
	}
	return d, nil
}

func (d *Dashboard) View() string {
	if d.quitting {
		return ""
	}

	completed := atomic.LoadUint64(&d.engine.Completed)
	pct := 0.0
	if d.engine.TotalJobs > 0 {
		pct = float64(completed) / float64(d.engine.TotalJobs)
	}

	headerStyle := lipgloss.NewStyle().Foreground(d.theme.Primary).Bold(true).Border(lipgloss.NormalBorder(), false, false, true, false)
	header := headerStyle.Render(fmt.Sprintf("👁 ARGOS PANOPTES | OP: %s | TARGETS: %d", d.engine.Profile.Name, d.engine.TotalJobs))

	statusPhase := "SCANNING..."
	statusColor := d.theme.Primary
	if d.done {
		statusPhase = "MISSION ACCOMPLISHED. [PRESS 'Q' TO EXIT]"
		statusColor = lipgloss.Color("#00FF00")
	}

	statusLine := lipgloss.NewStyle().Foreground(statusColor).Bold(true).Render(statusPhase)

	status := fmt.Sprintf("%s\nProgress: %d/%d (%.1f%%) | CRT: %d HGH: %d LOW: %d",
		statusLine, completed, d.engine.TotalJobs, pct*100, d.critical, d.high, d.low)

	barWidth := d.width - 10
	if barWidth < 10 {
		barWidth = 10
	}
	filled := int(float64(barWidth) * pct)

	bar := lipgloss.NewStyle().Foreground(d.theme.Secondary).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render(strings.Repeat("░", barWidth-filled))

	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("#555555")).Render("[Q] DISCONNECT SYSTEM  |  [ARROWS] SCROLL LOGS")

	return fmt.Sprintf("%s\n\n%s\n\n%s\n%s\n%s", header, d.viewport.View(), status, bar, footer)
}
