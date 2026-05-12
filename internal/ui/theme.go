package ui

import "github.com/charmbracelet/lipgloss"

type Theme struct {
	Primary   lipgloss.Color
	Secondary lipgloss.Color
	Text      lipgloss.Color
	Gradient  []string
}

// GetTheme traduit le string de configuration en vrai rendu visuel
func GetTheme(name string) Theme {
	switch name {
	case "blitz":
		return Theme{
			Primary:   lipgloss.Color("#FF2200"),
			Secondary: lipgloss.Color("#FF8800"),
			Text:      lipgloss.Color("#FFCC00"),
			Gradient:  []string{"#FF0000", "#FF4400", "#FF8800"},
		}
	case "titan":
		return Theme{
			Primary:   lipgloss.Color("#00FFFF"),
			Secondary: lipgloss.Color("#0066FF"),
			Text:      lipgloss.Color("#E0FFFF"),
			Gradient:  []string{"#0000FF", "#0088FF", "#00FFFF"},
		}
	case "shadow":
		return Theme{
			Primary:   lipgloss.Color("#FFFFFF"),
			Secondary: lipgloss.Color("#666666"),
			Text:      lipgloss.Color("#AAAAAA"),
			Gradient:  []string{"#333333", "#888888", "#FFFFFF"},
		}
	default: // "scout"
		return Theme{
			Primary:   lipgloss.Color("#00FF00"),
			Secondary: lipgloss.Color("#004400"),
			Text:      lipgloss.Color("#AAFFAA"),
			Gradient:  []string{"#003300", "#00AA00", "#00FF00"},
		}
	}
}
