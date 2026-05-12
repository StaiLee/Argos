package report

import "argos/internal/models"

// Exporter définit la capacité de générer un rapport de mission.
type Exporter interface {
	Export(results []*models.ScanResult, filepath string) error
}
