package report

import (
	"encoding/json"
	"os"

	"argos/internal/models"
)

type JSONExporter struct{}

func (e *JSONExporter) Export(results []*models.ScanResult, filepath string) error {
	// Prévention d'un JSON "null" si aucun port n'est trouvé. On force un tableau vide "[]".
	if results == nil {
		results = make([]*models.ScanResult, 0)
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0644)
}
