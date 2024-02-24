package ansible

import (
	"os"
	"path/filepath"
	"slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

const (
	version      = 1
	analyzerType = analyzer.TypeAnsible
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newAnsibleConfigAnalyzer)
}

type ansibleConfigAnalyzer struct {
	*config.Analyzer
}

func newAnsibleConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, misconf.NewAnsibleScanner, opts)
	if err != nil {
		return nil, err
	}
	return &ansibleConfigAnalyzer{Analyzer: a}, nil
}

// Required overrides config.Analyzer.Required() and check if the given file is JSON.
func (a *ansibleConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains([]string{".yml", ".yaml"}, filepath.Ext(filePath))
}
