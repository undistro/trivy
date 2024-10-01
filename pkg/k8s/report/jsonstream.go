package report

import (
	"bufio"
	"io"

	"github.com/aquasecurity/trivy/pkg/utils/jsonstream"
	"golang.org/x/xerrors"
)

type JSONStreamWriter struct {
	Output io.Writer
	Report string
}

// Write writes the results in JSON format
func (jw JSONStreamWriter) Write(report Report) error {
	var err error
	bufWriter := bufio.NewWriter(jw.Output)
	defer bufWriter.Flush()

	switch jw.Report {
	case AllReport:
		err = jsonstream.Marshal(bufWriter, report)
		if err != nil {
			return xerrors.Errorf("failed to write json: %w", err)
		}
	case SummaryReport:
		err = jsonstream.Marshal(bufWriter, report.consolidate())
		if err != nil {
			return xerrors.Errorf("failed to write json: %w", err)
		}
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, jw.Report)
	}

	return nil
}
