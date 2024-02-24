package ansible

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sync"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/ansible"
	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var (
	_ scanners.FSScanner          = (*Scanner)(nil)
	_ options.ConfigurableScanner = (*Scanner)(nil)
)

type Scanner struct {
	mu sync.Mutex

	opts                  []options.ScannerOption
	debug                 debug.Logger
	policyDirs            []string
	policyReaders         []io.Reader
	loadEmbeddedPolicies  bool
	loadEmbeddedLibraries bool
	frameworks            []framework.Framework
	regoOnly              bool

	regoScanner *rego.Scanner
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		opts: opts,
	}
	for _, opt := range opts {
		opt(scanner)
	}
	return scanner
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "ansible", "scanner")
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbeddedPolicies = b
}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	s.loadEmbeddedLibraries = b
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetRegoOnly(regoOnly bool) {
	s.regoOnly = regoOnly
}

func (s *Scanner) SetSpec(spec string)                    {}
func (s *Scanner) SetPolicyFilesystem(_ fs.FS)            {}
func (s *Scanner) SetDataFilesystem(_ fs.FS)              {}
func (s *Scanner) SetRegoErrorLimit(_ int)                {}
func (s *Scanner) SetTraceWriter(_ io.Writer)             {}
func (s *Scanner) SetPerResultTracingEnabled(_ bool)      {}
func (s *Scanner) SetDataDirs(_ ...string)                {}
func (s *Scanner) SetPolicyNamespaces(_ ...string)        {}
func (s *Scanner) SetSkipRequiredCheck(skipRequired bool) {}

func (s *Scanner) Name() string {
	return "Ansible"
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	p := parser.New(fsys)
	projects, err := p.Parse(dir)
	if err != nil {
		return nil, err
	}
	if err := s.initRegoScanner(fsys); err != nil {
		return nil, err
	}

	return s.scanProjects(ctx, fsys, projects)
}

func (s *Scanner) scanProjects(ctx context.Context, fsys fs.FS, projects []*parser.AnsibleProject) (scan.Results, error) {
	var results scan.Results

	for _, proj := range projects {
		res, err := s.scanProject(ctx, fsys, proj)
		if err != nil {
			return nil, err
		}
		results = append(results, res...)
	}
	return results, nil

}

func (s *Scanner) scanProject(ctx context.Context, fsys fs.FS, project *parser.AnsibleProject) (scan.Results, error) {
	tasks := project.ListTasks()
	state := adapter.Adapt(tasks)

	var results scan.Results

	if !s.regoOnly {
		for _, rule := range rules.GetRegistered(s.frameworks...) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			if rule.GetRule().RegoPackage != "" {
				continue
			}
			ruleResults := rule.Evaluate(&state)
			if len(ruleResults) > 0 {
				results = append(results, ruleResults...)
			}
		}
	}

	regoResults, err := s.regoScanner.ScanInput(ctx, rego.Input{
		Path:     project.Path(),
		FS:       fsys,
		Contents: state.ToRego(),
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}

	return append(results, regoResults...), nil
}

func (s *Scanner) initRegoScanner(fsys fs.FS) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return nil
	}
	regoScanner := rego.NewScanner(types.SourceCloud, s.opts...)
	regoScanner.SetParentDebugLogger(s.debug)
	if err := regoScanner.LoadPolicies(s.loadEmbeddedLibraries, s.loadEmbeddedPolicies, fsys, s.policyDirs, s.policyReaders); err != nil {
		return err
	}
	s.regoScanner = regoScanner
	return nil
}
