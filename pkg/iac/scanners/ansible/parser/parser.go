package parser

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

const ansibleCfgFile = "ansible.cfg"

type AnsibleProject struct {
	path string

	cfg AnsibleConfig
	// inventory Inventory
	mainPlaybook Playbook
	playbooks    []Playbook
}

func (p *AnsibleProject) Path() string {
	return p.path
}

func (p *AnsibleProject) ListTasks() Tasks {
	var res Tasks
	if p.mainPlaybook != nil {
		res = append(res, p.mainPlaybook.Compile()...)
	} else {
		for _, playbook := range p.playbooks {
			res = append(res, playbook.Compile()...)
		}
	}
	return res
}

type AnsibleConfig struct{}

type Parser struct {
	fsys fs.FS
}

func New(fsys fs.FS) *Parser {
	return &Parser{
		fsys: fsys,
	}
}

func (p *Parser) Parse(root string) ([]*AnsibleProject, error) {
	projectPaths, err := p.autoDetectProjects(root)
	if err != nil {
		return nil, err
	}

	var projects []*AnsibleProject

	for _, projectPath := range projectPaths {
		project, err := p.parse(projectPath)
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, nil
}

func (p *Parser) parse(root string, playbooks ...string) (*AnsibleProject, error) {
	project, err := p.initProject(root)
	if err != nil {
		return nil, err
	}

	if len(playbooks) == 0 {
		playbooks, err = p.resolvePlaybooksPaths(project)
		if err != nil {
			return nil, err
		}
	}

	if err := p.parsePlaybooks(project, playbooks); err != nil {
		return nil, err
	}
	return project, nil
}

func (p *Parser) initProject(root string) (*AnsibleProject, error) {
	cfg, err := p.readAnsibleConfig(root)
	if err != nil {
		return nil, fmt.Errorf("failed to read Ansible config: %w", err)
	}

	project := &AnsibleProject{
		path: root,
		cfg:  cfg,
	}

	return project, nil
}

func (p *Parser) parsePlaybooks(project *AnsibleProject, paths []string) error {
	for _, path := range paths {
		playbook, err := p.LoadPlaybook(nil, path)
		if err != nil {
			return err
		}

		if playbook == nil {
			return nil
		}

		if isMainPlaybook(path) {
			project.mainPlaybook = playbook
		} else {
			project.playbooks = append(project.playbooks, playbook)
		}
	}
	return nil
}

func (p *Parser) LoadPlaybook(sourceMetadata *iacTypes.Metadata, path string) (Playbook, error) {

	f, err := p.fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var playbook Playbook
	if err := yaml.NewDecoder(f).Decode(&playbook); err != nil {
		// not all YAML files are playbooks.
		log.Printf("Failed to decode playbook %q: %s", path, err)
		return nil, nil
	}
	for _, play := range playbook {
		play.UpdateMetadata(p.fsys, sourceMetadata, path)

		// TODO: load roles
	}
	return playbook, nil
}

func (p *Parser) readAnsibleConfig(projectPath string) (AnsibleConfig, error) {
	return AnsibleConfig{}, nil
}

func (p *Parser) resolvePlaybooksPaths(project *AnsibleProject) ([]string, error) {
	entries, err := fs.ReadDir(p.fsys, project.path)
	if err != nil {
		return nil, err
	}

	var res []string

	for _, entry := range entries {
		if isYAMLFile(entry.Name()) {
			res = append(res, filepath.Join(project.path, entry.Name()))
		}
	}

	return res, nil
}

func (p *Parser) autoDetectProjects(root string) ([]string, error) {
	var res []string
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		if !p.isAnsibleProject(path) {
			return nil
		}
		res = append(res, path)
		return fs.SkipDir
	}

	if err := fs.WalkDir(p.fsys, root, walkFn); err != nil {
		return nil, err
	}

	return res, nil
}

// TODO if there are no directories listed below, then find the playbook among yaml files
func (p *Parser) isAnsibleProject(path string) bool {
	requiredDirs := []string{
		ansibleCfgFile, "site.yml", "site.yaml", "group_vars", "host_vars", "inventory", "playbooks",
	}
	for _, filename := range requiredDirs {
		if isPathExists(p.fsys, filepath.Join(path, filename)) {
			return true
		}
	}

	if entries, err := doublestar.Glob(p.fsys, "**/roles/**/{tasks,defaults,vars}"); err == nil && len(entries) > 0 {
		return true
	}

	if entries, err := doublestar.Glob(p.fsys, "*.{.yml,yaml}"); err == nil && len(entries) > 0 {
		return true
	}

	return false
}

func isPathExists(fsys fs.FS, path string) bool {
	if filepath.IsAbs(path) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	if _, err := fs.Stat(fsys, path); err == nil {
		return true
	}
	return false
}

func isYAMLFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".yaml" || ext == ".yml"
}

func isMainPlaybook(filepath string) bool {
	return cutExtension(path.Base(filepath)) == "site"
}

func cutExtension(path string) string {
	ext := filepath.Ext(path)
	return path[0 : len(path)-len(ext)]
}
