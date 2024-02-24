package parser

import (
	"io/fs"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"gopkg.in/yaml.v3"
)

type Playbook []*Play

func (p Playbook) Compile() Tasks {
	var res Tasks
	for _, play := range p {
		res = append(res, play.Compile()...)
	}
	return res
}

type Play struct {
	inner playInner

	metadata iacTypes.Metadata
	rng      Range

	raw map[string]any
}

type playInner struct {
	Name            string            `yaml:"name"`
	ImportPlaybook  string            `yaml:"import_playbook"`
	Hosts           string            `yaml:"hosts"`
	RoleDefinitions []*RoleDefinition `yaml:"roles"`
	PreTasks        []*Task           `yaml:"pre_tasks"`
	Tasks           []*Task           `yaml:"tasks"`
	PostTasks       []*Task           `yaml:"post_tasks"`
	Vars            Variables         `yaml:"vars"`
	VarFiles        []string          `yaml:"var_files"`
}

func (p *Play) UnmarshalYAML(node *yaml.Node) error {
	p.rng = RangeFromNode(node)

	if err := node.Decode(&p.raw); err != nil {
		return err
	}
	return node.Decode(&p.inner)
}

// Compile compiles and returns the task list for this play, compiled from the
// roles (which are themselves compiled recursively) and/or the list of
// tasks specified in the play.
func (p *Play) Compile() Tasks {
	var res Tasks

	// TODO: handle import_playbook, include_playbook and roles

	for _, task := range p.listTasks() {
		res = append(res, task.Compile()...)
	}

	return res
}

func (p *Play) UpdateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {

	p.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, p.rng.startLine, p.rng.endLine, "", fsys),
		"play",
	)
	p.metadata.SetParentPtr(parent)

	for _, roleDef := range p.inner.RoleDefinitions {
		roleDef.updateMetadata(fsys, &p.metadata, path)
	}

	for _, task := range p.listTasks() {
		task.updateMetadata(fsys, &p.metadata, path)
	}
}

func (p *Play) listTasks() Tasks {
	res := make(Tasks, 0, len(p.inner.PreTasks)+len(p.inner.Tasks)+len(p.inner.PostTasks))
	res = append(res, p.inner.PreTasks...)
	res = append(res, p.inner.Tasks...)
	res = append(res, p.inner.PostTasks...)
	return res
}

type RoleDefinition struct {
	inner roleDefinitionInner

	metadata iacTypes.Metadata
	rng      Range
}

type roleDefinitionInner struct {
	Name string         `yaml:"role"`
	Vars map[string]any `yaml:"vars"`
}

func (r *RoleDefinition) UnmarshalYAML(node *yaml.Node) error {
	r.rng = RangeFromNode(node)

	// a role can be a string or a dictionary
	if node.Kind == yaml.ScalarNode {
		r.inner.Name = node.Value
		return nil
	}

	return node.Decode(&r.inner)
}

func (r *RoleDefinition) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	r.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, r.rng.startLine, r.rng.endLine, "", fsys),
		"",
	)
	r.metadata.SetParentPtr(parent)
}
