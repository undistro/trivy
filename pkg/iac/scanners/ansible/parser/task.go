package parser

import (
	"io/fs"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"gopkg.in/yaml.v3"
)

type Variables map[string]any

type Tasks []*Task

func (t Tasks) GetModules(names ...string) []Module {
	var modules []Module

	for _, task := range t {
		for _, name := range names {
			if module, exists := task.GetModule(name); exists {
				modules = append(modules, module)
			}
		}
	}

	return modules
}

type Task struct {
	inner    taskInner
	rng      Range
	metadata iacTypes.Metadata

	raw map[string]*Attribute
}

type taskInner struct {
	Name  string    `yaml:"name"`
	Block []*Task   `yaml:"block"`
	Vars  Variables `yaml:"vars"`
}

func (t *Task) UnmarshalYAML(node *yaml.Node) error {
	t.rng = RangeFromNode(node)

	var rawMap map[string]*Attribute
	if err := node.Decode(&rawMap); err != nil {
		return err
	}

	t.raw = rawMap
	if err := node.Decode(&t.inner); err != nil {
		return err
	}
	for _, b := range t.inner.Block {
		b.metadata.SetParentPtr(&t.metadata)
	}
	return nil
}

func (t *Task) GetModule(name string) (Module, bool) {
	val, exists := t.raw[name]
	if !exists {
		return Module{}, false
	}

	if !val.IsMap() {
		return Module{}, false
	}

	params := val.AsMap()

	return Module{
		metadata: val.Metadata(),
		attrs:    params,
	}, true
}

func (t *Task) Compile() Tasks {
	// TODO: handle include_role, import_role, include_tasks and import_tasks
	switch {
	case len(t.inner.Block) > 0:
		return t.compileBlockTasks()
	default:
		return Tasks{t}
	}
}

func (t *Task) compileBlockTasks() Tasks {
	var res []*Task
	for _, task := range t.inner.Block {
		res = append(res, task.Compile()...)
	}
	return res
}

// TODO update attribute metadata
func (t *Task) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	t.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, t.rng.startLine, t.rng.endLine, "", fsys),
		"task", // TODO add reference
	)
	t.metadata.SetParentPtr(parent)

	for _, attr := range t.raw {
		attr.updateMetadata(fsys, &t.metadata, path)
	}
}
