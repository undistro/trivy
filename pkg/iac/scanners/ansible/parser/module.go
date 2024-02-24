package parser

import (
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Module struct {
	metadata iacTypes.Metadata

	attrs map[string]*Attribute
}

func (m *Module) Metadata() iacTypes.Metadata {
	return m.metadata
}

func (b *Module) GetAttr(name string) *Attribute {
	return b.attrs[name]
}

func (b *Module) GetNestedAttr(path string) *Attribute {
	if path == "" {
		return nil
	}

	parts := strings.SplitN(path, ".", 2)
	attr := b.GetAttr(parts[0])
	if attr == nil {
		return nil
	}
	if len(parts) == 1 {
		return attr
	}
	return attr.GetNestedAttr(parts[1])
}

func (b *Module) GetBoolAttr(name string, defValue ...bool) iacTypes.BoolValue {
	def := iacTypes.BoolDefault(firstOrDefault(defValue), b.metadata)
	attr, exists := b.attrs[name]
	if !exists {
		return def
	}
	val := attr.AsBool()
	if val == nil {
		return def
	}

	return iacTypes.Bool(*val, b.metadata)
}

func (b *Module) GetStringAttr(name string, defValue ...string) iacTypes.StringValue {
	def := iacTypes.StringDefault(firstOrDefault(defValue), b.metadata)
	attr, exists := b.attrs[name]
	if !exists {
		return def
	}
	val := attr.AsString()
	if val == nil {
		return def
	}

	return iacTypes.String(*val, b.metadata)
}

func firstOrDefault[T any](a []T) T {
	if len(a) == 0 {
		return *new(T)
	}
	return a[0]
}
