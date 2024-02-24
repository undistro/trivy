package ansible

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXxx(t *testing.T) {
	fsys := fstest.MapFS{
		"playbook.yaml": {
			Data: []byte(`---
- name: Update web servers
  hosts: localhost

  tasks:
  - name: Ensure apache is at the latest version
    s3_bucket:
      name: mys3bucket
      public_access:
`),
		},
	}

	scanner := New(
		options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithEmbeddedPolicies(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fsys, ".")
	require.NoError(t, err)

	failed := results.GetFailed()
	assert.NotEmpty(t, failed)
}
