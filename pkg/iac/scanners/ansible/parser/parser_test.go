package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProject(t *testing.T) {
	fsys := os.DirFS(filepath.Join("testdata", "sample-proj"))

	projects, err := New(fsys).Parse(".")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	tasks := projects[0].ListTasks()
	assert.Len(t, tasks, 4)
}
