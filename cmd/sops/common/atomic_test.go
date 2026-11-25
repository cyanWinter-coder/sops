package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")

	// New file: created with restrictive permissions.
	require.NoError(t, WriteFileAtomic(path, []byte("first")))
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "first", string(content))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// Existing file: contents replaced, permissions preserved.
	require.NoError(t, os.Chmod(path, 0o640))
	require.NoError(t, WriteFileAtomic(path, []byte("second")))
	content, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "second", string(content))
	info, err = os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())

	// No temporary files are left behind.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "secret.yaml", entries[0].Name())
}
