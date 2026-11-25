package common

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to the file at path atomically: the data
// is written to a temporary file in the same directory, synced to disk,
// and then renamed over the target. At any time either the old or the
// new contents are visible at path; a crash can never leave a
// half-written file behind. The file mode of an existing target is
// preserved, new files are created with mode 0600.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("could not create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup; once the rename succeeds this is a no-op.
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("could not write temporary file %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("could not sync temporary file %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("could not close temporary file %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("could not set permissions on temporary file %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("could not replace %s: %w", path, err)
	}
	return nil
}
