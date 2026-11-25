package stores

import (
	"github.com/getsops/sops/v3"
)

// RestoreRepresentations overlays representation wrappers previously
// collected with CollectRepresentations onto an encrypted tree. Only
// locations holding an encrypted ENC[...] string receive a wrapper, so
// values that were never encrypted (e.g. entries under an unencrypted
// suffix) keep whatever value the encrypted parse already produced.
func RestoreRepresentations(branches sops.TreeBranches, entries []sops.Representation) sops.TreeBranches {
	for _, entry := range entries {
		restoreAt(branches, entry.Path, entry.Wrapper)
	}
	return branches
}

func restoreAt(branches sops.TreeBranches, path []interface{}, wrapper interface{}) {
	if len(path) == 0 || len(branches) == 0 {
		return
	}
	// Metadata-free trees always carry their content in the first branch.
	restoreInBranch(branches[0], path, wrapper)
}

func restoreInBranch(branch sops.TreeBranch, path []interface{}, wrapper interface{}) {
	if len(path) == 0 {
		return
	}
	key, ok := path[0].(string)
	if !ok {
		return
	}
	for i := range branch {
		if name, isString := branch[i].Key.(string); !isString || name != key {
			continue
		}
		if len(path) == 1 {
			if isEncryptedString(branch[i].Value) {
				branch[i].Value = withEncryptedValue(wrapper, branch[i].Value)
			}
			return
		}
		restoreInValue(branch[i].Value, path[1:], wrapper)
		return
	}
}

func restoreInValue(value interface{}, path []interface{}, wrapper interface{}) {
	switch node := value.(type) {
	case sops.TreeBranch:
		restoreInBranch(node, path, wrapper)
	case []interface{}:
		index, ok := path[0].(int)
		if !ok || index < 0 || index >= len(node) {
			return
		}
		if len(path) == 1 {
			if isEncryptedString(node[index]) {
				node[index] = withEncryptedValue(wrapper, node[index])
			}
			return
		}
		restoreInValue(node[index], path[1:], wrapper)
	}
}

// isEncryptedString reports whether a tree value is an encrypted scalar
// (the AES cipher's ENC[...] marker).
func isEncryptedString(value interface{}) bool {
	text, ok := value.(string)
	return ok && len(text) >= 4 && text[:4] == "ENC["
}

// withEncryptedValue returns a copy of wrapper whose current value is the
// encrypted ciphertext, ready to be decrypted by the tree walk.
func withEncryptedValue(wrapper, encrypted interface{}) interface{} {
	switch w := wrapper.(type) {
	case sops.Scalar:
		w.Value = encrypted
		return w
	case sops.RawNumber:
		w.Value = encrypted
		return w
	default:
		return wrapper
	}
}
