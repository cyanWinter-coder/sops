package sops

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// pathErrorCipher fails decryption for any additional data containing the
// marker and succeeds otherwise, so the error-path and atomicity behavior
// can be exercised deterministically.
type pathErrorCipher struct {
	marker string
}

func (c pathErrorCipher) Encrypt(value interface{}, key []byte, additionalData string) (string, error) {
	return "ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]", nil
}

func (c pathErrorCipher) Decrypt(ciphertext string, key []byte, additionalData string) (interface{}, error) {
	if strings.Contains(additionalData, c.marker) {
		return nil, errors.New("simulated decryption failure")
	}
	return "decrypted", nil
}

// snapshotBranches renders branches as a stable string so a before/after
// comparison does not depend on reflect and survives interface wrapping.
func snapshotBranches(branches TreeBranches) string {
	var b strings.Builder
	writeBranchSnapshot(&b, branches[0])
	return b.String()
}

func writeBranchSnapshot(b *strings.Builder, branch TreeBranch) {
	for _, item := range branch {
		if key, ok := item.Key.(string); ok {
			b.WriteString(key)
			b.WriteString("=")
		}
		writeValueSnapshot(b, item.Value)
		b.WriteString(";")
	}
}

func writeValueSnapshot(b *strings.Builder, value interface{}) {
	switch value := value.(type) {
	case TreeBranch:
		writeBranchSnapshot(b, value)
	case []interface{}:
		for i, child := range value {
			fmt.Fprintf(b, "[%d]", i)
			writeValueSnapshot(b, child)
		}
	default:
		fmt.Fprintf(b, "%v", value)
	}
}

// TestDecryptAtomicOnFailure ensures a failing decryption leaves the tree
// exactly as it was, with no mixture of encrypted and decrypted values.
func TestDecryptAtomicOnFailure(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "good", Value: "ENC[AES256_GCM,data:g,iv:y,tag:z,type:str]"},
		TreeItem{Key: "bad", Value: TreeBranch{
			TreeItem{Key: "leaf", Value: "ENC[AES256_GCM,data:b,iv:y,tag:z,type:str]"},
		}},
	}}
	tree := &Tree{Branches: branches, Metadata: Metadata{}}
	original := snapshotBranches(tree.Branches)

	_, err := tree.Decrypt(bytes.Repeat([]byte("k"), 32), pathErrorCipher{marker: "bad"})
	if err == nil {
		t.Fatal("expected decryption to fail")
	}
	if got := snapshotBranches(tree.Branches); got != original {
		t.Fatalf("tree was modified by a failed decryption\nwant: %s\ngot:  %s", original, got)
	}
}

// TestDecryptErrorCarriesPath ensures the reported error names the map
// location that failed.
func TestDecryptErrorCarriesPath(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "outer", Value: TreeBranch{
			TreeItem{Key: "broken", Value: "ENC[AES256_GCM,data:b,iv:y,tag:z,type:str]"},
		}},
	}}
	tree := &Tree{Branches: branches, Metadata: Metadata{}}
	_, err := tree.Decrypt(bytes.Repeat([]byte("k"), 32), pathErrorCipher{marker: "broken"})
	if err == nil {
		t.Fatal("expected decryption to fail")
	}
	message := err.Error()
	for _, want := range []string{"outer", "broken"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q does not contain path component %q", message, want)
		}
	}
}

// TestDecryptErrorCarriesListIndex ensures list positions appear in the
// error path as an index.
func TestDecryptErrorCarriesListIndex(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "items", Value: []interface{}{
			"ENC[AES256_GCM,data:a,iv:y,tag:z,type:str]",
			"ENC[AES256_GCM,data:b,iv:y,tag:z,type:str]",
		}},
	}}
	tree := &Tree{Branches: branches, Metadata: Metadata{}}
	_, err := tree.Decrypt(bytes.Repeat([]byte("k"), 32), pathErrorCipher{marker: "items"})
	if err == nil {
		t.Fatal("expected decryption to fail")
	}
	if !strings.Contains(err.Error(), "[0]") {
		t.Fatalf("error %q does not contain list index [0]", err.Error())
	}
}
