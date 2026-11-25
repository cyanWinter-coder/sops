package stores

import (
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/stretchr/testify/assert"
)

// TestExtractMetadataKeepsUnknownFields ensures fields this SOPS version
// does not model survive extraction via the raw metadata snapshot.
func TestExtractMetadataKeepsUnknownFields(t *testing.T) {
	branches := sops.TreeBranches{sops.TreeBranch{
		sops.TreeItem{Key: "sops", Value: sops.TreeBranch{
			sops.TreeItem{Key: "lastmodified", Value: "2025-03-23T10:20:30Z"},
			sops.TreeItem{Key: "custom_future_field", Value: "preserve-me"},
			sops.TreeItem{Key: "version", Value: "3.13.1"},
			sops.TreeItem{Key: "age", Value: []interface{}{
				sops.TreeBranch{
					sops.TreeItem{Key: "recipient", Value: "age1x"},
					sops.TreeItem{Key: "enc", Value: "dummy"},
				},
			}},
		}},
	}}
	_, metadata, err := ExtractMetadata(branches, MetadataOpts{Flatten: MetadataFlattenNone})
	assert.Nil(t, err)
	raw := metadata.RawMetadata()
	assert.NotNil(t, raw)
	var found bool
	var order []string
	for _, item := range raw {
		order = append(order, item.Key.(string))
		if item.Key == "custom_future_field" {
			found = true
			assert.Equal(t, "preserve-me", item.Value)
		}
	}
	assert.True(t, found, "unknown field must be retained in raw metadata")
	// Ordering of the source document must be retained verbatim.
	assert.Equal(t, []string{
		"lastmodified", "custom_future_field", "version", "age",
	}, order)
}

// TestSerializeMetadataRoundTripsUnknownField ensures an unknown field and
// the original key ordering come back out when the metadata is serialized.
func TestSerializeMetadataRoundTripsUnknownField(t *testing.T) {
	branches := sops.TreeBranches{sops.TreeBranch{
		sops.TreeItem{Key: "sops", Value: sops.TreeBranch{
			sops.TreeItem{Key: "custom_future_field", Value: "preserve-me"},
			sops.TreeItem{Key: "lastmodified", Value: "2025-03-23T10:20:30Z"},
			sops.TreeItem{Key: "version", Value: "3.13.1"},
			sops.TreeItem{Key: "age", Value: []interface{}{
				sops.TreeBranch{
					sops.TreeItem{Key: "recipient", Value: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw5smwv9m3ue83sqq6dj9d3"},
					sops.TreeItem{Key: "enc", Value: "dummy"},
				},
			}},
		}},
	}}
	_, metadata, err := ExtractMetadata(branches, MetadataOpts{Flatten: MetadataFlattenNone})
	assert.Nil(t, err)

	tree := sops.Tree{Branches: sops.TreeBranches{sops.TreeBranch{}}, Metadata: metadata}
	out, err := SerializeMetadata(tree, MetadataOpts{Flatten: MetadataFlattenNone})
	assert.Nil(t, err)

	sopsEntry := out[0][len(out[0])-1]
	assert.Equal(t, "sops", sopsEntry.Key)
	metaBranch := sopsEntry.Value.(sops.TreeBranch)
	var order []string
	var unknown interface{}
	for _, item := range metaBranch {
		order = append(order, item.Key.(string))
		if item.Key == "custom_future_field" {
			unknown = item.Value
		}
	}
	assert.Equal(t, "preserve-me", unknown)
	// The unknown field stays in its original leading position.
	assert.Equal(t, "custom_future_field", order[0])
}

// TestRepresentationPersistenceRoundTrip serializes captured scalar
// representations into the metadata tree and reads them back, ensuring the
// wrapper metadata survives the trip through generic tree structures.
func TestRepresentationPersistenceRoundTrip(t *testing.T) {
	reps := []sops.Representation{
		{Path: []interface{}{"ratio"}, Wrapper: sops.Scalar{Value: 1, Literal: "1.0", Tag: "!!float", Style: 0}},
		{Path: []interface{}{"list", 0}, Wrapper: sops.Scalar{Value: 31, Literal: "0x1F", Tag: "!!int"}},
		{Path: []interface{}{"big"}, Wrapper: sops.RawNumber{Value: float64(1e21), Literal: "1e21"}},
	}
	item, err := representationsToMetadataBranch(reps)
	assert.Nil(t, err)

	// Rebuild through the generic tree form the stores emit and parse.
	restored, err := representationsFromMetadataBranch(item.Value)
	assert.Nil(t, err)
	assert.Len(t, restored, 3)

	first, ok := restored[0].Wrapper.(sops.Scalar)
	assert.True(t, ok)
	assert.Equal(t, "1.0", first.Literal)
	assert.Equal(t, "!!float", first.Tag)
	assert.Equal(t, []interface{}{"ratio"}, restored[0].Path)

	second := restored[1].Wrapper.(sops.Scalar)
	assert.Equal(t, "0x1F", second.Literal)
	assert.Equal(t, []interface{}{"list", 0}, restored[1].Path)

	third, ok := restored[2].Wrapper.(sops.RawNumber)
	assert.True(t, ok)
	assert.Equal(t, "1e21", third.Literal)
}

// TestRestoreRepresentationsOnlyTouchesEncryptedValues ensures unencrypted
// entries are not overwritten when representation metadata is re-applied.
func TestRestoreRepresentationsOnlyTouchesEncryptedValues(t *testing.T) {
	branches := sops.TreeBranches{sops.TreeBranch{
		sops.TreeItem{Key: "encrypted", Value: "ENC[AES256_GCM,data:x,iv:y,tag:z,type:float]"},
		sops.TreeItem{Key: "plain_unencrypted", Value: "keep-me"},
	}}
	reps := []sops.Representation{
		{Path: []interface{}{"encrypted"}, Wrapper: sops.Scalar{Literal: "1.0", Tag: "!!float"}},
		{Path: []interface{}{"plain_unencrypted"}, Wrapper: sops.Scalar{Literal: "x", Tag: "!!str"}},
	}
	RestoreRepresentations(branches, reps)
	branch := branches[0]
	_, wrapped := branch[0].Value.(sops.Scalar)
	assert.True(t, wrapped, "encrypted value should receive the wrapper")
	assert.Equal(t, "keep-me", branch[1].Value, "unencrypted value must be left alone")
}
