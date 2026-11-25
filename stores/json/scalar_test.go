package json

import (
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/config"
	"github.com/stretchr/testify/assert"
)

// TestJSONFloatLiteralRoundTrip ensures non-canonical float spellings are
// reproduced byte-for-byte instead of being normalized through float64.
func TestJSONFloatLiteralRoundTrip(t *testing.T) {
	store := Store{config: config.JSONStoreConfig{Indent: -1}}
	for _, lit := range []string{"1.0", "1.000", "1e3", "1.5E-2", "0.0"} {
		in := []byte("{\n\t\"v\": " + lit + "\n}")
		branch, err := store.treeBranchFromJSON(in)
		assert.Nil(t, err)
		// The wrapper keeps the literal while remaining a number semantically.
		raw, ok := branch[0].Value.(sops.RawNumber)
		assert.True(t, ok, "literal %s should be wrapped as RawNumber", lit)
		assert.Equal(t, lit, raw.Literal)
		out, err := store.jsonFromTreeBranch(branch)
		assert.Nil(t, err)
		assert.Equal(t, string(in), string(out), "literal %s should round-trip", lit)
	}
}

// TestJSONCanonicalNumberStaysBare ensures canonical numbers keep their
// traditional bare Go types and do not get wrapped.
func TestJSONCanonicalNumberStaysBare(t *testing.T) {
	store := Store{config: config.JSONStoreConfig{Indent: -1}}
	branch, err := store.treeBranchFromJSON([]byte("{\n\t\"i\": 42,\n\t\"f\": 2.5\n}"))
	assert.Nil(t, err)
	values := map[string]interface{}{}
	for _, item := range branch {
		values[item.Key.(string)] = item.Value
	}
	assert.IsType(t, 0, values["i"])
	assert.IsType(t, float64(0), values["f"])
}

// TestJSONLargeIntegerBeyondInt64 ensures integers outside the int64 range
// keep their exact literal instead of being mangled by float64 decoding.
func TestJSONLargeIntegerBeyondInt64(t *testing.T) {
	store := Store{config: config.JSONStoreConfig{Indent: -1}}
	lit := "123456789012345678901234567890"
	in := []byte("{\n\t\"id\": " + lit + "\n}")
	branch, err := store.treeBranchFromJSON(in)
	assert.Nil(t, err)
	raw, ok := branch[0].Value.(sops.RawNumber)
	assert.True(t, ok)
	assert.Equal(t, lit, raw.Literal)
	out, err := store.jsonFromTreeBranch(branch)
	assert.Nil(t, err)
	assert.Equal(t, string(in), string(out))
}
