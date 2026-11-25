package yaml

import (
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/stretchr/testify/assert"
)

// TestScalarRoundTrip pins the representation-preserving behavior for
// scalars whose default Go decoding would otherwise lose information:
// float spelling, non-decimal integers, quoted strings, timestamps and the
// !!binary tag.
func TestScalarRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"float spelling", "floatval: 1.0\n"},
		{"scientific float", "speed: 1e3\n"},
		{"hex integer", "hexval: 0x1F\n"},
		{"octal integer", "octval: 0o17\n"},
		{"quoted numeric string", "strnum: \"42\"\n"},
		{"binary tag", "bincat: !!binary |\n    SGVsbG8=\n"},
		{"timestamp", "ts: 2020-01-02T15:04:05Z\n"},
		{"nested and ordered", "outer:\n    zlast: 1.0\n    afirst: 0xFF\n"},
		{"scalars in list", "items:\n    - 1.0\n    - 0x10\n    - \"3\"\n"},
	}
	store := &Store{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			branches, err := store.LoadPlainFile([]byte(tc.in))
			assert.Nil(t, err)
			out, err := store.EmitPlainFile(branches)
			assert.Nil(t, err)
			// Re-indentation is the only allowed normalization; compare the
			// semantic content and, where indentation is irrelevant, bytes.
			assert.Equal(t, tc.in, string(out))
		})
	}
}

// TestScalarWrappingIsSelective ensures ordinary canonical scalars keep
// their traditional bare Go types so existing consumers are unaffected.
func TestScalarWrappingIsSelective(t *testing.T) {
	branches, err := (&Store{}).LoadPlainFile([]byte("s: hello\ni: 42\nf: 2.5\nb: true\nn: null\n"))
	assert.Nil(t, err)
	branch := branches[0]
	values := map[string]interface{}{}
	for _, item := range branch {
		values[item.Key.(string)] = item.Value
	}
	assert.IsType(t, "", values["s"])
	assert.IsType(t, 0, values["i"])
	assert.IsType(t, float64(0), values["f"])
	assert.IsType(t, false, values["b"])
	assert.Nil(t, values["n"])
}

// TestBinaryScalarIsBytes ensures !!binary data is decoded to raw bytes
// rather than silently becoming a UTF-8 string.
func TestBinaryScalarIsBytes(t *testing.T) {
	branches, err := (&Store{}).LoadPlainFile([]byte("data: !!binary |\n    SGVsbG8=\n"))
	assert.Nil(t, err)
	value := branches[0][0].Value
	scalar, ok := value.(sops.Scalar)
	assert.True(t, ok, "binary scalar should be wrapped in sops.Scalar, got %T", value)
	assert.Equal(t, "!!binary", scalar.Tag)
	assert.Equal(t, []byte("Hello"), scalar.Value)
}

// TestNonUTF8Rejected ensures content that is not valid UTF-8 is rejected
// at parse time rather than being silently transcoded.
func TestNonUTF8Rejected(t *testing.T) {
	_, err := (&Store{}).LoadPlainFile([]byte("a: \"caf\xE9\"\n"))
	assert.NotNil(t, err)
}
