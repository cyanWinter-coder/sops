package yaml

import (
	"bytes"
	"testing"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/stretchr/testify/assert"
)

// encryptedRoundTrip drives the full pipeline a CLI run performs:
// load plaintext -> encrypt -> emit encrypted bytes -> load those bytes
// fresh (as a separate process would) -> decrypt -> emit plaintext, and
// checks that the scalar representations survive the whole trip.
func TestEncryptedRoundTripPreservesScalars(t *testing.T) {
	plain := []byte(`ratio: 1.0
hexval: 0x1F
strnum: "42"
bincat: !!binary |
    SGVsbG8=
nested:
    zlast: 1.0
    afirst: 0xFF
items:
    - 2.0
    - "3"
plain_unencrypted: keep-me
`)
	store := NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plain)
	assert.Nil(t, err)

	tree := &sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			LastModified:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			UnencryptedSuffix: "_unencrypted",
			Version:           "3.13.1",
			KeyGroups: []sops.KeyGroup{
				{&age.MasterKey{Recipient: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw5smwv9m3ue83sqq6dj9d3", EncryptedKey: "dummy"}},
			},
		},
	}
	key := bytes.Repeat([]byte("k"), 32)
	cipher := aes.NewCipher()

	mac, err := tree.Encrypt(key, cipher)
	assert.Nil(t, err)
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(
		mac, key, tree.Metadata.LastModified.Format(time.RFC3339))
	assert.Nil(t, err)

	encrypted, err := store.EmitEncryptedFile(*tree)
	assert.Nil(t, err)
	assert.Contains(t, string(encrypted), "scalar_representations")

	// Reload from raw bytes, mimicking a brand-new process.
	reloaded, err := store.LoadEncryptedFile(encrypted)
	assert.Nil(t, err)

	decryptedMAC, err := reloaded.Decrypt(key, aes.NewCipher())
	assert.Nil(t, err)
	fileMAC, err := aes.NewCipher().Decrypt(
		reloaded.Metadata.MessageAuthenticationCode, key,
		reloaded.Metadata.LastModified.Format(time.RFC3339))
	assert.Nil(t, err)
	assert.Equal(t, fileMAC, decryptedMAC)

	out, err := store.EmitPlainFile(reloaded.Branches)
	assert.Nil(t, err)
	assert.Equal(t, string(plain), string(out))
}
