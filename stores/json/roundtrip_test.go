package json

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

// TestEncryptedRoundTripPreservesNumbers drives the full JSON pipeline and
// checks that non-canonical numeric spellings and large integers survive
// encrypt -> emit -> reload -> decrypt -> emit.
func TestEncryptedRoundTripPreservesNumbers(t *testing.T) {
	plain := []byte("{\n\t\"ratio\": 1.0,\n\t\"big\": 9007199254740993,\n\t\"scientific\": 1e3,\n\t\"canonical\": 42\n}\n")
	store := Store{config: config.JSONStoreConfig{Indent: -1}}

	branches, err := store.LoadPlainFile(plain)
	assert.Nil(t, err)
	tree := &sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			LastModified: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Version:      "3.13.1",
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
