package sops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
)

// fakeKeyService is a keyservice.KeyServiceClient that "wraps" plaintext
// by prefixing it, and can be told to fail for keys whose recipient
// contains a given substring, simulating an unreachable KMS endpoint.
type fakeKeyService struct {
	encryptFailSubstr string
	decryptFailSubstr string
}

func fakeRecipient(key *keyservice.Key) string {
	if ageKey := key.GetAgeKey(); ageKey != nil {
		return ageKey.Recipient
	}
	return ""
}

func (f fakeKeyService) Encrypt(_ context.Context, req *keyservice.EncryptRequest, _ ...grpc.CallOption) (*keyservice.EncryptResponse, error) {
	recipient := fakeRecipient(req.Key)
	if f.encryptFailSubstr != "" && strings.Contains(recipient, f.encryptFailSubstr) {
		return nil, fmt.Errorf("endpoint timeout for key %s", recipient)
	}
	return &keyservice.EncryptResponse{
		Ciphertext: append([]byte("enc:"), req.Plaintext...),
	}, nil
}

func (f fakeKeyService) Decrypt(_ context.Context, req *keyservice.DecryptRequest, _ ...grpc.CallOption) (*keyservice.DecryptResponse, error) {
	recipient := fakeRecipient(req.Key)
	if f.decryptFailSubstr != "" && strings.Contains(recipient, f.decryptFailSubstr) {
		return nil, fmt.Errorf("endpoint timeout for key %s", recipient)
	}
	plaintext, ok := bytes.CutPrefix(req.Ciphertext, []byte("enc:"))
	if !ok {
		return nil, errors.New("cannot decrypt ciphertext")
	}
	return &keyservice.DecryptResponse{Plaintext: plaintext}, nil
}

func testMasterKey(recipient string) *age.MasterKey {
	return &age.MasterKey{Recipient: recipient}
}

// wrappedMetadata returns a Metadata with a single key group holding the
// given keys, each wrapping dataKey.
func wrappedMetadata(t *testing.T, dataKey []byte, svcs []keyservice.KeyServiceClient, recipients ...string) *Metadata {
	t.Helper()
	group := KeyGroup{}
	for _, r := range recipients {
		group = append(group, testMasterKey(r))
	}
	m := &Metadata{KeyGroups: []KeyGroup{group}}
	errs := m.UpdateMasterKeysWithKeyServices(dataKey, svcs)
	require.Empty(t, errs)
	return m
}

func TestRotateKeysAddAndRemove(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, dataKey, svcs, "age1old")

	newKey := testMasterKey("age1new")
	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Add:         []keys.MasterKey{newKey},
		Remove:      []keys.MasterKey{testMasterKey("age1old")},
		KeyServices: svcs,
	})
	require.True(t, report.OK(), report.Error())
	assert.Equal(t, []string{"age1new"}, report.AddedKeys)
	assert.Equal(t, []string{"age1old"}, report.RemovedKeys)
	assert.Empty(t, report.SkippedKeys)

	// Only the new key remains, and it alone recovers the same data key.
	require.Len(t, m.KeyGroups, 1)
	require.Len(t, m.KeyGroups[0], 1)
	assert.Equal(t, "age1new", m.KeyGroups[0][0].ToString())
	m.DataKey = nil
	got, err := m.GetDataKeyWithKeyServices(svcs, nil)
	require.NoError(t, err)
	assert.Equal(t, dataKey, got)
}

func TestRotateKeysIdempotentRerun(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, dataKey, svcs, "age1old")

	opts := RotateKeysOpts{
		Add:         []keys.MasterKey{testMasterKey("age1new")},
		Remove:      []keys.MasterKey{testMasterKey("age1old")},
		KeyServices: svcs,
	}
	report := m.RotateKeys(dataKey, opts)
	require.True(t, report.OK(), report.Error())

	// Re-running the same rotation adds and removes nothing, and still
	// succeeds even though the old key's endpoint is now unreachable:
	// no operation involves the old key anymore.
	downSvcs := []keyservice.KeyServiceClient{fakeKeyService{
		encryptFailSubstr: "old",
		decryptFailSubstr: "old",
	}}
	opts.KeyServices = downSvcs
	opts.Add = []keys.MasterKey{testMasterKey("age1new")}
	report = m.RotateKeys(dataKey, opts)
	require.True(t, report.OK(), report.Error())
	assert.Empty(t, report.AddedKeys)
	assert.Equal(t, []string{"age1new"}, report.SkippedKeys)
	assert.Empty(t, report.RemovedKeys)
}

func TestRotateKeysOldEndpointDownDoesNotBlock(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, dataKey, svcs, "age1old")

	// The old key's endpoint is down, which is precisely why the key is
	// being rotated out. Only the new key's endpoint is needed.
	downSvcs := []keyservice.KeyServiceClient{fakeKeyService{
		encryptFailSubstr: "old",
		decryptFailSubstr: "old",
	}}
	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Add:         []keys.MasterKey{testMasterKey("age1new")},
		Remove:      []keys.MasterKey{testMasterKey("age1old")},
		KeyServices: downSvcs,
	})
	require.True(t, report.OK(), report.Error())
	assert.Equal(t, []string{"age1new"}, report.AddedKeys)
	assert.Equal(t, []string{"age1old"}, report.RemovedKeys)
}

func TestRotateKeysFailureReportsKeyAndContinues(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, dataKey, svcs, "age1old")

	// One of the two new keys lives behind an unreachable endpoint.
	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Add: []keys.MasterKey{
			testMasterKey("age1new-ok"),
			testMasterKey("age1new-down"),
		},
		KeyServices: []keyservice.KeyServiceClient{fakeKeyService{
			encryptFailSubstr: "down",
		}},
	})
	require.False(t, report.OK())
	require.Len(t, report.Failures, 1)
	assert.Equal(t, 0, report.Failures[0].GroupIndex)
	assert.Equal(t, "age1new-down", report.Failures[0].KeyID)
	assert.Contains(t, report.Failures[0].Err.Error(), "endpoint timeout")
	assert.Contains(t, report.Error(), "age1new-down")

	// The reachable key was still processed despite the other's failure.
	var newOK keys.MasterKey
	for _, k := range m.KeyGroups[0] {
		if k.ToString() == "age1new-ok" {
			newOK = k
		}
	}
	require.NotNil(t, newOK)
	assert.NotEmpty(t, newOK.EncryptedDataKey())
}

func TestRotateKeysVerificationFailure(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, dataKey, svcs, "age1old")

	// The new key encrypts fine but cannot decrypt afterwards (e.g. the
	// endpoint lost the key between the two calls). The rotation must
	// fail verification instead of dropping the old key.
	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Add:    []keys.MasterKey{testMasterKey("age1flaky")},
		Remove: []keys.MasterKey{testMasterKey("age1old")},
		KeyServices: []keyservice.KeyServiceClient{fakeKeyService{
			decryptFailSubstr: "flaky",
		}},
	})
	require.False(t, report.OK())
	require.Error(t, report.VerifyError)
	assert.Contains(t, report.VerifyError.Error(), "cannot recover the data key")
}

func TestRotateKeysRefusesToRemoveLastKey(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, dataKey, svcs, "age1old")

	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Remove:      []keys.MasterKey{testMasterKey("age1old")},
		KeyServices: svcs,
	})
	require.False(t, report.OK())
	require.Error(t, report.VerifyError)
}

func TestRotateKeysMultiGroup(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}

	// Two key groups, both required to decrypt (Shamir quorum of 2).
	m := &Metadata{
		KeyGroups: []KeyGroup{
			{testMasterKey("age1a")},
			{testMasterKey("age1b")},
		},
	}
	errs := m.UpdateMasterKeysWithKeyServices(dataKey, svcs)
	require.Empty(t, errs)

	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Add:         []keys.MasterKey{testMasterKey("age1new")},
		Remove:      []keys.MasterKey{testMasterKey("age1a")},
		KeyServices: svcs,
	})
	require.True(t, report.OK(), report.Error())

	// The new key joined the first group, the old key is gone.
	require.Len(t, m.KeyGroups, 2)
	require.Len(t, m.KeyGroups[0], 1)
	assert.Equal(t, "age1new", m.KeyGroups[0][0].ToString())

	// The data key is still recovered from the quorum of both groups.
	m.DataKey = nil
	got, err := m.GetDataKeyWithKeyServices(svcs, nil)
	require.NoError(t, err)
	assert.Equal(t, dataKey, got)
}

func TestRotateKeysAnyKeyInGroupDecrypts(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, dataKey, svcs, "age1old")

	// Two keys end up in the single group; either of them is sufficient
	// to decrypt, so one endpoint being down does not affect readers.
	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Add:         []keys.MasterKey{testMasterKey("age1new")},
		KeyServices: svcs,
	})
	require.True(t, report.OK(), report.Error())
	require.Len(t, m.KeyGroups[0], 2)

	m.DataKey = nil
	got, err := m.GetDataKeyWithKeyServices([]keyservice.KeyServiceClient{
		fakeKeyService{decryptFailSubstr: "old"},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, dataKey, got)
}

func TestRotateKeysMultiGroupFailureKeepsOtherGroupsGoing(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}

	m := &Metadata{
		KeyGroups: []KeyGroup{
			{testMasterKey("age1a")},
			{testMasterKey("age1b-down")},
		},
	}
	errs := m.UpdateMasterKeysWithKeyServices(dataKey, svcs)
	require.Empty(t, errs)

	// Adding a key changes the group composition, and the second group's
	// endpoint is down, so its part cannot be recovered from the existing
	// ciphertexts either. The rotation falls back to a fresh split and
	// re-encrypts every key; group 0 must still be processed even though
	// group 1 fails.
	report := m.RotateKeys(dataKey, RotateKeysOpts{
		Add: []keys.MasterKey{testMasterKey("age1new")},
		KeyServices: []keyservice.KeyServiceClient{fakeKeyService{
			encryptFailSubstr: "down",
			decryptFailSubstr: "down",
		}},
	})
	require.False(t, report.OK())
	require.NotEmpty(t, report.Failures)
	var failedKeys []string
	for _, f := range report.Failures {
		failedKeys = append(failedKeys, f.KeyID)
	}
	assert.Contains(t, failedKeys, "age1b-down")
	assert.NotContains(t, failedKeys, "age1a")
	assert.NotContains(t, failedKeys, "age1new")

	// Group 0's keys were re-encrypted successfully despite group 1's
	// failure.
	assert.NotEmpty(t, m.KeyGroups[0][0].EncryptedDataKey())
}

func TestRotateKeysReencryptAll(t *testing.T) {
	oldDataKey := []byte("0123456789abcdef0123456789abcdef")
	newDataKey := []byte("fedcba9876543210fedcba9876543210")
	svcs := []keyservice.KeyServiceClient{fakeKeyService{}}
	m := wrappedMetadata(t, oldDataKey, svcs, "age1old")

	// Rotating the data key itself forces every remaining key to
	// re-encrypt, even keys that already carry a ciphertext.
	report := m.RotateKeys(newDataKey, RotateKeysOpts{
		KeyServices:  svcs,
		ReencryptAll: true,
	})
	require.True(t, report.OK(), report.Error())

	m.DataKey = nil
	got, err := m.GetDataKeyWithKeyServices(svcs, nil)
	require.NoError(t, err)
	assert.Equal(t, newDataKey, got)
}
