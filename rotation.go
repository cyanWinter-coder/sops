package sops

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/shamir"
)

// KeyError describes the failure of a single master key during key
// rotation. It identifies the key group, the master key (via
// MasterKey.ToString) and the underlying cause, so that operators can
// tell exactly which key of which group failed and why, while the
// remaining groups continued to be processed.
type KeyError struct {
	// GroupIndex is the index of the key group the key belongs to.
	GroupIndex int
	// KeyID is the MasterKey.ToString() identifier of the failed key.
	KeyID string
	// Op is the operation that failed, e.g. "encrypt".
	Op string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e KeyError) Error() string {
	return fmt.Sprintf("key group %d: failed to %s data key with master key %q: %s",
		e.GroupIndex, e.Op, e.KeyID, e.Err)
}

// Unwrap returns the underlying error.
func (e KeyError) Unwrap() error {
	return e.Err
}

// RotationReport summarizes the outcome of a single RotateKeys pass.
type RotationReport struct {
	// AddedKeys lists the identifiers of master keys that were newly
	// added to the metadata.
	AddedKeys []string
	// SkippedKeys lists the identifiers of master keys that were already
	// present in the metadata and were therefore not added again. An
	// empty AddedKeys together with a non-empty SkippedKeys means the
	// rotation had already been applied by a previous run.
	SkippedKeys []string
	// RemovedKeys lists the identifiers of master keys that were removed
	// from the metadata. Removal only becomes effective once the caller
	// persists the metadata, which must only happen when OK returns true.
	RemovedKeys []string
	// Failures lists every per-key failure encountered while encrypting
	// the data key. Rotation continues past individual failures so that
	// one unreachable key service does not block the remaining groups.
	Failures []KeyError
	// VerifyError is set when the post-rotation key set could not
	// recover the data key. When VerifyError is set, the old keys must
	// not be considered removed and the file must not be replaced.
	VerifyError error
}

// OK reports whether the rotation completed without any failure and the
// resulting key set was verified to recover the data key.
func (r RotationReport) OK() bool {
	return len(r.Failures) == 0 && r.VerifyError == nil
}

// Error returns a human-readable summary of all rotation failures.
func (r RotationReport) Error() string {
	if r.OK() {
		return "key rotation succeeded"
	}
	var b strings.Builder
	b.WriteString("key rotation failed:")
	for _, f := range r.Failures {
		fmt.Fprintf(&b, "\n  - %s", f)
	}
	if r.VerifyError != nil {
		fmt.Fprintf(&b, "\n  - verification: %s", r.VerifyError)
	}
	return b.String()
}

// RotateKeysOpts configures a resumable key rotation.
type RotateKeysOpts struct {
	// Add lists the master keys to add to the first key group. Keys that
	// are already present in any key group (matched by
	// MasterKey.ToString) are skipped, which makes re-running a rotation
	// idempotent.
	Add []keys.MasterKey
	// Remove lists the master keys to remove from all key groups.
	// Removal only takes effect on disk once the caller persists the
	// metadata after a successful verification.
	Remove []keys.MasterKey
	// KeyServices are the key service clients used to encrypt and
	// decrypt the data key, in order of preference.
	KeyServices []keyservice.KeyServiceClient
	// DecryptionOrder is the order in which key types are attempted
	// during the verification decryption.
	DecryptionOrder []string
	// ReencryptAll forces the data key to be re-encrypted with every
	// remaining master key, even keys that already carry a ciphertext.
	// It must be set when the data key itself is being rotated (i.e.
	// dataKey is a freshly generated key). When false, keys that already
	// wrap dataKey are left untouched, so that temporarily unreachable
	// key services do not block the rotation.
	ReencryptAll bool
}

// RotateKeys re-wraps dataKey with a new set of master keys in a
// resumable way:
//
//   - Keys are processed group by group; the failure of a single key is
//     reported with the key's identifier and the cause, and does not
//     abort the processing of the remaining groups.
//   - The rotation is idempotent: keys that are already present are not
//     added again, and keys that are already absent are not removed
//     again, so a failed run can simply be retried.
//   - Before the rotation is considered successful, the remaining key
//     set is verified to recover dataKey, guaranteeing that old keys are
//     only dropped once the new keys can decrypt the same plaintext.
//
// RotateKeys mutates m in memory only. Callers must persist the metadata
// (atomically) only when the returned report's OK method returns true;
// otherwise the original file must be left untouched, where it remains
// decryptable with the original keys.
func (m *Metadata) RotateKeys(dataKey []byte, opts RotateKeysOpts) RotationReport {
	report := RotationReport{}
	if len(opts.KeyServices) == 0 {
		report.VerifyError = fmt.Errorf("no key services provided, cannot rotate keys")
		return report
	}
	if len(m.KeyGroups) == 0 {
		report.VerifyError = fmt.Errorf("no key groups provided")
		return report
	}

	// Keep the original group structure around: the Shamir parts of
	// groups whose composition does not change can be recovered from the
	// existing ciphertexts, avoiding unnecessary calls to key services.
	originalGroups := make([]KeyGroup, len(m.KeyGroups))
	copy(originalGroups, m.KeyGroups)

	// Apply removals first, so that additions below always win over
	// removals. Keys that are not present are simply not reported,
	// which keeps re-runs idempotent. Groups emptied by the removal are
	// kept for now: additions below land in the first group, taking the
	// place of retired keys.
	removeSet := make(map[string]struct{}, len(opts.Remove))
	for _, k := range opts.Remove {
		removeSet[k.ToString()] = struct{}{}
	}
	if len(removeSet) > 0 {
		for i, group := range m.KeyGroups {
			var kept KeyGroup
			for _, k := range group {
				id := k.ToString()
				if _, remove := removeSet[id]; remove {
					report.RemovedKeys = append(report.RemovedKeys, id)
					continue
				}
				kept = append(kept, k)
			}
			m.KeyGroups[i] = kept
		}
	}

	// Add new keys to the first group, skipping keys that are already
	// present in any group.
	if len(opts.Add) > 0 {
		existing := make(map[string]struct{})
		for _, group := range m.KeyGroups {
			for _, k := range group {
				existing[k.ToString()] = struct{}{}
			}
		}
		for _, k := range opts.Add {
			id := k.ToString()
			if _, ok := existing[id]; ok {
				report.SkippedKeys = append(report.SkippedKeys, id)
				continue
			}
			if len(m.KeyGroups) == 0 {
				m.KeyGroups = []KeyGroup{{}}
			}
			m.KeyGroups[0] = append(m.KeyGroups[0], k)
			existing[id] = struct{}{}
			report.AddedKeys = append(report.AddedKeys, id)
		}
	}

	// Groups that are still empty after additions are dropped; the Shamir
	// split below is recomputed for the final group count.
	var groups []KeyGroup
	for _, group := range m.KeyGroups {
		if len(group) > 0 {
			groups = append(groups, group)
		}
	}
	m.KeyGroups = groups

	if len(m.KeyGroups) == 0 {
		report.VerifyError = fmt.Errorf("rotation would remove the last master key, refusing to continue")
		return report
	}

	// The Shamir threshold can never exceed the number of key groups,
	// otherwise the file would become undecryptable.
	if m.ShamirThreshold == 0 {
		m.ShamirThreshold = len(m.KeyGroups)
	} else if m.ShamirThreshold > len(m.KeyGroups) {
		log.WithField("quorum", len(m.KeyGroups)).Warn(
			"Adjusting Shamir threshold to match the number of key groups")
		m.ShamirThreshold = len(m.KeyGroups)
	}

	structureChanged := len(report.AddedKeys) > 0 || len(report.RemovedKeys) > 0

	var parts [][]byte
	reencryptAll := opts.ReencryptAll
	switch {
	case !structureChanged && !opts.ReencryptAll:
		// Nothing to do: a previous run already applied this rotation.
		// Fall through to the verification below, so that re-running a
		// rotation still confirms the file is decryptable.
	case len(m.KeyGroups) == 1 && len(originalGroups) == 1:
		// Without Shamir secret sharing every key wraps the data key
		// itself, and existing ciphertexts stay valid: only keys that do
		// not yet carry a ciphertext need to be encrypted.
		parts = [][]byte{dataKey}
	case len(m.KeyGroups) == 1:
		// The group count changed, so existing ciphertexts may wrap
		// Shamir parts of a previous split rather than the data key
		// itself. Every remaining key has to be re-encrypted.
		parts = [][]byte{dataKey}
		reencryptAll = true
	default:
		// With multiple key groups the data key is split into Shamir
		// parts, one per group. Parts from a previous split cannot be
		// mixed with parts from a new split, so either all parts are
		// recovered from the existing ciphertexts, or everything has to
		// be re-encrypted with parts from a fresh split.
		if !opts.ReencryptAll && len(m.KeyGroups) == len(originalGroups) {
			parts = recoverKeyGroupParts(originalGroups, opts.KeyServices, opts.DecryptionOrder)
		}
		if parts == nil {
			var err error
			parts, err = shamir.Split(dataKey, len(m.KeyGroups), m.ShamirThreshold)
			if err != nil {
				report.VerifyError = fmt.Errorf("could not split data key into parts for Shamir: %s", err)
				return report
			}
			reencryptAll = true
		}
	}

	if parts != nil {
		for i, group := range m.KeyGroups {
			for _, key := range group {
				if !reencryptAll && len(key.EncryptedDataKey()) > 0 {
					// This key already wraps the data key; leave the
					// existing ciphertext untouched so that unreachable
					// key services do not block the rotation.
					continue
				}
				if err := encryptKeyWithKeyServices(key, parts[i], opts.KeyServices); err != nil {
					report.Failures = append(report.Failures, KeyError{
						GroupIndex: i,
						KeyID:      key.ToString(),
						Op:         "encrypt",
						Err:        err,
					})
				}
			}
		}
	}

	if !report.OK() {
		return report
	}

	// Verify that the post-rotation key set can recover the data key
	// before the caller commits to it: old keys must only be dropped
	// once the remaining keys are proven to decrypt the same plaintext.
	verify := &Metadata{
		KeyGroups:       m.KeyGroups,
		ShamirThreshold: m.ShamirThreshold,
	}
	recovered, err := verify.GetDataKeyWithKeyServices(opts.KeyServices, opts.DecryptionOrder)
	if err != nil {
		report.VerifyError = fmt.Errorf("post-rotation key set cannot recover the data key: %w", err)
		return report
	}
	if !bytes.Equal(recovered, dataKey) {
		report.VerifyError = fmt.Errorf("post-rotation key set recovered a different data key")
		return report
	}
	m.DataKey = dataKey
	return report
}

// recoverKeyGroupParts decrypts the Shamir part of every key group using
// the existing ciphertexts. It returns nil if any group's part cannot be
// recovered, in which case the caller must fall back to a fresh split.
func recoverKeyGroupParts(groups []KeyGroup, svcs []keyservice.KeyServiceClient, decryptionOrder []string) [][]byte {
	parts := make([][]byte, len(groups))
	for i, group := range groups {
		part, err := decryptKeyGroup(group, svcs, decryptionOrder)
		if err != nil {
			return nil
		}
		parts[i] = part
	}
	return parts
}

// encryptKeyWithKeyServices encrypts plaintext (the data key or a Shamir
// part of it) with the given master key, trying each key service in
// order until one succeeds.
func encryptKeyWithKeyServices(key keys.MasterKey, plaintext []byte, svcs []keyservice.KeyServiceClient) error {
	svcKey := keyservice.KeyFromMasterKey(key)
	var errs []string
	for _, svc := range svcs {
		rsp, err := svc.Encrypt(context.Background(), &keyservice.EncryptRequest{
			Key:       &svcKey,
			Plaintext: plaintext,
		})
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		key.SetEncryptedDataKey(rsp.Ciphertext)
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errs, "; "))
}
