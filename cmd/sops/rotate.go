package main

import (
	"crypto/rand"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/audit"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
)

type rotateOpts struct {
	Cipher           sops.Cipher
	InputStore       sops.Store
	OutputStore      sops.Store
	InputPath        string
	IgnoreMAC        bool
	RotateDataKey    bool
	AddMasterKeys    []keys.MasterKey
	RemoveMasterKeys []keys.MasterKey
	KeyServices      []keyservice.KeyServiceClient
	DecryptionOrder  []string
}

func rotate(opts rotateOpts) ([]byte, error) {
	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:          opts.Cipher,
		InputStore:      opts.InputStore,
		InputPath:       opts.InputPath,
		IgnoreMAC:       opts.IgnoreMAC,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
	if err != nil {
		return nil, err
	}

	audit.SubmitEvent(audit.RotateEvent{
		File: tree.FilePath,
	})

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:          opts.Cipher,
		IgnoreMac:       opts.IgnoreMAC,
		Tree:            tree,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
	if err != nil {
		return nil, err
	}

	if opts.RotateDataKey {
		// Rotate the data key itself, not just the master keys wrapping
		// it. Every remaining master key will have to encrypt the fresh
		// data key, and the payload is re-encrypted below.
		dataKey = make([]byte, 32)
		if _, err := rand.Read(dataKey); err != nil {
			return nil, fmt.Errorf("could not generate a new data key: %s", err)
		}
	}

	// Re-wrap the data key with the new set of master keys. This is
	// resumable: it only mutates the in-memory metadata, processes the
	// key groups one by one, and verifies that the remaining keys can
	// recover the data key before reporting success.
	report := tree.Metadata.RotateKeys(dataKey, sops.RotateKeysOpts{
		Add:             opts.AddMasterKeys,
		Remove:          opts.RemoveMasterKeys,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
		ReencryptAll:    opts.RotateDataKey,
	})
	for _, id := range report.AddedKeys {
		log.WithField("key", id).Info("Added master key")
	}
	for _, id := range report.SkippedKeys {
		log.WithField("key", id).Info("Master key already present, skipping")
	}
	for _, id := range report.RemovedKeys {
		log.WithField("key", id).Info("Removed master key")
	}
	if !report.OK() {
		// The original file is left untouched and remains decryptable
		// with the original keys. Re-running the same command resumes
		// the rotation: keys that were already rotated are skipped.
		return nil, common.NewExitError(report.Error(), codes.KeysRotationFailed)
	}

	// Re-encrypt the payload. With the default data-key-preserving
	// rotation this only re-encrypts locally with the same data key and
	// refreshes the MAC; no key service is involved.
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey, Tree: tree, Cipher: opts.Cipher,
	})
	if err != nil {
		return nil, err
	}

	encryptedFile, err := opts.OutputStore.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	return encryptedFile, nil
}
