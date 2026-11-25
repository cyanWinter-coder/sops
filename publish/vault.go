package publish

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/getsops/sops/v3/logging"
	"github.com/google/go-cmp/cmp"
	vault "github.com/hashicorp/vault/api"

	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("PUBLISH")
}

type VaultDestination struct {
	vaultAddress string
	vaultPath    string
	kvMountName  string
	kvVersion    int
}

func NewVaultDestination(vaultAddress, vaultPath, kvMountName string, kvVersion int) *VaultDestination {
	if !strings.HasSuffix(vaultPath, "/") {
		vaultPath = vaultPath + "/"
	}
	if kvMountName == "" {
		kvMountName = "secret/"
	}
	if !strings.HasSuffix(kvMountName, "/") {
		kvMountName = kvMountName + "/"
	}
	if kvVersion != 1 && kvVersion != 2 {
		kvVersion = 2
	}
	return &VaultDestination{vaultAddress, vaultPath, kvMountName, kvVersion}
}

func (vaultd *VaultDestination) getAddress() string {
	if vaultd.vaultAddress != "" {
		return vaultd.vaultAddress
	}
	return vault.DefaultConfig().Address
}

func (vaultd *VaultDestination) Path(fileName string) string {
	return fmt.Sprintf("%s/v1/%s", vaultd.getAddress(), vaultd.secretsPath(fileName))
}

func (vaultd *VaultDestination) secretsPath(fileName string) string {
	if vaultd.kvVersion == 1 {
		return fmt.Sprintf("%s%s%s", vaultd.kvMountName, vaultd.vaultPath, fileName)
	}
	return fmt.Sprintf("%sdata/%s%s", vaultd.kvMountName, vaultd.vaultPath, fileName)
}

// metadataPath is the KV v2 metadata endpoint, used to permanently delete a
// secret that did not exist before a release. It is only valid for KV v2.
func (vaultd *VaultDestination) metadataPath(fileName string) string {
	return fmt.Sprintf("%smetadata/%s%s", vaultd.kvMountName, vaultd.vaultPath, fileName)
}

func (vaultd *VaultDestination) client(ctx context.Context) (*vault.Client, error) {
	client, err := vault.NewClient(nil)
	if err != nil {
		return nil, err
	}
	if vaultd.vaultAddress != "" {
		if err = client.SetAddress(vaultd.vaultAddress); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// Check verifies the Vault server is reachable, initialized and unsealed so a
// publish cannot start against a server that will reject every write.
func (vaultd *VaultDestination) Check(ctx context.Context) error {
	client, err := vaultd.client(ctx)
	if err != nil {
		return err
	}
	health, err := client.Sys().HealthWithContext(ctx)
	if err != nil {
		return err
	}
	if health == nil {
		return fmt.Errorf("no health response from Vault at %s", vaultd.getAddress())
	}
	if health.Sealed {
		return fmt.Errorf("Vault at %s is sealed", vaultd.getAddress())
	}
	if !health.Initialized {
		return fmt.Errorf("Vault at %s is not initialized", vaultd.getAddress())
	}
	return nil
}

// Snapshot records the current secret data and, for KV v2, its version number,
// so it can be restored and identical re-publishes can be skipped.
func (vaultd *VaultDestination) Snapshot(ctx context.Context, fileName string) (*TargetState, error) {
	client, err := vaultd.client(ctx)
	if err != nil {
		return nil, err
	}
	secretsPath := vaultd.secretsPath(fileName)
	secret, err := client.Logical().ReadWithContext(ctx, secretsPath)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return &TargetState{
			Destination: vaultd,
			FileName:    fileName,
			Existed:     false,
		}, nil
	}

	state := &TargetState{
		Destination: vaultd,
		FileName:    fileName,
		Existed:     true,
	}
	if vaultd.kvVersion == 1 {
		// KV v1 reads return the key/value pairs directly in Secret.Data.
		state.UnencryptedData = secret.Data
	} else {
		// KV v2 wraps the payload under "data" alongside "metadata".
		state.UnencryptedData, _ = secret.Data["data"].(map[string]interface{})
		if metadata, ok := secret.Data["metadata"].(map[string]interface{}); ok {
			state.Version = metadataVersion(metadata["version"])
		}
	}
	state.Digest = digestMap(state.UnencryptedData)
	return state, nil
}

// metadataVersion renders the JSON-encoded metadata version field, which may
// arrive as either a json.Number or a float64.
func metadataVersion(value interface{}) string {
	switch v := value.(type) {
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return v
	default:
		return ""
	}
}

// Restore writes the snapshotted secret data back.
func (vaultd *VaultDestination) Restore(ctx context.Context, state *TargetState) error {
	client, err := vaultd.client(ctx)
	if err != nil {
		return err
	}
	secretsData := make(map[string]interface{})
	if vaultd.kvVersion == 1 {
		secretsData = state.UnencryptedData
	} else {
		secretsData["data"] = state.UnencryptedData
	}
	_, err = client.Logical().WriteWithContext(ctx, vaultd.secretsPath(state.FileName), secretsData)
	return err
}

// Delete permanently removes a secret created during the release. KV v1 secrets
// are deleted at their data path; KV v2 secrets are purged through the
// metadata endpoint so no soft-deleted version remains behind.
func (vaultd *VaultDestination) Delete(ctx context.Context, fileName string) error {
	client, err := vaultd.client(ctx)
	if err != nil {
		return err
	}
	if vaultd.kvVersion == 1 {
		_, err = client.Logical().DeleteWithContext(ctx, vaultd.secretsPath(fileName))
		return err
	}
	_, err = client.Logical().DeleteWithContext(ctx, vaultd.metadataPath(fileName))
	return err
}

// Returns NotImplementedError
func (vaultd *VaultDestination) Upload(fileContents []byte, fileName string) error {
	return &NotImplementedError{"Vault does not support uploading encrypted sops files directly."}
}

func (vaultd *VaultDestination) UploadUnencrypted(data map[string]interface{}, fileName string) error {
	client, err := vault.NewClient(nil)
	if err != nil {
		return err
	}
	if vaultd.vaultAddress != "" {
		err = client.SetAddress(vaultd.vaultAddress)
		if err != nil {
			return err
		}
	}

	secretsPath := vaultd.secretsPath(fileName)
	existingSecret, err := client.Logical().Read(secretsPath)
	if err != nil {
		log.Warnf("Cannot check if destination secret already exists in %s. New version will be created even if the data has not been changed.", secretsPath)
	}
	if existingSecret != nil && cmp.Equal(data, existingSecret.Data["data"]) {
		log.Infof("Secret in %s is already up-to-date.\n", secretsPath)
		return nil
	}

	secretsData := make(map[string]interface{})

	if vaultd.kvVersion == 1 {
		secretsData = data
	} else if vaultd.kvVersion == 2 {
		secretsData["data"] = data
	}

	_, err = client.Logical().Write(secretsPath, secretsData)
	if err != nil {
		return err
	}

	return nil
}
