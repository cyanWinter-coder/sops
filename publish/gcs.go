package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// GCSDestination represents the Google Cloud Storage destination
type GCSDestination struct {
	gcsBucket string
	gcsPrefix string
	// immutable marks a bucket with a retention policy / object holds whose
	// objects cannot be overwritten or deleted. Restore and Delete return
	// ErrImmutable so the rollback flags the target for manual intervention.
	immutable bool
}

// NewGCSDestination is the constructor for a Google Cloud Storage destination
func NewGCSDestination(gcsBucket, gcsPrefix string) *GCSDestination {
	return &GCSDestination{gcsBucket: gcsBucket, gcsPrefix: gcsPrefix}
}

// SetImmutable marks this destination as a read-only archive whose objects
// cannot be overwritten. It returns the destination to support chaining at
// construction time.
func (gcsd *GCSDestination) SetImmutable(immutable bool) *GCSDestination {
	gcsd.immutable = immutable
	return gcsd
}

func (gcsd *GCSDestination) objectName(fileName string) string {
	return gcsd.gcsPrefix + fileName
}

func (gcsd *GCSDestination) newClient(ctx context.Context) (*storage.Client, error) {
	return storage.NewClient(ctx)
}

// Path returns a the GCS path for a file within this GCS Destination
func (gcsd *GCSDestination) Path(fileName string) string {
	return fmt.Sprintf("gcs://%s/%s%s", gcsd.gcsBucket, gcsd.gcsPrefix, fileName)
}

// Upload uploads contents to a file in GCS
func (gcsd *GCSDestination) Upload(fileContents []byte, fileName string) error {
	return gcsd.upload(context.Background(), fileContents, fileName)
}

func (gcsd *GCSDestination) upload(ctx context.Context, fileContents []byte, fileName string) error {
	client, err := gcsd.newClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	wc := client.Bucket(gcsd.gcsBucket).Object(gcsd.objectName(fileName)).NewWriter(ctx)
	if _, err = wc.Write(fileContents); err != nil {
		_ = wc.Close()
		return err
	}
	return wc.Close()
}

// Check verifies the bucket exists and is reachable. It is used as the
// preflight check so an unreachable destination fails the release before any
// target is written.
func (gcsd *GCSDestination) Check(ctx context.Context) error {
	client, err := gcsd.newClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	// Attrs only returns bucket metadata; iterate a single object to confirm
	// the caller also has the object-level permissions a publish needs.
	if _, err = client.Bucket(gcsd.gcsBucket).Attrs(ctx); err != nil {
		return err
	}
	it := client.Bucket(gcsd.gcsBucket).Objects(ctx, &storage.Query{Prefix: gcsd.gcsPrefix})
	if _, err = it.Next(); err != nil && !errors.Is(err, iterator.Done) {
		return err
	}
	return nil
}

// Snapshot records the current object's generation and full contents so it can
// be restored even without bucket versioning.
func (gcsd *GCSDestination) Snapshot(ctx context.Context, fileName string) (*TargetState, error) {
	client, err := gcsd.newClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	obj := client.Bucket(gcsd.gcsBucket).Object(gcsd.objectName(fileName))

	attrs, err := obj.Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return &TargetState{
				Destination: gcsd,
				FileName:    fileName,
				Existed:     false,
			}, nil
		}
		return nil, err
	}

	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)

	return &TargetState{
		Destination: gcsd,
		FileName:    fileName,
		Existed:     true,
		Digest:      hex.EncodeToString(sum[:]),
		Version:     fmt.Sprintf("%d", attrs.Generation),
		Data:        data,
	}, nil
}

// Restore puts the snapshotted object contents back.
func (gcsd *GCSDestination) Restore(ctx context.Context, state *TargetState) error {
	if gcsd.immutable {
		return fmt.Errorf("%w: %s", ErrImmutable, gcsd.Path(state.FileName))
	}
	return gcsd.upload(ctx, state.Data, state.FileName)
}

// Delete removes an object created during the release.
func (gcsd *GCSDestination) Delete(ctx context.Context, fileName string) error {
	if gcsd.immutable {
		return fmt.Errorf("%w: %s", ErrImmutable, gcsd.Path(fileName))
	}
	client, err := gcsd.newClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.Bucket(gcsd.gcsBucket).Object(gcsd.objectName(fileName)).Delete(ctx)
}

// Returns NotImplementedError
func (gcsd *GCSDestination) UploadUnencrypted(data map[string]interface{}, fileName string) error {
	return &NotImplementedError{"GCS does not support uploading the unencrypted file contents."}
}
