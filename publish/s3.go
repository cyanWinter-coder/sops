package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Destination is the AWS S3 implementation of the Destination interface
type S3Destination struct {
	s3Bucket string
	s3Prefix string
	// immutable marks a write-once/object-lock archive. Its targets can be
	// snapshotted but not overwritten or deleted; Restore and Delete return
	// ErrImmutable so the rollback flags the target for manual intervention.
	immutable bool
}

// NewS3Destination is the constructor for an S3 Destination
func NewS3Destination(s3Bucket, s3Prefix string) *S3Destination {
	return &S3Destination{s3Bucket: s3Bucket, s3Prefix: s3Prefix}
}

// SetImmutable marks this destination as a read-only archive whose objects
// cannot be overwritten. It returns the destination to support chaining at
// construction time.
func (s3d *S3Destination) SetImmutable(immutable bool) *S3Destination {
	s3d.immutable = immutable
	return s3d
}

func (s3d *S3Destination) key(fileName string) string {
	return s3d.s3Prefix + fileName
}

func (s3d *S3Destination) s3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}
	return s3.NewFromConfig(cfg), nil
}

// Path returns the S3 path of a file in an S3 Destination (bucket)
func (s3d *S3Destination) Path(fileName string) string {
	return fmt.Sprintf("s3://%s/%s%s", s3d.s3Bucket, s3d.s3Prefix, fileName)
}

// Upload uploads contents to a file in an S3 Destination (bucket)
func (s3d *S3Destination) Upload(fileContents []byte, fileName string) error {
	return s3d.upload(context.TODO(), fileContents, fileName)
}

func (s3d *S3Destination) upload(ctx context.Context, fileContents []byte, fileName string) error {
	svc, err := s3d.s3Client(ctx)
	if err != nil {
		return err
	}
	input := &s3.PutObjectInput{
		Body:   manager.ReadSeekCloser(bytes.NewReader(fileContents)),
		Bucket: aws.String(s3d.s3Bucket),
		Key:    aws.String(s3d.key(fileName)),
	}
	if _, err = svc.PutObject(ctx, input); err != nil {
		return err
	}
	return nil
}

// Check verifies the bucket exists and is reachable. It is used as the
// preflight check so an unreachable destination fails the release before any
// target is written.
func (s3d *S3Destination) Check(ctx context.Context) error {
	svc, err := s3d.s3Client(ctx)
	if err != nil {
		return err
	}
	_, err = svc.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s3d.s3Bucket)})
	return err
}

// Snapshot records the current object's version id and full contents so it can
// be restored even when the bucket does not have versioning enabled.
func (s3d *S3Destination) Snapshot(ctx context.Context, fileName string) (*TargetState, error) {
	svc, err := s3d.s3Client(ctx)
	if err != nil {
		return nil, err
	}
	key := s3d.key(fileName)

	head, err := svc.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s3d.s3Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var notFound *s3types.NotFound
		if errors.As(err, &notFound) {
			return &TargetState{
				Destination: s3d,
				FileName:    fileName,
				Existed:     false,
			}, nil
		}
		return nil, err
	}

	out, err := svc.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3d.s3Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)

	state := &TargetState{
		Destination: s3d,
		FileName:    fileName,
		Existed:     true,
		Digest:      hex.EncodeToString(sum[:]),
		Data:        data,
	}
	if head.VersionId != nil {
		state.Version = *head.VersionId
	}
	return state, nil
}

// Restore puts the snapshotted object contents back.
func (s3d *S3Destination) Restore(ctx context.Context, state *TargetState) error {
	if s3d.immutable {
		return fmt.Errorf("%w: %s", ErrImmutable, s3d.Path(state.FileName))
	}
	return s3d.upload(ctx, state.Data, state.FileName)
}

// Delete removes an object created during the release.
func (s3d *S3Destination) Delete(ctx context.Context, fileName string) error {
	if s3d.immutable {
		return fmt.Errorf("%w: %s", ErrImmutable, s3d.Path(fileName))
	}
	svc, err := s3d.s3Client(ctx)
	if err != nil {
		return err
	}
	_, err = svc.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s3d.s3Bucket),
		Key:    aws.String(s3d.key(fileName)),
	})
	return err
}

// Returns NotImplementedError
func (s3d *S3Destination) UploadUnencrypted(data map[string]interface{}, fileName string) error {
	return &NotImplementedError{"S3 does not support uploading the unencrypted file contents."}
}
