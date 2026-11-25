package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// A release is one Publisher.Publish call containing one Operation per
// destination/file pair (for example four destinations and a dozen files).
// The publisher makes the release rollback-safe: every destination is checked
// for reachability before any write, every target is snapshotted before it is
// overwritten, writes happen in order, and on failure or cancellation the
// already written targets are restored in reverse order.
//
// The rollback guarantees are exposed through optional capability interfaces.
// The existing Destination interface is unchanged, so destinations that only
// implement Destination keep working; they simply cannot be restored
// automatically and are reported as needing manual intervention on rollback.
//
//	type op = publish.Operation
//	result := (&publish.Publisher{}).Publish(ctx, []*publish.Operation{
//		{Destination: s3Dest, FileName: "app/config.yaml", Contents: bytes},
//		{Destination: vaultDest, FileName: "app/config", UnencryptedData: secret},
//	})
//	if err := result.Err(); err != nil {
//		// result.PrimaryError is what failed; result.RollbackFailures lists
//		// anything that could not be restored and needs manual attention.
//	}
type (
	// PreflightChecker is implemented by destinations that can verify they are
	// reachable and ready before any write happens. A failing check aborts the
	// release before the first target is modified. Destinations without this
	// capability are assumed reachable.
	PreflightChecker interface {
		Check(ctx context.Context) error
	}

	// Snapshotter captures the current state of a single target so it can be
	// restored later. Snapshots for every operation are taken before any write.
	Snapshotter interface {
		Snapshot(ctx context.Context, fileName string) (*TargetState, error)
	}

	// Restorer puts a target back into the state captured in the given
	// snapshot. A Restorer may return ErrImmutable to signal that the target is
	// read-only and must be handled manually instead.
	Restorer interface {
		Restore(ctx context.Context, state *TargetState) error
	}

	// Deleter removes a target that did not exist before the release. It is
	// used during rollback when the snapshot reports Existed == false.
	Deleter interface {
		Delete(ctx context.Context, fileName string) error
	}
)

var (
	// ErrImmutable is returned by a Restorer for a read-only/immutable target
	// whose content cannot be overwritten. Such targets are recorded in
	// Result.RollbackFailures with Immutable set and flagged for manual
	// intervention instead of being treated as ordinary restore errors.
	ErrImmutable = errors.New("destination is immutable and cannot be rolled back automatically")
)

// TargetState is the pre-publish state of one file in one destination, as
// captured by a Snapshotter.
type TargetState struct {
	Destination Destination
	FileName    string
	// Existed reports whether a previous version of the target was found.
	// When false, rollback deletes the target instead of restoring content.
	Existed bool
	// Digest is the hex-encoded SHA-256 of the previous payload, when it could
	// be read. It is used to skip writes that would not change the target.
	Digest string
	// Version is the destination-native version identifier (S3 version id,
	// GCS generation, Vault secret version) when the backend provides one.
	Version string
	// Data holds the previous encrypted/raw payload for targets written
	// through Upload.
	Data []byte
	// UnencryptedData holds the previous secret payload for targets written
	// through UploadUnencrypted.
	UnencryptedData map[string]interface{}
}

// Operation is one file published to one destination as part of a release.
// Exactly one of Contents (Upload) or UnencryptedData (UploadUnencrypted)
// must be set.
type Operation struct {
	Destination     Destination
	FileName        string
	Contents        []byte
	UnencryptedData map[string]interface{}

	state   *TargetState
	written bool
	skipped bool
}

// Written reports whether this operation produced a new version.
func (op *Operation) Written() bool { return op.written }

// Skipped reports whether this operation was not written because the target
// was already up-to-date.
func (op *Operation) Skipped() bool { return op.skipped }

// TargetFailure records a target that could not be restored during rollback.
// Failures are collected without aborting the remaining rollbacks and never
// replace the error that triggered the rollback.
type TargetFailure struct {
	Destination Destination
	FileName    string
	// Phase is the operation that failed: "snapshot", "write", "restore" or
	// "delete".
	Phase string
	Err   error
	// Immutable is true when the target rejected the restore because it is
	// read-only and cannot be overwritten.
	Immutable bool
}

func (f TargetFailure) Error() string {
	return fmt.Sprintf("%s failed for %s: %v", f.Phase, f.Destination.Path(f.FileName), f.Err)
}

func (f TargetFailure) Unwrap() error { return f.Err }

// Result describes what a Publisher did.
type Result struct {
	Operations []*Operation
	// Written counts operations that produced a new version.
	Written int
	// Skipped counts operations that were not written because the target was
	// already up-to-date (idempotent re-publish).
	Skipped int
	// PrimaryError is the first error encountered: a preflight failure, a
	// snapshot failure, a write failure or a cancellation. It is preserved
	// separately from any rollback failures.
	PrimaryError error
	// RollbackFailures lists the targets that could not be restored. Every
	// entry means the target needs manual intervention; the Immutable flag
	// marks read-only archives that cannot be overwritten at all.
	RollbackFailures []TargetFailure
	// Canceled is true when the context was canceled during the release.
	Canceled bool
}

// NeedsManualIntervention reports whether at least one target could not be
// restored and an operator must reconcile it.
func (r *Result) NeedsManualIntervention() bool { return len(r.RollbackFailures) > 0 }

// Err returns nil for a fully successful release. Otherwise it returns an
// error joining the primary failure with every rollback failure, so the first
// error stays discoverable via errors.Is/errors.As and is never masked.
func (r *Result) Err() error {
	var errs []error
	if r.PrimaryError != nil {
		errs = append(errs, r.PrimaryError)
	}
	for i := range r.RollbackFailures {
		errs = append(errs, r.RollbackFailures[i])
	}
	return errors.Join(errs...)
}

// Publisher runs Operations transactionally. The zero value is usable.
type Publisher struct {
	// RollbackTimeout bounds a rollback that has no usable deadline of its own,
	// in particular a rollback triggered by a canceled context. Defaults to one
	// minute when zero, matching the requirement to revert within a minute.
	RollbackTimeout time.Duration
}

// Publish is a convenience wrapper around a zero-value Publisher.
func Publish(ctx context.Context, ops []*Operation) *Result {
	return (&Publisher{}).Publish(ctx, ops)
}

// Publish runs the release described by ops in order. On any failure or
// cancellation it rolls back the already written targets in reverse order and
// returns a Result describing both the primary error and any rollback
// failures; it never panics and never performs a partial rollback silently.
func (p *Publisher) Publish(ctx context.Context, ops []*Operation) *Result {
	res := &Result{Operations: ops}
	if len(ops) == 0 {
		return res
	}
	for _, op := range ops {
		if op == nil || op.Destination == nil || op.FileName == "" {
			res.PrimaryError = errors.New("invalid publish operation: destination and file name are required")
			return res
		}
		if (op.Contents == nil) == (op.UnencryptedData == nil) {
			res.PrimaryError = fmt.Errorf(
				"invalid publish operation for %s: exactly one of Contents or UnencryptedData must be set",
				op.Destination.Path(op.FileName))
			return res
		}
	}

	// 1. Preflight: every destination must be reachable before any write.
	if err := p.preflight(ctx, ops); err != nil {
		res.PrimaryError = err
		if ctxErr := ctx.Err(); ctxErr != nil {
			res.Canceled = true
		}
		return res
	}

	// 2. Snapshot every target before writing anything. A snapshot failure
	// aborts with no writes performed.
	for _, op := range ops {
		if err := ctx.Err(); err != nil {
			res.Canceled = true
			res.PrimaryError = err
			return res
		}
		snapper, ok := op.Destination.(Snapshotter)
		if !ok {
			continue
		}
		state, err := snapper.Snapshot(ctx, op.FileName)
		if err != nil {
			res.PrimaryError = fmt.Errorf("snapshot of %s failed: %w",
				op.Destination.Path(op.FileName), err)
			return res
		}
		op.state = state
	}

	// 3. Write in order, checking for cancellation before each target.
	for i, op := range ops {
		if err := ctx.Err(); err != nil {
			res.Canceled = true
			res.PrimaryError = err
			p.rollback(ctx, res, ops[:i])
			return res
		}

		if p.upToDate(op) {
			op.skipped = true
			res.Skipped++
			log.Infof("%s is already up-to-date, skipping", op.Destination.Path(op.FileName))
			continue
		}

		var err error
		if op.Contents != nil {
			err = op.Destination.Upload(op.Contents, op.FileName)
		} else {
			err = op.Destination.UploadUnencrypted(op.UnencryptedData, op.FileName)
		}
		if err != nil {
			res.PrimaryError = fmt.Errorf("publish to %s failed: %w",
				op.Destination.Path(op.FileName), err)
			p.rollback(ctx, res, ops[:i])
			return res
		}
		op.written = true
		res.Written++
	}

	// A cancellation landing after the last write still has to be reconciled.
	if err := ctx.Err(); err != nil {
		res.Canceled = true
		res.PrimaryError = err
		p.rollback(ctx, res, ops)
	}

	return res
}

// preflight checks every distinct destination once and joins all reachability
// errors so the operator sees every unreachable target at once. No write has
// happened when this runs.
func (p *Publisher) preflight(ctx context.Context, ops []*Operation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	checked := make(map[Destination]struct{})
	var errs []error
	for _, op := range ops {
		if _, ok := checked[op.Destination]; ok {
			continue
		}
		checked[op.Destination] = struct{}{}
		checker, ok := op.Destination.(PreflightChecker)
		if !ok {
			continue
		}
		if err := checker.Check(ctx); err != nil {
			errs = append(errs, fmt.Errorf("destination %s is unreachable: %w",
				op.Destination.Path(op.FileName), err))
		}
	}
	return errors.Join(errs...)
}

// upToDate reports whether the target already holds the intended payload. It
// only applies when a snapshot with a content digest is available.
func (p *Publisher) upToDate(op *Operation) bool {
	if op.state == nil || !op.state.Existed || op.state.Digest == "" {
		return false
	}
	return op.state.Digest == op.payloadDigest()
}

func (op *Operation) payloadDigest() string {
	if op.Contents != nil {
		sum := sha256.Sum256(op.Contents)
		return hex.EncodeToString(sum[:])
	}
	return digestMap(op.UnencryptedData)
}

// digestMap returns a stable hex SHA-256 of an unencrypted payload. Encoding
// through JSON sorts map keys, so two equal maps always hash identically.
func digestMap(data map[string]interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// rollback restores written targets in reverse write order. It never aborts
// on the first failure: every target gets an attempt, and failures are
// recorded on the result without touching PrimaryError.
func (p *Publisher) rollback(parentCtx context.Context, res *Result, ops []*Operation) {
	// The triggering context may already be canceled; cleanup must not inherit
	// that, but still gets its own deadline so a hung destination cannot block
	// the rollback forever.
	timeout := p.RollbackTimeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parentCtx), timeout)
	defer cancel()

	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		if !op.written {
			continue
		}
		path := op.Destination.Path(op.FileName)

		if op.state == nil {
			res.RollbackFailures = append(res.RollbackFailures, TargetFailure{
				Destination: op.Destination,
				FileName:    op.FileName,
				Phase:       "restore",
				Err:         errors.New("no snapshot available; destination does not support automatic rollback"),
			})
			log.Errorf("cannot roll back %s: destination does not support snapshots", path)
			continue
		}

		if !op.state.Existed {
			p.rollbackNewTarget(ctx, res, op)
			continue
		}

		restorer, ok := op.Destination.(Restorer)
		if !ok {
			res.RollbackFailures = append(res.RollbackFailures, TargetFailure{
				Destination: op.Destination,
				FileName:    op.FileName,
				Phase:       "restore",
				Err:         errors.New("destination does not implement Restore"),
			})
			continue
		}
		if err := restorer.Restore(ctx, op.state); err != nil {
			failure := TargetFailure{
				Destination: op.Destination,
				FileName:    op.FileName,
				Phase:       "restore",
				Err:         err,
				Immutable:   errors.Is(err, ErrImmutable),
			}
			res.RollbackFailures = append(res.RollbackFailures, failure)
			log.Errorf("could not restore %s: %v", path, err)
			continue
		}
		log.Infof("rolled back %s", path)
	}
}

// rollbackNewTarget handles a target that was created by the release and
// therefore needs to be deleted rather than overwritten.
func (p *Publisher) rollbackNewTarget(ctx context.Context, res *Result, op *Operation) {
	path := op.Destination.Path(op.FileName)
	deleter, ok := op.Destination.(Deleter)
	if !ok {
		res.RollbackFailures = append(res.RollbackFailures, TargetFailure{
			Destination: op.Destination,
			FileName:    op.FileName,
			Phase:       "delete",
			Err:         errors.New("target did not exist before the release and destination cannot delete it"),
		})
		return
	}
	if err := deleter.Delete(ctx, op.FileName); err != nil {
		failure := TargetFailure{
			Destination: op.Destination,
			FileName:    op.FileName,
			Phase:       "delete",
			Err:         err,
			Immutable:   errors.Is(err, ErrImmutable),
		}
		res.RollbackFailures = append(res.RollbackFailures, failure)
		log.Errorf("could not delete newly created %s: %v", path, err)
		return
	}
	log.Infof("deleted newly created %s", path)
}
