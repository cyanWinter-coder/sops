package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDestination is an in-memory Destination implementing all optional
// capabilities. It is the test stand-in for S3/GCS/Vault and records every
// call so tests can assert ordering and rollback behavior.
type fakeDestination struct {
	name      string
	immutable bool

	mu          sync.Mutex
	objects     map[string][]byte
	checkErr    error
	snapshotErr error
	restoreErr  error
	deleteErr   error
	uploadErr   map[string]error
	calls       []string

	// beforeUpload, when set, is invoked inside Upload before the object is
	// stored. Tests use it to cancel the context from a known point in the
	// release instead of racing a timer.
	beforeUpload func(fileName string)
	// order, when non-nil, receives every call as "name:call" so tests can
	// assert cross-destination ordering such as reverse rollback.
	order *[]string
}

func newFakeDestination(name string) *fakeDestination {
	return &fakeDestination{
		name:    name,
		objects: map[string][]byte{},
	}
}

func (f *fakeDestination) Path(fileName string) string {
	return fmt.Sprintf("fake://%s/%s", f.name, fileName)
}

func (f *fakeDestination) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	if f.order != nil {
		*f.order = append(*f.order, f.name+":"+call)
	}
}

func (f *fakeDestination) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeDestination) get(fileName string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.objects[fileName]
	return v, ok
}

func (f *fakeDestination) Upload(fileContents []byte, fileName string) error {
	f.record("upload:" + fileName)
	if f.beforeUpload != nil {
		f.beforeUpload(fileName)
	}
	if err := f.uploadErr[fileName]; err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(fileContents))
	copy(cp, fileContents)
	f.objects[fileName] = cp
	return nil
}

func (f *fakeDestination) UploadUnencrypted(data map[string]interface{}, fileName string) error {
	f.record("upload:" + fileName)
	if err := f.uploadErr[fileName]; err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[fileName] = []byte(fmt.Sprintf("%v", data))
	return nil
}

func (f *fakeDestination) Check(ctx context.Context) error {
	f.record("check")
	return f.checkErr
}

func (f *fakeDestination) Snapshot(ctx context.Context, fileName string) (*TargetState, error) {
	f.record("snapshot:" + fileName)
	if f.snapshotErr != nil {
		return nil, f.snapshotErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[fileName]
	if !ok {
		return &TargetState{Destination: f, FileName: fileName, Existed: false}, nil
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return &TargetState{
		Destination: f,
		FileName:    fileName,
		Existed:     true,
		Digest:      digestBytes(cp),
		Version:     "v-old",
		Data:        cp,
	}, nil
}

func (f *fakeDestination) Restore(ctx context.Context, state *TargetState) error {
	f.record("restore:" + state.FileName)
	if f.immutable {
		return fmt.Errorf("%w: %s", ErrImmutable, f.Path(state.FileName))
	}
	if f.restoreErr != nil {
		return f.restoreErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(state.Data))
	copy(cp, state.Data)
	f.objects[state.FileName] = cp
	return nil
}

func (f *fakeDestination) Delete(ctx context.Context, fileName string) error {
	f.record("delete:" + fileName)
	if f.immutable {
		return fmt.Errorf("%w: %s", ErrImmutable, f.Path(fileName))
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, fileName)
	return nil
}

// basicDestination only implements Destination, none of the rollback
// capabilities.
type basicDestination struct {
	name    string
	mu      sync.Mutex
	objects map[string][]byte
}

func (b *basicDestination) Path(fileName string) string {
	return fmt.Sprintf("basic://%s/%s", b.name, fileName)
}

func (b *basicDestination) Upload(fileContents []byte, fileName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[fileName] = append([]byte(nil), fileContents...)
	return nil
}

func (b *basicDestination) UploadUnencrypted(data map[string]interface{}, fileName string) error {
	return &NotImplementedError{"basic destination does not support unencrypted uploads"}
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func encryptedOp(d *fakeDestination, name string, content string) *Operation {
	return &Operation{Destination: d, FileName: name, Contents: []byte(content)}
}

// TestSuccessfulPublishWritesAllTargetsAndTakesSnapshots covers requirement 1's
// happy path: preflight and snapshots happen before writes, in release order.
func TestSuccessfulPublishWritesAllTargetsAndTakesSnapshots(t *testing.T) {
	a, b, c, d := newFakeDestination("a"), newFakeDestination("b"),
		newFakeDestination("c"), newFakeDestination("d")
	a.objects["f1"] = []byte("old-a")
	b.objects["f2"] = []byte("old-b")

	ops := []*Operation{
		encryptedOp(a, "f1", "new-a"),
		encryptedOp(b, "f2", "new-b"),
		encryptedOp(c, "f3", "new-c"),
		encryptedOp(d, "f4", "new-d"),
	}
	res := (&Publisher{}).Publish(context.Background(), ops)
	if err := res.Err(); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if res.Written != 4 || res.Skipped != 0 {
		t.Fatalf("want 4 written, 0 skipped, got %d/%d", res.Written, res.Skipped)
	}
	for _, pair := range []struct {
		dest *fakeDestination
		name string
		want string
	}{
		{a, "f1", "new-a"}, {b, "f2", "new-b"},
		{c, "f3", "new-c"}, {d, "f4", "new-d"},
	} {
		got, ok := pair.dest.get(pair.name)
		if !ok || string(got) != pair.want {
			t.Fatalf("%s: want %q, got %q (exists=%v)", pair.name, pair.want, got, ok)
		}
	}

	// All checks and snapshots must precede any upload.
	calls := a.Calls()
	if len(calls) < 2 || calls[0] != "check" || calls[1] != "snapshot:f1" {
		t.Fatalf("check/snapshot must precede upload, got %v", calls)
	}
}

// TestPreflightFailureAbortsBeforeAnyWrite covers requirement 5: an
// unreachable destination fails fast without touching any target.
func TestPreflightFailureAbortsBeforeAnyWrite(t *testing.T) {
	healthy := newFakeDestination("healthy")
	unreachable := newFakeDestination("down")
	unreachable.checkErr = errors.New("connection refused")

	ops := []*Operation{
		encryptedOp(healthy, "f1", "new"),
		encryptedOp(unreachable, "f2", "new"),
	}
	res := (&Publisher{}).Publish(context.Background(), ops)
	if res.Err() == nil {
		t.Fatal("expected preflight error")
	}
	if res.PrimaryError == nil || !contains(res.PrimaryError.Error(), "unreachable") {
		t.Fatalf("want unreachable error, got %v", res.PrimaryError)
	}
	if res.Written != 0 {
		t.Fatalf("no writes expected, got %d", res.Written)
	}
	if _, ok := healthy.get("f1"); ok {
		t.Fatal("healthy destination must not have been written")
	}
	for _, calls := range [][]string{healthy.Calls(), unreachable.Calls()} {
		for _, call := range calls {
			if call == "upload:f1" || call == "upload:f2" {
				t.Fatalf("no uploads allowed during failed preflight, got %v", calls)
			}
		}
	}
}

// TestWriteFailureRollsBackInReverseOrder covers requirement 1: a failed write
// restores every already written target in reverse order.
func TestWriteFailureRollsBackInReverseOrder(t *testing.T) {
	a, b, c := newFakeDestination("a"), newFakeDestination("b"), newFakeDestination("c")
	order := &[]string{}
	a.order, b.order, c.order = order, order, order
	a.objects["f1"] = []byte("old-a")
	b.objects["f2"] = []byte("old-b")
	boom := errors.New("rate limited")
	c.uploadErr = map[string]error{"f3": boom}

	ops := []*Operation{
		encryptedOp(a, "f1", "new-a"),
		encryptedOp(b, "f2", "new-b"),
		encryptedOp(c, "f3", "new-c"),
	}
	res := (&Publisher{}).Publish(context.Background(), ops)
	if res.Err() == nil {
		t.Fatal("expected failure")
	}
	if !errors.Is(res.PrimaryError, boom) {
		t.Fatalf("primary error must be preserved, got %v", res.PrimaryError)
	}
	if got, _ := a.get("f1"); string(got) != "old-a" {
		t.Fatalf("a not rolled back: %q", got)
	}
	if got, _ := b.get("f2"); string(got) != "old-b" {
		t.Fatalf("b not rolled back: %q", got)
	}

	// b was written after a, so b must be restored before a.
	restoreB := indexInOrder(*order, "b:restore:f2")
	restoreA := indexInOrder(*order, "a:restore:f1")
	if restoreB < 0 || restoreA < 0 {
		t.Fatalf("missing restore calls in order: %v", *order)
	}
	if restoreB >= restoreA {
		t.Fatalf("reverse order violated: b restore at %d, a at %d (%v)",
			restoreB, restoreA, *order)
	}
}

// TestRollbackFailureDoesNotMaskPrimaryError covers requirement 2: restore
// failures are recorded separately and the primary error stays available.
func TestRollbackFailureDoesNotMaskPrimaryError(t *testing.T) {
	a, b := newFakeDestination("a"), newFakeDestination("b")
	a.objects["f1"] = []byte("old-a")
	b.objects["f2"] = []byte("old-b")
	primary := errors.New("vault rate limited")
	restoreErr := errors.New("restore endpoint broken")
	b.restoreErr = restoreErr
	// b fails its restore; c fails its write and triggers rollback.
	c := newFakeDestination("c")
	c.uploadErr = map[string]error{"f3": primary}

	ops := []*Operation{
		encryptedOp(a, "f1", "new-a"),
		encryptedOp(b, "f2", "new-b"),
		encryptedOp(c, "f3", "new-c"),
	}
	res := (&Publisher{}).Publish(context.Background(), ops)
	if !errors.Is(res.Err(), primary) {
		t.Fatalf("joined error must still expose primary: %v", res.Err())
	}
	if !errors.Is(res.Err(), restoreErr) {
		t.Fatalf("joined error must expose rollback failure: %v", res.Err())
	}
	if res.PrimaryError == nil || !errors.Is(res.PrimaryError, primary) {
		t.Fatalf("primary error overwritten: %v", res.PrimaryError)
	}
	if !res.NeedsManualIntervention() || len(res.RollbackFailures) != 1 {
		t.Fatalf("want exactly one rollback failure, got %+v", res.RollbackFailures)
	}
	failure := res.RollbackFailures[0]
	if failure.Destination != b || failure.Phase != "restore" ||
		!errors.Is(failure.Err, restoreErr) || failure.Immutable {
		t.Fatalf("unexpected failure record: %+v", failure)
	}
	// a still rolled back despite b failing: rollback continues past failures.
	if got, _ := a.get("f1"); string(got) != "old-a" {
		t.Fatalf("a should still roll back, got %q", got)
	}
}

// TestImmutableArchiveRollbackIsFlaggedForManualIntervention covers the
// read-only archive case: restores/deletes return ErrImmutable and the target
// is flagged rather than retried or reported as a generic error.
func TestImmutableArchiveRollbackIsFlaggedForManualIntervention(t *testing.T) {
	archive := newFakeDestination("archive")
	archive.immutable = true
	archive.objects["f1"] = []byte("old")
	trigger := newFakeDestination("trigger")
	trigger.uploadErr = map[string]error{"f2": errors.New("boom")}

	res := (&Publisher{}).Publish(context.Background(), []*Operation{
		encryptedOp(archive, "f1", "new"),
		encryptedOp(trigger, "f2", "new"),
	})
	if res.Err() == nil {
		t.Fatal("expected failure")
	}
	if len(res.RollbackFailures) != 1 {
		t.Fatalf("want one rollback failure, got %+v", res.RollbackFailures)
	}
	failure := res.RollbackFailures[0]
	if failure.Destination != archive || !failure.Immutable ||
		!errors.Is(failure.Err, ErrImmutable) {
		t.Fatalf("want immutable manual-intervention flag, got %+v", failure)
	}
	if !res.NeedsManualIntervention() {
		t.Fatal("result must report manual intervention")
	}
}

// TestNewTargetIsDeletedOnRollback covers a target created by the release:
// rollback deletes it instead of trying to restore content.
func TestNewTargetIsDeletedOnRollback(t *testing.T) {
	fresh := newFakeDestination("fresh")
	trigger := newFakeDestination("trigger")
	trigger.uploadErr = map[string]error{"f2": errors.New("boom")}

	res := (&Publisher{}).Publish(context.Background(), []*Operation{
		encryptedOp(fresh, "f1", "new"),
		encryptedOp(trigger, "f2", "new"),
	})
	if res.Err() == nil {
		t.Fatal("expected failure")
	}
	if _, ok := fresh.get("f1"); ok {
		t.Fatal("newly created target must be deleted on rollback")
	}
	if got := fresh.Calls(); lastIndex(got, "delete:f1") < 0 {
		t.Fatalf("expected delete call, got %v", got)
	}
	if len(res.RollbackFailures) != 0 {
		t.Fatalf("clean rollback expected, got %+v", res.RollbackFailures)
	}
}

// TestIdempotentRepublishSkipsUnchangedTargets covers requirement 3: the same
// content published twice produces no second write on any target.
func TestIdempotentRepublishSkipsUnchangedTargets(t *testing.T) {
	a, b := newFakeDestination("a"), newFakeDestination("b")
	a.objects["f1"] = []byte("v1")
	b.objects["f2"] = []byte("v1")

	first := (&Publisher{}).Publish(context.Background(), []*Operation{
		encryptedOp(a, "f1", "v2"),
		encryptedOp(b, "f2", "v2"),
	})
	if err := first.Err(); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if first.Written != 2 {
		t.Fatalf("want 2 writes, got %d", first.Written)
	}

	second := (&Publisher{}).Publish(context.Background(), []*Operation{
		encryptedOp(a, "f1", "v2"),
		encryptedOp(b, "f2", "v2"),
	})
	if err := second.Err(); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if second.Written != 0 || second.Skipped != 2 {
		t.Fatalf("want 0 writes and 2 skips, got written=%d skipped=%d",
			second.Written, second.Skipped)
	}
	for _, dest := range []*fakeDestination{a, b} {
		var uploads int
		for _, call := range dest.Calls() {
			if len(call) >= 6 && call[:6] == "upload" {
				uploads++
			}
		}
		if uploads != 1 {
			t.Fatalf("%s uploaded %d times, want exactly 1: %v", dest.name, uploads, dest.Calls())
		}
	}
}

// TestIdempotencyAlsoAppliesToUnencryptedPayloads ensures map payloads are
// compared by content, not by map identity or key order.
func TestIdempotencyAlsoAppliesToUnencryptedPayloads(t *testing.T) {
	v := newFakeDestination("vaultish")
	v.objects["secret"] = []byte("map[a:1 b:2]")
	// Seed a snapshot state directly to control the digest path.
	existing := map[string]interface{}{"a": 1, "b": 2}

	op := &Operation{
		Destination:     v,
		FileName:        "secret",
		UnencryptedData: map[string]interface{}{"b": 2, "a": 1},
	}
	// Simulate an already-current snapshot as Snapshot would produce it.
	state := &TargetState{
		Destination:     v,
		FileName:        "secret",
		Existed:         true,
		Digest:          digestMap(existing),
		UnencryptedData: existing,
	}
	op.state = state

	p := &Publisher{}
	if !p.upToDate(op) {
		t.Fatal("equal maps with different key order must be considered up-to-date")
	}
}

// TestCancelationRollsBackWrittenTargets covers requirement 4: a context
// canceled between writes triggers a reverse rollback of what was written.
// The cancel fires deterministically from the third target's upload hook once
// the first two targets have been written.
func TestCancelationRollsBackWrittenTargets(t *testing.T) {
	a, b, c := newFakeDestination("a"), newFakeDestination("b"), newFakeDestination("c")
	order := &[]string{}
	a.order, b.order, c.order = order, order, order
	a.objects["f1"] = []byte("old-a")
	b.objects["f2"] = []byte("old-b")
	ctx, cancel := context.WithCancel(context.Background())
	c.beforeUpload = func(string) { cancel() }

	res := (&Publisher{}).Publish(ctx, []*Operation{
		encryptedOp(a, "f1", "new-a"),
		encryptedOp(b, "f2", "new-b"),
		encryptedOp(c, "f3", "new-c"),
	})
	if !res.Canceled {
		t.Fatalf("want canceled result, got %+v", res)
	}
	if res.PrimaryError == nil {
		t.Fatal("canceled publish must carry the context error as primary error")
	}
	if got, ok := a.get("f1"); ok && string(got) != "old-a" {
		t.Fatalf("a not rolled back after cancel: %q", got)
	}
	if got, ok := b.get("f2"); ok && string(got) != "old-b" {
		t.Fatalf("b not rolled back after cancel: %q", got)
	}
	if _, ok := c.get("f3"); ok {
		t.Fatal("target whose write was interrupted by cancel must not exist")
	}
	restoreB := indexInOrder(*order, "b:restore:f2")
	restoreA := indexInOrder(*order, "a:restore:f1")
	if restoreB < 0 || restoreA < 0 || restoreB >= restoreA {
		t.Fatalf("reverse rollback order violated: %v", *order)
	}
}

// TestAlreadyCanceledContextFailsBeforeWrites checks the fast path: a release
// started with an already canceled context performs no writes at all.
func TestAlreadyCanceledContextFailsBeforeWrites(t *testing.T) {
	a := newFakeDestination("a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := (&Publisher{}).Publish(ctx, []*Operation{encryptedOp(a, "f1", "new")})
	if !res.Canceled || res.PrimaryError == nil {
		t.Fatalf("want immediate cancellation, got %+v", res)
	}
	if res.Written != 0 {
		t.Fatal("no writes expected")
	}
	if _, ok := a.get("f1"); ok {
		t.Fatal("nothing should have been written")
	}
}

// TestCancelationWithImmutableTargetIsMarkedManual combines requirements 4 and
// the archive rule: when cancel triggers rollback against an immutable target,
// the target is flagged for manual intervention rather than silently lost.
func TestCancelationWithImmutableTargetIsMarkedManual(t *testing.T) {
	archive := newFakeDestination("archive")
	archive.immutable = true
	archive.objects["f1"] = []byte("old")
	other := newFakeDestination("other")
	ctx, cancel := context.WithCancel(context.Background())
	other.beforeUpload = func(string) { cancel() }

	res := (&Publisher{}).Publish(ctx, []*Operation{
		encryptedOp(archive, "f1", "new"),
		encryptedOp(other, "f2", "new"),
	})
	if !res.Canceled {
		t.Fatalf("want canceled result, got %+v", res)
	}
	var found bool
	for _, failure := range res.RollbackFailures {
		if failure.Destination == archive && failure.Immutable &&
			errors.Is(failure.Err, ErrImmutable) {
			found = true
		}
	}
	if !found {
		t.Fatalf("immutable target must be flagged manual on cancel, got %+v",
			res.RollbackFailures)
	}
}

// TestRollbackRunsUnderDetachedContext verifies requirement 4's cleanup
// guarantee: once writes are in flight, cancellation still restores earlier
// targets because rollback detaches from the canceled context. The hook-based
// cancellation in TestCancelationRollsBackWrittenTargets already exercises
// this path; here we assert the result carries no rollback failure from the
// canceled context itself.
func TestRollbackRunsUnderDetachedContext(t *testing.T) {
	a := newFakeDestination("a")
	a.objects["f1"] = []byte("old")
	trigger := newFakeDestination("trigger")
	ctx, cancel := context.WithCancel(context.Background())
	trigger.beforeUpload = func(string) { cancel() }

	res := (&Publisher{RollbackTimeout: time.Second}).Publish(ctx, []*Operation{
		encryptedOp(a, "f1", "new"),
		encryptedOp(trigger, "f2", "new"),
	})
	if !res.Canceled {
		t.Fatalf("want canceled result, got %+v", res)
	}
	for _, failure := range res.RollbackFailures {
		if errors.Is(failure.Err, context.Canceled) ||
			errors.Is(failure.Err, context.DeadlineExceeded) {
			t.Fatalf("rollback must not inherit the canceled context: %+v", failure)
		}
	}
	if got, _ := a.get("f1"); string(got) != "old" {
		t.Fatalf("a must be restored despite canceled context, got %q", got)
	}
}

// TestSnapshotFailureAbortsWithoutWrites covers failure while recording the
// old state: nothing may be written and the primary error names the snapshot.
func TestSnapshotFailureAbortsWithoutWrites(t *testing.T) {
	broken := newFakeDestination("broken")
	broken.snapshotErr = errors.New("access denied")
	other := newFakeDestination("other")

	res := (&Publisher{}).Publish(context.Background(), []*Operation{
		encryptedOp(other, "f1", "new"),
		encryptedOp(broken, "f2", "new"),
	})
	if res.Err() == nil || !contains(res.PrimaryError.Error(), "snapshot") {
		t.Fatalf("want snapshot error, got %v", res.PrimaryError)
	}
	if res.Written != 0 {
		t.Fatal("snapshot failure must prevent all writes")
	}
}

// TestDestinationWithoutCapabilitiesIsFlaggedOnRollback keeps the Destination
// interface compatible: a plain destination still publishes, but a rollback
// reports it as requiring manual intervention instead of panicking.
func TestDestinationWithoutCapabilitiesIsFlaggedOnRollback(t *testing.T) {
	basic := &basicDestination{name: "legacy", objects: map[string][]byte{}}
	trigger := newFakeDestination("trigger")
	trigger.uploadErr = map[string]error{"f2": errors.New("boom")}

	res := (&Publisher{}).Publish(context.Background(), []*Operation{
		{Destination: basic, FileName: "f1", Contents: []byte("new")},
		encryptedOp(trigger, "f2", "new"),
	})
	if res.Err() == nil {
		t.Fatal("expected failure")
	}
	if len(res.RollbackFailures) != 1 {
		t.Fatalf("want one manual-intervention entry, got %+v", res.RollbackFailures)
	}
	failure := res.RollbackFailures[0]
	if failure.Destination != basic || failure.Phase != "restore" {
		t.Fatalf("unexpected failure record: %+v", failure)
	}
}

// TestInvalidOperationsFailBeforeAnySideEffect validates operation validation:
// malformed input is rejected before preflight, snapshot or write.
func TestInvalidOperationsFailBeforeAnySideEffect(t *testing.T) {
	good := newFakeDestination("good")
	cases := []struct {
		name string
		op   *Operation
	}{
		{"nil destination", &Operation{FileName: "f", Contents: []byte("x")}},
		{"empty file name", &Operation{Destination: good, Contents: []byte("x")}},
		{"both payloads", &Operation{Destination: good, FileName: "f", Contents: []byte("x"), UnencryptedData: map[string]interface{}{"k": "v"}}},
		{"neither payload", &Operation{Destination: good, FileName: "f"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := (&Publisher{}).Publish(context.Background(), []*Operation{tc.op})
			if res.Err() == nil {
				t.Fatal("expected validation error")
			}
			if res.Written != 0 || len(good.Calls()) != 0 {
				t.Fatalf("validation failure must have no side effects: %v", good.Calls())
			}
		})
	}
}

// TestDigestMapIsStableAndHexEncoded locks the idempotency digest format used
// by all destinations.
func TestDigestMapIsStableAndHexEncoded(t *testing.T) {
	d1 := digestMap(map[string]interface{}{"z": 1, "a": 2})
	d2 := digestMap(map[string]interface{}{"a": 2, "z": 1})
	if d1 != d2 || d1 == "" {
		t.Fatalf("digest must be stable across key order: %q vs %q", d1, d2)
	}
	if len(d1) != 64 {
		t.Fatalf("want 64 hex chars (sha256), got %d: %q", len(d1), d1)
	}
	// nil maps marshal to "null" and still get a digest, so idempotency checks
	// never get silently disabled by an empty digest.
	if digestMap(nil) == "" {
		t.Fatal("nil map digest must not be empty")
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

func lastIndex(calls []string, want string) int {
	idx := -1
	for i, call := range calls {
		if call == want {
			idx = i
		}
	}
	return idx
}

func indexInOrder(order []string, want string) int {
	for i, call := range order {
		if call == want {
			return i
		}
	}
	return -1
}
