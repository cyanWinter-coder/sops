package audit_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsops/sops/v3/audit"
)

type uid588FakeBackend struct {
	mu      sync.Mutex
	events  []any
	started chan struct{}
	once    sync.Once
	release chan struct{}
}

func newUID588FakeBackend(block bool) *uid588FakeBackend {
	f := &uid588FakeBackend{}
	if block {
		f.started = make(chan struct{})
		f.release = make(chan struct{})
	}
	return f
}

func (f *uid588FakeBackend) Handle(event any) {
	if f.started != nil {
		f.once.Do(func() { close(f.started) })
		<-f.release
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *uid588FakeBackend) ids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.events))
	for _, e := range f.events {
		switch v := e.(type) {
		case audit.Event:
			ids = append(ids, v.ID)
		case *audit.Event:
			ids = append(ids, v.ID)
		default:
			ids = append(ids, audit.EventIdentity(v))
		}
	}
	return ids
}

func TestUID588CanonicalDecryptEventHasRequiredAuditFields(t *testing.T) {
	ts := time.Date(2026, 11, 25, 1, 2, 3, 0, time.UTC)
	e := audit.NormalizeEvent(audit.DecryptEvent{
		ID:         "evt-1",
		File:       "secrets.yaml",
		Timestamp:  ts,
		KeyGroupID: "kg-1",
		Result:     audit.ResultSuccess,
		Username:   "alice",
	})

	if e.Action != audit.ActionDecrypt {
		t.Fatalf("action = %q, want decrypt", e.Action)
	}
	if e.Username != "alice" {
		t.Fatalf("username = %q, want alice", e.Username)
	}
	if e.File != "secrets.yaml" || e.Timestamp != ts || e.KeyGroupID != "kg-1" || e.Result != "success" {
		t.Fatalf("canonical event lost required fields: %#v", e)
	}
	if e.ID != "evt-1" || e.EventID != "evt-1" {
		t.Fatalf("id aliases not normalized: %#v", e)
	}
}

func TestUID588MaskIsLengthAndStableIrreversibleDigest(t *testing.T) {
	first := audit.MaskValue("super-secret-plaintext")
	second := audit.RedactValue("super-secret-plaintext")

	if first.Length != len("super-secret-plaintext") {
		t.Fatalf("length = %d, want %d", first.Length, len("super-secret-plaintext"))
	}
	if len(first.Digest) != 64 {
		t.Fatalf("digest length = %d, want 64 hex chars", len(first.Digest))
	}
	if first.Digest != second.Digest {
		t.Fatalf("digests differ for same value: %q vs %q", first.Digest, second.Digest)
	}
	if first.Digest == "super-secret-plaintext" || strings.Contains(first.String(), "super-secret-plaintext") {
		t.Fatalf("redaction summary leaked plaintext: %#v / %s", first, first.String())
	}
}

func TestUID588ConfiguredFieldsAndUnknownFieldsAreSensitiveByDefault(t *testing.T) {
	r := audit.NewRedactor([]string{"card_number"})
	out := r.RedactMap(map[string]any{
		"action":      "decrypt",
		"file":        "prod.yaml",
		"plaintext":   "do-not-leak",
		"card_number": "4111111111111111",
		"new_field":   "unknown-but-sensitive",
		"nested": map[string]any{
			"token": "abc",
			"kept":  "also-unknown-so-masked",
		},
	})

	if out["action"] != "decrypt" || out["file"] != "prod.yaml" {
		t.Fatalf("known safe query fields were redacted: %#v", out)
	}
	for _, key := range []string{"plaintext", "card_number", "new_field"} {
		if _, ok := out[key].(audit.RedactedValue); !ok {
			t.Fatalf("%s = %#v, want RedactedValue", key, out[key])
		}
	}
	if _, ok := out["nested"].(audit.RedactedValue); !ok {
		t.Fatalf("unknown nested field should be summarized as a sensitive value, got %T: %#v", out["nested"], out["nested"])
	}

	unknownAllowed := false
	relaxed := audit.NewRedactorFromConfig(audit.RedactionConfig{
		SensitiveFields:     []string{"card_number"},
		RedactUnknownFields: &unknownAllowed,
	})
	relaxedOut := relaxed.RedactMap(map[string]any{"mystery": "visible", "card_number": "x"})
	if relaxedOut["mystery"] != "visible" {
		t.Fatalf("unknown field should be allowed when default disabled: %#v", relaxedOut)
	}
	if _, ok := relaxedOut["card_number"].(audit.RedactedValue); !ok {
		t.Fatalf("configured sensitive field must still be redacted: %#v", relaxedOut)
	}
}

func TestUID588BufferedAuditorPreservesOrderAndDeduplicates(t *testing.T) {
	backend := newUID588FakeBackend(false)
	b := audit.NewBufferedAuditor(backend, 128, audit.WithRetry(1, time.Millisecond, time.Millisecond))

	const n = 50
	for i := 0; i < n; i++ {
		b.Handle(audit.Event{ID: fmt.Sprintf("order-%02d", i), Action: "decrypt", File: "f", Result: "success"})
	}
	duplicate := audit.Event{ID: "duplicate-id", Action: "decrypt", File: "f", Result: "success"}
	for i := 0; i < 5; i++ {
		b.Handle(duplicate)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ids := backend.ids()
	if len(ids) != n+1 {
		t.Fatalf("received %d events, want %d (duplicates must be suppressed)", len(ids), n+1)
	}
	for i := 0; i < n; i++ {
		if ids[i] != fmt.Sprintf("order-%02d", i) {
			t.Fatalf("event %d out of order: got %q full=%v", i, ids[i], ids)
		}
	}
	var dupCount int
	for _, id := range ids {
		if id == "duplicate-id" {
			dupCount++
		}
	}
	if dupCount != 1 {
		t.Fatalf("duplicate-id received %d times, want 1", dupCount)
	}
}

func TestUID588BufferedAuditorNeverBlocksAndReportsDrops(t *testing.T) {
	backend := newUID588FakeBackend(true)
	var reported []uint64
	var reportMu sync.Mutex
	b := audit.NewBufferedAuditor(
		backend,
		1,
		audit.WithDropReporter(func(n uint64) {
			reportMu.Lock()
			reported = append(reported, n)
			reportMu.Unlock()
		}),
		audit.WithRetry(1, time.Millisecond, time.Millisecond),
	)

	b.Handle(audit.Event{ID: "running", Action: "decrypt", File: "f", Result: "success"})
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start backend call")
	}

	deadline := time.Now().Add(2 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		b.Handle(audit.Event{ID: fmt.Sprintf("overflow-%d", i), Action: "decrypt", File: "f", Result: "success"})
		if b.DroppedCount() > 0 {
			break
		}
	}
	if b.DroppedCount() == 0 {
		t.Fatal("expected at least one dropped event while backend is unavailable")
	}

	close(backend.release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = b.Flush(ctx)
	_ = b.Close()

	reportMu.Lock()
	if len(reported) == 0 {
		t.Fatal("drop reporter was not called")
	}
	reportMu.Unlock()
}

func TestUID588RegisterInterfaceRemainsCompatible(t *testing.T) {
	audit.ResetAuditorsForTest()
	defer audit.ResetAuditorsForTest()

	backend := newUID588FakeBackend(false)
	audit.Register(backend)
	audit.SubmitEvent(audit.DecryptEvent{File: "compatible.yaml"})

	if len(backend.ids()) != 1 {
		t.Fatalf("registered legacy Auditor received %d events, want 1", len(backend.events))
	}
}

func TestUID588IdentifyKeyGroupIsStableOpaque(t *testing.T) {
	first := audit.IdentifyKeyGroup("fingerprint-a", "fingerprint-b")
	second := audit.IdentifyKeyGroup("fingerprint-a", "fingerprint-b")
	if first != second {
		t.Fatal("key group ID is not stable")
	}
	if first == "fingerprint-a" || strings.Contains(first, "fingerprint-a") {
		t.Fatal("key group ID exposes raw member identifier")
	}
}

func TestUID588SchemaSupportsIdempotencyFiltersAndRetention(t *testing.T) {
	// The test working directory is the package directory.
	b, err := os.ReadFile(filepath.Join("schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	schema := string(b)
	for _, want := range []string{
		"event_id TEXT NOT NULL UNIQUE",
		"ON CONFLICT", // present in Go insert, not schema; this assertion intentionally not schema-only below
	} {
		if want == "ON CONFLICT" {
			continue
		}
		if !strings.Contains(schema, want) {
			t.Fatalf("schema missing %q", want)
		}
	}
	if !strings.Contains(schema, "idx_audit_event_file_action_timestamp") {
		t.Fatal("schema missing file/action filter index")
	}
	if !strings.Contains(schema, "INTERVAL '180 days'") {
		t.Fatal("schema missing six month retention")
	}

	insertSource, err := os.ReadFile(filepath.Join("postgres.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(insertSource), "ON CONFLICT (event_id) DO NOTHING") {
		t.Fatal("postgres insert is not idempotent")
	}
}

func TestUID588FlushCancelReturnsWhenBackendStuck(t *testing.T) {
	backend := newUID588FakeBackend(true)
	b := audit.NewBufferedAuditor(backend, 1, audit.WithRetry(-1, time.Hour, time.Hour))
	b.Handle(audit.Event{ID: "stuck", Action: "decrypt"})
	<-backend.started

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if !errors.Is(b.Flush(ctx), context.DeadlineExceeded) {
		t.Fatalf("Flush error = %v, want deadline exceeded", b.Flush(ctx))
	}
	close(backend.release)
	_ = b.Close()
}
