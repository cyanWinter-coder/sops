package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// Action names used by audit events. They match the historical values stored
// in the action column.
const (
	ActionDecrypt = "decrypt"
	ActionEncrypt = "encrypt"
	ActionRotate  = "rotate"
)

// Result values for an audit event.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultError   = "error"
	ResultDenied  = "denied"
	ResultUnknown = "unknown"
)

// DefaultRetention is the minimum time audit events are retained. The security
// policy asks for six months; 180 days is the conventional SQL interval used by
// the schema and janitor.
const DefaultRetention = 180 * 24 * time.Hour

// Event is the canonical, safe audit event. It intentionally has no field for
// plaintext or raw key material. Arbitrary diagnostic values can be carried in
// Details, Fields or Metadata, but all of them pass through the Redactor before
// they are persisted.
type Event struct {
	// ID is the idempotency key. Repeating an event with the same ID is
	// accepted at most once by the buffer and database.
	ID string `json:"id,omitempty" db:"event_id"`
	// EventID is an alias for ID used by schemas and APIs that name the
	// idempotency key explicitly.
	EventID string `json:"event_id,omitempty"`

	Action     string    `json:"action"`
	Operation  string    `json:"operation,omitempty"`
	Type       string    `json:"type,omitempty"`
	File       string    `json:"file"`
	FilePath   string    `json:"file_path,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	Time       time.Time `json:"time,omitempty"`
	OccurredAt time.Time `json:"occurred_at,omitempty"`

	// KeyGroupID is an opaque, stable identifier for the key group. It must
	// not contain a raw key fingerprint; use IdentifyKeyGroup to construct
	// one from member identifiers.
	KeyGroupID string `json:"key_group_id,omitempty"`
	KeyGroup   string `json:"key_group,omitempty"`

	Result  string `json:"result"`
	Status  string `json:"status,omitempty"`
	Success *bool  `json:"success,omitempty"`

	Username string `json:"username,omitempty"`

	// Details is the canonical bag of additional, redacted fields.
	Details map[string]any `json:"details,omitempty"`
	// Fields and Metadata are compatibility aliases for Details.
	Fields   map[string]any `json:"fields,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// AuditEvent is an alternate name for Event.
type AuditEvent = Event

// NewEvent creates an event with a random idempotency key and UTC timestamp.
func NewEvent(action, file, result string) Event {
	now := time.Now().UTC()
	id, err := randomID()
	if err != nil {
		// crypto/rand failure is not realistically recoverable. Fall back to a
		// time/content-derived key rather than panicking in an audit path.
		id = Fingerprint(fmt.Sprintf("%s\x00%s\x00%s\x00%d", action, file, result, now.UnixNano()))
	}
	return Event{
		ID:         id,
		EventID:    id,
		Action:     action,
		Operation:  action,
		Type:       action,
		File:       file,
		FilePath:   file,
		Timestamp:  now,
		Time:       now,
		OccurredAt: now,
		Result:     normalizeResult(result),
		Status:     normalizeResult(result),
	}
}

// NewDecryptEvent creates a canonical decrypt event.
func NewDecryptEvent(file, keyGroupID, result string) Event {
	e := NewEvent(ActionDecrypt, file, result)
	e.KeyGroupID = keyGroupID
	return e
}

// Canonical returns a copy with all compatibility aliases resolved into the
// canonical fields. It does not generate an ID or timestamp; call Normalize if
// defaults are required.
func (e Event) Canonical() Event {
	out := e

	if out.ID == "" {
		out.ID = out.EventID
	}
	if out.EventID == "" {
		out.EventID = out.ID
	}

	out.Action = firstNonEmpty(out.Action, out.Operation, out.Type)
	out.Operation = out.Action
	out.Type = out.Action

	out.File = firstNonEmpty(out.File, out.FilePath)
	out.FilePath = out.File

	out.Timestamp = firstTime(out.Timestamp, out.Time, out.OccurredAt)
	out.Time = out.Timestamp
	out.OccurredAt = out.Timestamp

	out.KeyGroupID = firstNonEmpty(out.KeyGroupID, out.KeyGroup)
	out.KeyGroup = out.KeyGroupID

	out.Result = firstNonEmpty(out.Result, out.Status)
	if (out.Result == "" || out.Result == ResultUnknown) && out.Success != nil {
		if *out.Success {
			out.Result = ResultSuccess
		} else {
			out.Result = ResultFailure
		}
	}
	if out.Result == "" {
		out.Result = ResultUnknown
	}
	out.Status = out.Result

	details := make(map[string]any)
	mergeMap(details, e.Details)
	mergeMap(details, e.Fields)
	mergeMap(details, e.Metadata)
	if len(details) == 0 {
		out.Details = nil
	} else {
		out.Details = details
	}
	out.Fields = nil
	out.Metadata = nil

	return out
}

// Normalize returns Canonical with defaults suitable for persistence. If no
// ID is supplied, a deterministic fingerprint is used so repeated submission
// of the same value remains idempotent.
func (e Event) Normalize() Event {
	out := e.Canonical()
	// Compute a content ID before stamping an occurrence time. This keeps the
	// deterministic idempotency key stable across retries of an event that did
	// not supply an explicit timestamp.
	if out.ID == "" {
		out.ID = FingerprintEvent(out)
		out.EventID = out.ID
	}
	if out.Timestamp.IsZero() {
		out.Timestamp = time.Now().UTC()
		out.Time = out.Timestamp
		out.OccurredAt = out.Timestamp
	}
	if out.Result == "" {
		out.Result = ResultUnknown
		out.Status = out.Result
	}
	return out
}

// NormalizeEvent converts one of the historical event structs or a generic
// Event into the canonical Event and applies persistence defaults.
func NormalizeEvent(event any) Event {
	return canonicalizeEvent(event).Normalize()
}

func canonicalizeEvent(event any) Event {
	switch v := event.(type) {
	case nil:
		return Event{Action: "unknown", Result: ResultUnknown}
	case Event:
		return v.Canonical()
	case *Event:
		if v == nil {
			return Event{Action: "unknown", Result: ResultUnknown}
		}
		return v.Canonical()
	case DecryptEvent:
		return oldEventToCanonical(ActionDecrypt, v.File, v.ID, v.Username, v.Timestamp, v.KeyGroupID, v.Result, v.Details, v.Fields)
	case *DecryptEvent:
		if v == nil {
			return NormalizeEvent(nil)
		}
		return canonicalizeEvent(*v)
	case EncryptEvent:
		return oldEventToCanonical(ActionEncrypt, v.File, v.ID, v.Username, v.Timestamp, v.KeyGroupID, v.Result, v.Details, v.Fields)
	case *EncryptEvent:
		if v == nil {
			return NormalizeEvent(nil)
		}
		return canonicalizeEvent(*v)
	case RotateEvent:
		return oldEventToCanonical(ActionRotate, v.File, v.ID, v.Username, v.Timestamp, v.KeyGroupID, v.Result, v.Details, v.Fields)
	case *RotateEvent:
		if v == nil {
			return NormalizeEvent(nil)
		}
		return canonicalizeEvent(*v)
	default:
		e := Event{
			Action: eventActionName(event),
			Result: ResultUnknown,
		}
		if id := reflectStringField(event, "ID", "EventID", "Id"); id != "" {
			e.ID = id
		}
		if file := reflectStringField(event, "File", "FilePath", "Path"); file != "" {
			e.File = file
		}
		if kg := reflectStringField(event, "KeyGroupID", "KeyGroup"); kg != "" {
			e.KeyGroupID = kg
		}
		if result := reflectStringField(event, "Result", "Status"); result != "" {
			e.Result = result
		}
		if username := reflectStringField(event, "Username", "User", "Actor"); username != "" {
			e.Username = username
		}
		if ts := reflectTimeField(event, "Timestamp", "Time", "OccurredAt"); !ts.IsZero() {
			e.Timestamp = ts
		}
		if m := reflectMapField(event, "Details", "Fields", "Metadata", "Attributes"); m != nil {
			e.Details = m
		}
		return e.Canonical()
	}
}

func oldEventToCanonical(action, file, id, username string, ts time.Time, keyGroupID, result string, maps ...map[string]any) Event {
	e := Event{
		ID:         id,
		EventID:    id,
		Action:     action,
		File:       file,
		Timestamp:  ts,
		KeyGroupID: keyGroupID,
		Result:     result,
		Username:   username,
	}
	for _, m := range maps {
		mergeMapLazy(&e.Details, m)
	}
	return e.Normalize()
}

// Fingerprint returns the hex SHA-256 digest of data.
func Fingerprint(data any) string {
	h := sha256.New()
	switch v := data.(type) {
	case string:
		_, _ = h.Write([]byte(v))
	case []byte:
		_, _ = h.Write(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			_, _ = h.Write([]byte(fmt.Sprintf("%#v", v)))
		} else {
			_, _ = h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FingerprintEvent returns a stable idempotency key for an event value. The ID
// fields are excluded so an event can be fingerprinted before a key is
// assigned.
func FingerprintEvent(event Event) string {
	e := event.Canonical()
	e.ID = ""
	e.EventID = ""
	b, err := json.Marshal(e)
	if err != nil {
		return Fingerprint(fmt.Sprintf("%#v", e))
	}
	return Fingerprint(b)
}

// EventIdentity returns the explicit idempotency key when present and
// otherwise a stable fingerprint of the event value.
func EventIdentity(event any) string {
	if id := explicitIdentity(event); id != "" {
		return id
	}
	// Use the same canonical representation and content ID as persistence.
	return FingerprintEvent(canonicalizeEvent(event))
}

// IdentifyKeyGroup returns an opaque stable identifier for a key group. Member
// identifiers are length-prefixed before hashing to avoid canonicalization
// ambiguity.
func IdentifyKeyGroup(members ...string) string {
	h := sha256.New()
	for _, member := range members {
		fmt.Fprintf(h, "%d:%s;", len(member), member)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func explicitIdentity(event any) string {
	switch v := event.(type) {
	case Event:
		return firstNonEmpty(v.ID, v.EventID)
	case *Event:
		if v != nil {
			return firstNonEmpty(v.ID, v.EventID)
		}
	case interface{ GetID() string }:
		if id := v.GetID(); id != "" {
			return id
		}
	case interface{ ID() string }:
		if id := v.ID(); id != "" {
			return id
		}
	}
	return reflectStringField(event, "ID", "EventID", "Id", "UUID", "Uuid")
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstTime(values ...time.Time) time.Time {
	for _, v := range values {
		if !v.IsZero() {
			return v.UTC()
		}
	}
	return time.Time{}
}

func normalizeResult(result string) string {
	if result == "" {
		return ""
	}
	return result
}

func mergeMap(dst map[string]any, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

func mergeMapLazy(dst *map[string]any, src map[string]any) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[string]any, len(src))
	}
	mergeMap(*dst, src)
}

func eventActionName(event any) string {
	t := reflect.TypeOf(event)
	if t == nil {
		return "unknown"
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

func reflectStringField(event any, names ...string) string {
	v := reflect.ValueOf(event)
	if !v.IsValid() {
		return ""
	}
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	for _, name := range names {
		f := v.FieldByName(name)
		if !f.IsValid() {
			continue
		}
		if f.Kind() == reflect.String {
			return f.String()
		}
		if f.CanInterface() {
			if s, ok := f.Interface().(fmt.Stringer); ok {
				return s.String()
			}
		}
	}
	return ""
}

func reflectTimeField(event any, names ...string) time.Time {
	v := reflect.ValueOf(event)
	if !v.IsValid() {
		return time.Time{}
	}
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return time.Time{}
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return time.Time{}
	}
	for _, name := range names {
		f := v.FieldByName(name)
		if !f.IsValid() || !f.CanInterface() {
			continue
		}
		if t, ok := f.Interface().(time.Time); ok {
			return t
		}
	}
	return time.Time{}
}

func reflectMapField(event any, names ...string) map[string]any {
	v := reflect.ValueOf(event)
	if !v.IsValid() {
		return nil
	}
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	for _, name := range names {
		f := v.FieldByName(name)
		if !f.IsValid() || f.IsNil() || !f.CanInterface() {
			continue
		}
		if m, ok := f.Interface().(map[string]any); ok {
			return m
		}
		if m, ok := f.Interface().(map[string]string); ok {
			out := make(map[string]any, len(m))
			for k, v := range m {
				out[k] = v
			}
			return out
		}
	}
	return nil
}
