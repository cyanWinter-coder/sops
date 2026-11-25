package audit

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"
)

// RedactedValue is the only safe representation of a value that must not be
// written to audit logs. It records the original byte length and a stable,
// irreversible SHA-256 digest. The digest is unsalted so the same value gets
// the same summary in every event.
type RedactedValue struct {
	Length int    `json:"length"`
	Digest string `json:"digest"`
	// Hash is populated with the same digest for APIs/tests that use "hash"
	// terminology. It is omitted from JSON to keep the serialized summary to
	// length plus one digest field.
	Hash string `json:"-"`
}

// GetHash returns the stable digest. It is provided for callers that prefer a
// method; the Hash field contains the same value.
func (r RedactedValue) GetHash() string { return r.Digest }

// SHA256 returns the stable hex SHA-256 digest.
func (r RedactedValue) SHA256() string { return r.Digest }

// String never contains the original value.
func (r RedactedValue) String() string {
	return fmt.Sprintf("[REDACTED length=%d sha256=%s]", r.Length, r.Digest)
}

// GoString keeps fmt's %#v formatting safe as well.
func (r RedactedValue) GoString() string { return r.String() }

// Common alternate names for the redacted summary.
type (
	MaskedValue    = RedactedValue
	Redacted       = RedactedValue
	Masked         = RedactedValue
	SensitiveValue = RedactedValue
)

// RedactionConfig configures field classification. The zero value is not
// usable; use NewRedactorFromConfig or DefaultRedactor.
type RedactionConfig struct {
	// SensitiveFields contains field names or glob paths that must always be
	// redacted, for example "plaintext" or "*.fingerprint".
	SensitiveFields []string `yaml:"sensitive_fields" json:"sensitive_fields"`
	// SafeFields explicitly marks fields that may remain visible.
	SafeFields []string `yaml:"safe_fields" json:"safe_fields"`
	// RedactUnknownFields defaults to true. A pointer is used so configuration
	// can distinguish unset from an explicit false.
	RedactUnknownFields *bool `yaml:"redact_unknown_fields" json:"redact_unknown_fields"`
}

// Redactor classifies and redacts audit fields. A Redactor is safe for
// concurrent use after construction.
type Redactor struct {
	sensitive     map[string]struct{}
	safe          map[string]struct{}
	redactUnknown bool
}

// DefaultSensitiveFields lists common secret names. Unknown fields are already
// redacted by default; this list mainly makes intent explicit and protects a
// name if it is ever added to the built-in safe set.
func DefaultSensitiveFields() []string {
	return []string{
		"plaintext", "cleartext", "ciphertext", "secret", "secrets",
		"password", "passwd", "token", "api_key", "apikey",
		"private_key", "data_key", "master_key", "key",
		"fingerprint", "key_fingerprint", "keyfingerprint",
		"encrypted_data_key", "encrypted_datakey",
	}
}

// DefaultSafeFields are the schema and transport fields that audit needs to
// remain queryable.
func DefaultSafeFields() []string {
	return []string{
		"id", "event_id", "action", "operation", "type",
		"file", "file_path", "filepath", "path",
		"timestamp", "time", "occurred_at", "at",
		"key_group_id", "keygroupid", "key_group", "keygroup",
		"result", "status", "success", "code", "error_code",
		"username", "user",
		"details", "fields", "metadata", "attributes", "extra",
		"length", "digest", "hash", "sha256", "algorithm",
	}
}

// NewRedactor creates a Redactor with unknown-field redaction enabled. It
// accepts either field names or a single []string/[]any list, allowing both
// NewRedactor("token") and NewRedactor([]string{"token"}) call styles.
func NewRedactor(fields ...any) *Redactor {
	return NewRedactorFromConfig(RedactionConfig{SensitiveFields: expandFieldArgs(fields)})
}

// NewVariadicRedactor is an explicit string-variadic constructor.
func NewVariadicRedactor(sensitiveFields ...string) *Redactor {
	return NewRedactorFromConfig(RedactionConfig{SensitiveFields: sensitiveFields})
}

func expandFieldArgs(args []any) []string {
	var fields []string
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			fields = append(fields, v)
		case []string:
			fields = append(fields, v...)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					fields = append(fields, s)
				}
			}
		}
	}
	return fields
}

// NewRedactorFromConfig creates a configured Redactor.
func NewRedactorFromConfig(cfg RedactionConfig) *Redactor {
	r := &Redactor{
		sensitive:     make(map[string]struct{}),
		safe:          make(map[string]struct{}),
		redactUnknown: true,
	}
	if cfg.RedactUnknownFields != nil {
		r.redactUnknown = *cfg.RedactUnknownFields
	}
	for _, f := range DefaultSensitiveFields() {
		r.addSensitive(f)
	}
	for _, f := range cfg.SensitiveFields {
		r.addSensitive(f)
	}
	for _, f := range DefaultSafeFields() {
		r.addSafe(f)
	}
	for _, f := range cfg.SafeFields {
		r.addSafe(f)
	}
	return r
}

// DefaultRedactor returns the secure default: configured common sensitive
// names and redaction of every unknown field.
func DefaultRedactor() *Redactor { return NewRedactorFromConfig(RedactionConfig{}) }

func (r *Redactor) addSensitive(field string) {
	for _, name := range fieldNames(field) {
		r.sensitive[name] = struct{}{}
	}
}

func (r *Redactor) addSafe(field string) {
	for _, name := range fieldNames(field) {
		r.safe[name] = struct{}{}
	}
}

// RedactUnknown reports whether fields not explicitly classified are masked.
func (r *Redactor) RedactUnknown() bool { return r.redactUnknown }

// IsSensitive reports whether a field path must be masked. Explicit sensitive
// configuration wins over the safe list.
func (r *Redactor) IsSensitive(fieldPath string) bool {
	if r == nil || (r.sensitive == nil && r.safe == nil) {
		// Preserve the secure default even for a nil or zero-value Redactor.
		return DefaultRedactor().IsSensitive(fieldPath)
	}
	raw := strings.ToLower(strings.TrimSpace(fieldPath))
	normalized := normalizeFieldName(fieldPath)
	baseRaw := raw
	if i := strings.LastIndex(raw, "."); i >= 0 {
		baseRaw = raw[i+1:]
	}
	baseNormalized := normalizeFieldName(baseRaw)

	candidates := []string{raw, normalized, baseRaw, baseNormalized}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := r.sensitive[candidate]; ok {
			return true
		}
		for pattern := range r.sensitive {
			if strings.ContainsAny(pattern, "*?[") {
				if ok, _ := path.Match(pattern, candidate); ok {
					return true
				}
			}
		}
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := r.safe[candidate]; ok {
			return false
		}
	}
	return r.redactUnknown
}

// RedactEvent returns a copy of e with all detail fields classified by the
// redactor. The canonical query fields are retained.
func (r *Redactor) RedactEvent(event Event) Event {
	if r == nil {
		r = DefaultRedactor()
	}
	e := event.Canonical()
	e.Details = r.RedactMap(e.Details)
	return e
}

// RedactMap returns a redacted copy of m.
func (r *Redactor) RedactMap(m map[string]any) map[string]any {
	if r == nil {
		r = DefaultRedactor()
	}
	if m == nil {
		return nil
	}
	out, _ := r.redactReflect(reflect.ValueOf(m), "").(map[string]any)
	return out
}

// Redact returns a redacted copy of an arbitrary map, slice or struct value.
func (r *Redactor) Redact(value any) any {
	if r == nil {
		r = DefaultRedactor()
	}
	if value == nil {
		return nil
	}
	return r.redactReflect(reflect.ValueOf(value), "")
}

// RedactField classifies fieldPath and either masks value or recursively
// redacts it.
func (r *Redactor) RedactField(fieldPath string, value any) any {
	if r == nil {
		r = DefaultRedactor()
	}
	if r.IsSensitive(fieldPath) {
		return MaskValue(value)
	}
	if value == nil {
		return nil
	}
	return r.redactReflect(reflect.ValueOf(value), fieldPath)
}

func (r *Redactor) redactReflect(v reflect.Value, fieldPath string) any {
	if !v.IsValid() {
		return nil
	}
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	if t, ok := v.Interface().(time.Time); ok {
		return t
	}
	if redacted, ok := v.Interface().(RedactedValue); ok {
		return redacted
	}

	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.Map:
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			key := fmt.Sprint(iter.Key().Interface())
			childPath := joinFieldPath(fieldPath, key)
			if r.IsSensitive(childPath) || r.IsSensitive(key) {
				out[key] = MaskValue(iter.Value().Interface())
			} else {
				out[key] = r.redactReflect(iter.Value(), childPath)
			}
		}
		return out
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(b), v)
			if r.IsSensitive(fieldPath) {
				return MaskValue(b)
			}
			return b
		}
		out := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			out[i] = r.redactReflect(v.Index(i), fieldPath)
		}
		return out
	case reflect.Struct:
		out := make(map[string]any, v.NumField())
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			ft := t.Field(i)
			if ft.PkgPath != "" {
				continue // unexported
			}
			name := structFieldName(ft)
			if name == "-" {
				continue
			}
			childPath := joinFieldPath(fieldPath, name)
			if sensitiveTag(ft) || r.IsSensitive(childPath) || r.IsSensitive(name) {
				out[name] = MaskValue(v.Field(i).Interface())
			} else {
				out[name] = r.redactReflect(v.Field(i), childPath)
			}
		}
		return out
	default:
		if v.CanInterface() {
			return v.Interface()
		}
		return nil
	}
}

// MaskValue returns length and stable digest for a value. Structured values are
// canonically encoded as JSON before digesting.
func MaskValue(value any) RedactedValue {
	if value == nil {
		return digestBytes(nil)
	}
	switch v := value.(type) {
	case RedactedValue:
		return v
	case *RedactedValue:
		if v == nil {
			return digestBytes(nil)
		}
		return *v
	case string:
		return digestBytes([]byte(v))
	case []byte:
		return digestBytes(v)
	case json.RawMessage:
		return digestBytes(v)
	case fmt.Stringer:
		return digestBytes([]byte(v.String()))
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return digestBytes([]byte(fmt.Sprint(v)))
		}
		return digestBytes(b)
	}
}

// RedactValue is an alias for MaskValue.
func RedactValue(value any) RedactedValue { return MaskValue(value) }

// SummarizeValue is an alias for MaskValue.
func SummarizeValue(value any) RedactedValue { return MaskValue(value) }

// Mask is an alias for MaskValue.
func Mask(value any) RedactedValue { return MaskValue(value) }

// Redact is an alias for MaskValue.
func Redact(value any) RedactedValue { return MaskValue(value) }

// DigestValue returns only the stable digest.
func DigestValue(value any) string { return MaskValue(value).Digest }

// HashValue returns only the stable digest.
func HashValue(value any) string { return MaskValue(value).Digest }

func digestBytes(b []byte) RedactedValue {
	sum := sha256Sum(b)
	return RedactedValue{Length: len(b), Digest: sum, Hash: sum}
}

func sha256Sum(b []byte) string {
	// Wrapper keeps crypto/sha256 import localized in this file's history.
	return Fingerprint(b)
}

func normalizeFieldName(field string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(field) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func fieldNames(field string) []string {
	raw := strings.ToLower(strings.TrimSpace(field))
	// Glob patterns must be matched verbatim. In particular, deriving a base
	// "*" from "credentials.*" would otherwise classify every field as
	// sensitive.
	if strings.ContainsAny(raw, "*?[") {
		return []string{raw}
	}
	names := []string{raw, normalizeFieldName(field)}
	if i := strings.LastIndex(raw, "."); i >= 0 {
		base := raw[i+1:]
		names = append(names, base, normalizeFieldName(base))
	}
	return names
}

func joinFieldPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func structFieldName(f reflect.StructField) string {
	if tag := f.Tag.Get("audit"); tag != "" {
		name := strings.Split(tag, ",")[0]
		if name != "" {
			return name
		}
	}
	if tag := f.Tag.Get("json"); tag != "" {
		name := strings.Split(tag, ",")[0]
		if name != "" {
			return name
		}
	}
	if tag := f.Tag.Get("yaml"); tag != "" {
		name := strings.Split(tag, ",")[0]
		if name != "" {
			return name
		}
	}
	return f.Name
}

func sensitiveTag(f reflect.StructField) bool {
	if tag := strings.ToLower(f.Tag.Get("sensitive")); tag == "true" || tag == "1" {
		return true
	}
	if tag := strings.ToLower(f.Tag.Get("audit")); strings.Contains(tag, "sensitive") {
		return true
	}
	return false
}
