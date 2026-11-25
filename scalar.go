package sops

// Scalar is a leaf value that carries the representation information a store
// needs to emit the value back in exactly the same form it was read in.
//
// SOPS normally represents leaves with plain Go types (string, int, float64,
// bool, time.Time, []byte). Those types cannot carry the original scalar
// tag, literal spelling or quoting style, which is why a round-trip through
// SOPS used to normalize values such as `1.0` into `1`, `0x1F` into `31` or
// a YAML `!!binary` node into a plain string.
//
// Scalar keeps the decoded Value (so encryption, the MAC and all existing
// tree operations keep working on the underlying Go type) alongside the
// original representation. A Scalar is therefore transparent to every
// operation that only cares about the value, and authoritative for the
// stores that know how to re-emit the original representation.
type Scalar struct {
	// Value is the value decoded with the store's usual rules. It is one of
	// string, int, float64, bool, time.Time or []byte. During an encryption
	// walk it holds the resulting ciphertext; after a decryption walk it
	// holds the restored plaintext value.
	Value interface{}
	// Literal is the value spelled exactly as it appeared in the source
	// document, before any decoding. Stores use it to emit the value
	// byte-for-byte when Style/Tag do not already fully determine it.
	Literal string
	// Tag is the resolved resolution tag of the scalar, e.g. "!!int",
	// "!!float", "!!str", "!!bool", "!!null", "!!timestamp" or "!!binary".
	// Empty means the store should fall back to encoding Value.
	Tag string
	// Style carries store-specific quoting/style information. For YAML it
	// holds the yaml.Style bitmask; for JSON it is currently unused.
	Style int
}

// Unwrap returns the underlying decoded value. It lets helpers that only
// understand plain Go types treat a Scalar as the value it wraps.
func (s Scalar) Unwrap() interface{} {
	return s.Value
}

// unwrapScalar returns the underlying value of a Scalar and leaves any
// other value untouched.
func unwrapScalar(in interface{}) interface{} {
	if scalar, ok := in.(Scalar); ok {
		return scalar.Value
	}
	return in
}

// UnwrapScalar returns the value wrapped by a Scalar or RawNumber, leaving
// any other value untouched. It lets stores and metadata handling treat
// representation-preserving wrappers transparently when only the plain Go
// value matters.
func UnwrapScalar(in interface{}) interface{} {
	switch value := in.(type) {
	case Scalar:
		return value.Value
	case RawNumber:
		return value.Value
	default:
		return in
	}
}

// RawNumber is a JSON number that keeps the exact textual representation
// from the source document alongside a decoded Go value (int or float64).
//
// JSON allows one numeric value to be spelled several ways (`1`, `1.0`,
// `1e3`, `1.000`). Once decoded into a Go int or float64 the original
// spelling is gone, so re-emitting normalized `1.0` into `1` and produced
// noisy diffs. RawNumber carries the original literal for lossless
// emission while remaining transparent to encryption and the MAC, which
// operate on its decoded Value.
type RawNumber struct {
	// Value is the decoded number: an int when the literal is an integer
	// in range, otherwise a float64.
	Value interface{}
	// Literal is the number exactly as written in the JSON document.
	Literal string
}

// Unwrap returns the decoded numeric value.
func (n RawNumber) Unwrap() interface{} {
	return n.Value
}

// unwrapNumber returns the underlying value of a RawNumber and leaves any
// other value untouched.
func unwrapNumber(in interface{}) interface{} {
	if number, ok := in.(RawNumber); ok {
		return number.Value
	}
	return in
}
