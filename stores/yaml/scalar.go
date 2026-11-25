package yaml

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/getsops/sops/v3"
	"go.yaml.in/yaml/v3"
)

// needsScalarWrapper reports whether a scalar node's default Go decoding
// would lose information on re-emission. Only such nodes are wrapped in a
// sops.Scalar; plain strings, canonical integers, plain booleans and
// default-styled nulls stay bare Go values so existing consumers and the
// documented tree shape remain unchanged.
func needsScalarWrapper(node *yaml.Node, tag string) bool {
	switch tag {
	case "!!binary", "!!timestamp":
		// Binary data and timestamps have no faithful default Go
		// representation in the tree (a string would lose the tag).
		return true
	case "!!bool":
		// Plain booleans round-trip losslessly; only quoted or
		// explicitly tagged ones need their style preserved.
		return node.Style != 0
	case "!!float":
		// Any non-canonical spelling (1.0, 1e3, .inf, .nan, ...) would be
		// re-emitted differently after decoding into float64.
		f, err := strconv.ParseFloat(node.Value, 64)
		if err != nil {
			return true
		}
		return strconv.FormatFloat(f, 'f', -1, 64) != node.Value
	case "!!int":
		// Hex, octal, binary, underscored or otherwise non-decimal integers
		// decode into an int and lose their spelling.
		_, err := strconv.ParseInt(node.Value, 10, 64)
		return err != nil
	case "!!null":
		// ~ vs null vs empty and quoted "null" all need their style kept.
		return node.Style != 0 || node.Value != "null"
	case "!!str":
		// Quoted strings keep their quoting style; plain strings (style 0)
		// do not need a wrapper.
		return node.Style != 0
	default:
		// Any custom/unknown tag is preserved verbatim.
		return true
	}
}

// decodeScalar decodes a YAML scalar node into the plain Go value SOPS
// traditionally uses in its tree: nil, bool, int, float64, time.Time,
// []byte or string.
func decodeScalar(node *yaml.Node, tag string) (interface{}, error) {
	switch tag {
	case "!!null":
		return nil, nil
	case "!!bool":
		var v bool
		err := node.Decode(&v)
		return v, err
	case "!!int":
		var v int
		err := node.Decode(&v)
		return v, err
	case "!!float":
		var v float64
		err := node.Decode(&v)
		return v, err
	case "!!timestamp":
		var v time.Time
		err := node.Decode(&v)
		return v, err
	case "!!binary":
		// node.Value holds the raw base64 text (block scalars include a
		// trailing newline, which StdEncoding tolerates). Decoding straight
		// into []byte is not reliably supported by the yaml library, so do
		// the base64 decoding explicitly and keep the raw bytes rather
		// than silently turning possibly non-UTF-8 data into a string.
		decoded, err := base64.StdEncoding.DecodeString(node.Value)
		if err != nil {
			return nil, fmt.Errorf("error decoding !!binary scalar: %w", err)
		}
		return decoded, nil
	default:
		var v string
		err := node.Decode(&v)
		return v, err
	}
}

// decodeYamlScalar converts a scalar node into a tree value. Values whose
// default Go representation round-trips losslessly are returned bare.
// Anything that would lose its tag, spelling or quoting style is returned
// as a sops.Scalar carrying the original representation.
func decodeYamlScalar(node *yaml.Node) (interface{}, error) {
	tag := node.ShortTag()
	value, err := decodeScalar(node, tag)
	if err != nil {
		return nil, err
	}
	if !needsScalarWrapper(node, tag) {
		return value, nil
	}
	return sops.Scalar{
		Value:   value,
		Literal: node.Value,
		Tag:     tag,
		Style:   int(node.Style),
	}, nil
}

// scalarNode renders a sops.Scalar back into a yaml.Node using the retained
// tag, literal and style.
//
// Encryption replaces the wrapped value with an ENC[...] string while
// keeping the Scalar shell. Such a value must be emitted as an ordinary
// encrypted string (no original tag/quoting), otherwise the YAML would
// still carry e.g. !!float around a ciphertext and would not be recognized
// as encrypted on the next load. The ENC prefix is sops' established marker
// for an encrypted scalar.
func scalarNode(scalar sops.Scalar) *yaml.Node {
	if text, ok := scalar.Value.(string); ok && isEncryptedScalar(text) {
		node := &yaml.Node{}
		node.Encode(text)
		return node
	}
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   scalar.Tag,
		Value: scalar.Literal,
		Style: yaml.Style(scalar.Style),
	}
}

// rewrapScalar is the rewrapper the YAML store attaches to a Tree. After a
// decryption pass the Scalar shell carries the decrypted plaintext Go
// value; the retained tag/literal/style are still valid, so the existing
// shell simply needs to be returned for the representation to survive.
func rewrapScalar(in interface{}) interface{} {
	if scalar, ok := in.(sops.Scalar); ok {
		return scalar
	}
	return nil
}

// encryptedScalarPrefix matches the prefix of the encrypted-value format
// produced by the AES cipher (see aes.Cipher).
const encryptedScalarPrefix = "ENC["

func isEncryptedScalar(text string) bool {
	return strings.HasPrefix(text, encryptedScalarPrefix)
}
