package stores

import (
	"fmt"

	"github.com/getsops/sops/v3"
)

// scalarRepresentationsKey is the reserved metadata key under which the
// original spelling of non-canonical scalars is persisted so a
// decrypt/re-encrypt round-trip can reproduce them. It is kept inside the
// `sops` metadata block and is treated as an unknown field by any SOPS
// version that does not implement representation preservation.
const scalarRepresentationsKey = "scalar_representations"

// representationToTreeItem serializes one captured representation into a
// plain tree item made only of strings, ints and nested structures, so it
// can be emitted by every supported store format.
func representationToTreeItem(rep sops.Representation) (sops.TreeItem, error) {
	pathBranch := make([]interface{}, 0, len(rep.Path))
	for _, component := range rep.Path {
		switch component := component.(type) {
		case string:
			pathBranch = append(pathBranch, component)
		case int:
			pathBranch = append(pathBranch, component)
		default:
			return sops.TreeItem{}, fmt.Errorf("unsupported path component type %T in scalar representation", component)
		}
	}
	var entry sops.TreeBranch
	switch wrapper := rep.Wrapper.(type) {
	case sops.Scalar:
		entry = sops.TreeBranch{
			sops.TreeItem{Key: "tag", Value: wrapper.Tag},
			sops.TreeItem{Key: "literal", Value: wrapper.Literal},
			sops.TreeItem{Key: "style", Value: wrapper.Style},
			sops.TreeItem{Key: "wrapper", Value: "scalar"},
		}
	case sops.RawNumber:
		entry = sops.TreeBranch{
			sops.TreeItem{Key: "literal", Value: wrapper.Literal},
			sops.TreeItem{Key: "wrapper", Value: "raw_number"},
		}
	default:
		return sops.TreeItem{}, fmt.Errorf("unsupported representation wrapper type %T", rep.Wrapper)
	}
	entry = append(entry, sops.TreeItem{Key: "path", Value: pathBranch})
	return sops.TreeItem{Key: scalarRepresentationsKey, Value: entry}, nil
}

// representationsToMetadataBranch renders all captured representations as
// a single metadata entry whose value is a list of per-scalar records.
func representationsToMetadataBranch(reps []sops.Representation) (sops.TreeItem, error) {
	list := make([]interface{}, 0, len(reps))
	for _, rep := range reps {
		item, err := representationToTreeItem(rep)
		if err != nil {
			return sops.TreeItem{}, err
		}
		list = append(list, item.Value)
	}
	return sops.TreeItem{Key: scalarRepresentationsKey, Value: list}, nil
}

// representationsFromMetadataBranch reads the persisted representations
// back from the metadata tree and rebuilds the wrapper values. The
// decrypted plaintext value is filled in later by RestoreRepresentations,
// so only representation metadata is reconstructed here.
func representationsFromMetadataBranch(value interface{}) ([]sops.Representation, error) {
	list, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s metadata entry must be a list, got %T", scalarRepresentationsKey, value)
	}
	reps := make([]sops.Representation, 0, len(list))
	for _, raw := range list {
		entry, ok := raw.(sops.TreeBranch)
		if !ok {
			return nil, fmt.Errorf("%s entries must be mappings, got %T", scalarRepresentationsKey, raw)
		}
		fields := map[string]interface{}{}
		for _, item := range entry {
			if key, isString := item.Key.(string); isString {
				fields[key] = sops.UnwrapScalar(item.Value)
			}
		}
		pathValue, ok := fields["path"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("%s entry is missing a path", scalarRepresentationsKey)
		}
		path := make([]interface{}, 0, len(pathValue))
		for _, component := range pathValue {
			// Path components may be wrapped scalars too (quoted keys).
			path = append(path, sops.UnwrapScalar(component))
		}
		literal, _ := fields["literal"].(string)
		wrapperKind, _ := fields["wrapper"].(string)
		style, _ := fields["style"].(int)
		var wrapper interface{}
		switch wrapperKind {
		case "scalar":
			tag, _ := fields["tag"].(string)
			wrapper = sops.Scalar{Literal: literal, Tag: tag, Style: style}
		case "raw_number":
			wrapper = sops.RawNumber{Literal: literal}
		default:
			return nil, fmt.Errorf("unknown representation wrapper kind %q", wrapperKind)
		}
		reps = append(reps, sops.Representation{Path: path, Wrapper: wrapper})
	}
	return reps, nil
}
