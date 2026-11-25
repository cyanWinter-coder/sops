package stores

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/getsops/sops/v3"
)

// MetadataFlatten is an enum type
type MetadataFlatten int

const (
	// MetadataFlattenNone keeps the metadata under a single nested `sops`
	// key in the first tree branch.
	MetadataFlattenNone MetadataFlatten = iota
	// MetadataFlattenBelowTop keeps the metadata under a top-level `sops`
	// key in the first tree branch, with its values flattened beneath it.
	MetadataFlattenBelowTop
	// MetadataFlattenFull flattens the metadata fully into the first tree
	// branch, prefixing each key with `SopsPrefix`.
	MetadataFlattenFull
)

type MetadataOpts struct {
	Flatten MetadataFlatten
	// Whether strings need "\n" replaced by "\\n".
	// Only used if Flatten is not MetadataFlattenNone.
	// This does provide a double escape for newlines, since the store itself
	// is already expected to take care of them. This is mainly needed for
	// backwards compatibility with the INI store.
	EscapeNewlines bool
}

// SopsPrefix is the prefix for all metadata entry keys.
const SopsPrefix = SopsMetadataKey + "_"

func sopsToGoMap(mapping sops.TreeBranch) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, item := range mapping {
		if _, ok := item.Key.(sops.Comment); ok {
			continue
		}
		key, ok := item.Key.(string)
		if !ok {
			return nil, fmt.Errorf("Unexpected key type %T", item.Key)
		}
		value, err := sopsToGo(item.Value)
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}

func sopsToGoSlice(slice []interface{}) ([]interface{}, error) {
	result := make([]interface{}, 0, len(slice))
	for _, item := range slice {
		if _, ok := item.(sops.Comment); ok {
			continue
		}
		value, err := sopsToGo(item)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func sopsToGo(value interface{}) (interface{}, error) {
	// Representation-preserving wrappers are transparent to metadata
	// decoding: mapstructure only understands plain Go types, so unwrap the
	// underlying value before handing it off. The wrappers are still kept in
	// the raw metadata tree used for lossless re-emission.
	switch value := value.(type) {
	case sops.Scalar:
		return sopsToGo(value.Value)
	case sops.RawNumber:
		return sopsToGo(value.Value)
	}
	switch value := value.(type) {
	case sops.TreeBranch:
		return sopsToGoMap(value)
	case []interface{}:
		return sopsToGoSlice(value)
	default:
		return value, nil
	}
}

func treeBranchToMetadata(meta sops.TreeBranch) (metadata, error) {
	var md metadata
	m, err := sopsToGoMap(meta)
	if err != nil {
		return md, err
	}
	config := mapstructure.DecoderConfig{
		Result:           &md,
		WeaklyTypedInput: true,
	}
	d, err := mapstructure.NewDecoder(&config)
	if err != nil {
		return md, err
	}
	err = d.Decode(m)
	return md, err
}

// ExtractMetadata extracts SOPS metadata from the supplied tree branches.
func ExtractMetadata(branches sops.TreeBranches, opts MetadataOpts) (sops.TreeBranches, sops.Metadata, error) {
	var metadataTree sops.TreeBranch
	if opts.Flatten != MetadataFlattenFull {
		first := true
		for bi, branch := range branches {
			i := 0
			for i < len(branch) {
				if branch[i].Key == SopsMetadataKey {
					if bi == 0 {
						if !first {
							return nil, sops.Metadata{}, fmt.Errorf("Found duplicate %v entry", SopsMetadataKey)
						}
						first = false
						if tree, ok := branch[i].Value.(sops.TreeBranch); ok {
							metadataTree = tree
						} else {
							return nil, sops.Metadata{}, fmt.Errorf("Found %v entry that is not a mapping", SopsMetadataKey)
						}
					}
					branch = append(branch[:i], branch[i+1:]...)
				} else {
					i++
				}
			}
			branches[bi] = branch
		}
	} else {
		if len(branches) >= 1 {
			branch := branches[0]
			for i := 0; i < len(branch); i++ {
				if key, ok := branch[i].Key.(string); ok {
					if strings.HasPrefix(key, SopsPrefix) {
						entry := branch[i]
						entry.Key = key[len(SopsPrefix):]
						metadataTree = append(metadataTree, entry)
						branch = append(branch[:i], branch[i+1:]...)
						i--
					}
				}
			}
			branches[0] = branch
		}
	}
	if metadataTree == nil {
		return nil, sops.Metadata{}, sops.MetadataNotFound
	}
	if opts.Flatten != MetadataFlattenNone {
		var err error
		if opts.EscapeNewlines {
			for i, item := range metadataTree {
				if value, ok := item.Value.(string); ok {
					metadataTree[i] = sops.TreeItem{
						Key:   item.Key,
						Value: strings.ReplaceAll(value, "\\n", "\n"),
					}
				}
			}
		}
		metadataTree, err = unflattenTreeBranch(metadataTree)
		if err != nil {
			return nil, sops.Metadata{}, err
		}
	}
	// Pull the reserved scalar-representation entry out before the typed
	// metadata decode: mapstructure does not know about it, and keeping it
	// in the tree would only make it round-trip as an unknown field.
	var representationValue interface{}
	metadataTree = removeMetadataEntry(metadataTree, scalarRepresentationsKey, &representationValue)
	md, err := treeBranchToMetadata(metadataTree)
	if err != nil {
		return nil, sops.Metadata{}, err
	}
	metadata, err := md.ToInternal()
	if err != nil {
		return nil, sops.Metadata{}, err
	}
	if representationValue != nil {
		reps, err := representationsFromMetadataBranch(representationValue)
		if err != nil {
			return nil, sops.Metadata{}, err
		}
		metadata.SetRepresentations(reps)
	}
	// Remember the metadata exactly as it appeared in the file (ordered,
	// including unknown fields) so serialization can reproduce it
	// losslessly. A defensive copy keeps later tree edits from mutating
	// the captured metadata.
	if copied, ok := sops.DeepCopy(metadataTree).(sops.TreeBranch); ok {
		metadata.SetRawMetadata(copied)
	}
	return branches, metadata, nil
}

// removeMetadataEntry removes the entry with the given key from the branch,
// storing its value in out. It returns the branch unchanged when the key is
// absent, in which case out is left untouched.
func removeMetadataEntry(branch sops.TreeBranch, key string, out *interface{}) sops.TreeBranch {
	for i, item := range branch {
		if item.Key == key {
			*out = item.Value
			return append(branch[:i], branch[i+1:]...)
		}
	}
	return branch
}

type mapKey struct {
	Name string
	Key  reflect.Value
}

// byName implements sort.Interface for []mapKey
type byName []mapKey

func (mapKeys byName) Len() int {
	return len(mapKeys)
}

func (mapKeys byName) Swap(i, j int) {
	mapKeys[i], mapKeys[j] = mapKeys[j], mapKeys[i]
}

func (mapKeys byName) Less(i, j int) bool {
	return mapKeys[i].Name < mapKeys[j].Name
}

func goToSops(value interface{}) (interface{}, error) {
	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.Pointer:
		if val.IsNil() {
			return nil, nil
		}
		return goToSops(val.Elem().Interface())
	case reflect.Array, reflect.Slice:
		result := make([]interface{}, val.Len())
		for j := 0; j < val.Len(); j++ {
			v, err := goToSops(val.Index(j).Interface())
			if err != nil {
				return nil, err
			}
			result[j] = v
		}
		return result, nil
	case reflect.Map:
		keys := val.MapKeys()
		sortedKeys := make([]mapKey, len(keys))
		for idx, key := range keys {
			sortedKeys[idx] = mapKey{
				Name: key.Interface().(string),
				Key:  key,
			}
		}
		sort.Sort(byName(sortedKeys))
		result := make(sops.TreeBranch, len(sortedKeys))
		for idx, key := range sortedKeys {
			v, err := goToSops(val.MapIndex(key.Key).Interface())
			if err != nil {
				return nil, err
			}
			result[idx] = sops.TreeItem{
				Key:   key.Name,
				Value: v,
			}
		}
		return result, nil
	default:
		return value, nil
	}
}

func metadataToTreeBranch(md metadata) (sops.TreeBranch, error) {
	var mdMap map[string]interface{}
	config := mapstructure.DecoderConfig{
		Result: &mdMap,
	}
	d, err := mapstructure.NewDecoder(&config)
	if err != nil {
		return nil, err
	}
	err = d.Decode(md)
	if err != nil {
		return nil, err
	}
	metadata, err := goToSops(mdMap)
	if err != nil {
		return nil, err
	}
	if tb, ok := metadata.(sops.TreeBranch); ok {
		return tb, nil
	}
	return nil, fmt.Errorf("Internal error: unexpected metadata conversion result %T", metadata)
}

// buildMetadataTreeBranch produces the metadata entries in the order they
// must appear in the emitted document.
//
// When the metadata was read from an existing file, the original tree is
// used as the skeleton: its ordering is preserved, unknown fields are kept
// verbatim, and the typed fields known to SOPS are refreshed in place from
// the internal metadata (so updated MAC, lastmodified or rotated keys are
// not lost). Any known field that was absent in the original tree is
// appended in the canonical order. Metadata created locally has no raw
// tree, so it is serialized exactly as before this mechanism existed.
func buildMetadataTreeBranch(md sops.Metadata) (sops.TreeBranch, error) {
	fresh, err := metadataToTreeBranch(metadataFromInternal(md))
	if err != nil {
		return nil, err
	}
	// Persist scalar representations as a reserved entry so the original
	// spelling survives a cross-process decrypt/re-encrypt round-trip.
	if reps := md.Representations(); len(reps) > 0 {
		entry, err := representationsToMetadataBranch(reps)
		if err != nil {
			return nil, err
		}
		fresh = append(fresh, entry)
	}
	raw := md.RawMetadata()
	if raw == nil {
		return fresh, nil
	}
	return mergeMetadataTrees(raw, fresh), nil
}

// mergeMetadataTrees overlays freshly serialized, known metadata entries on
// top of the raw tree captured from the source file. Unknown entries and the
// original ordering of known ones come from raw; values come from fresh.
func mergeMetadataTrees(raw, fresh sops.TreeBranch) sops.TreeBranch {
	freshByName := make(map[string]sops.TreeItem, len(fresh))
	for _, item := range fresh {
		if key, ok := item.Key.(string); ok {
			freshByName[key] = item
		}
	}
	merged := make(sops.TreeBranch, 0, len(raw)+len(fresh))
	handled := make(map[string]bool, len(fresh))
	for _, item := range raw {
		key, ok := item.Key.(string)
		if !ok {
			// Comments and any non-string entries are preserved as-is.
			merged = append(merged, item)
			continue
		}
		if updated, known := freshByName[key]; known {
			merged = append(merged, updated)
			handled[key] = true
		} else {
			// Unknown field: keep the original entry, value included.
			merged = append(merged, item)
		}
	}
	// Append known fields that did not exist in the raw metadata, in the
	// canonical order produced by metadataToTreeBranch.
	for _, item := range fresh {
		key, ok := item.Key.(string)
		if !ok {
			continue
		}
		if !handled[key] {
			merged = append(merged, item)
		}
	}
	return merged
}

// SerializeMetadata embeds the metadata of `data` into its tree branches.
func SerializeMetadata(data sops.Tree, opts MetadataOpts) (sops.TreeBranches, error) {
	md, err := buildMetadataTreeBranch(data.Metadata)
	if err != nil {
		return nil, fmt.Errorf("Error while serializing metadata: %w", err)
	}
	if opts.Flatten != MetadataFlattenNone {
		var prefix string
		if opts.Flatten == MetadataFlattenFull {
			prefix = SopsPrefix
		}
		md, err = flattenTreeBranch(md, prefix)
		if err != nil {
			return nil, fmt.Errorf("Error while flattening metadata: %w", err)
		}
		if opts.EscapeNewlines {
			for i, item := range md {
				if value, ok := item.Value.(string); ok {
					md[i] = sops.TreeItem{
						Key:   item.Key,
						Value: strings.ReplaceAll(value, "\n", "\\n"),
					}
				}
			}
		}
	}
	if opts.Flatten != MetadataFlattenFull {
		md = sops.TreeBranch{
			sops.TreeItem{
				Key:   SopsMetadataKey,
				Value: md,
			},
		}
	}
	var result sops.TreeBranches
	for _, branch := range data.Branches {
		newBranch := make(sops.TreeBranch, 0, len(branch)+len(md))
		for _, item := range branch {
			if key, ok := item.Key.(string); ok {
				if opts.Flatten == MetadataFlattenFull {
					if strings.HasPrefix(key, SopsPrefix) {
						return nil, fmt.Errorf("Found key %q in encrypted data, which starts with the reserved key prefix %q for SOPS metadata", key, SopsPrefix)
					}
				} else {
					if key == SopsMetadataKey {
						return nil, fmt.Errorf("Found key %q in encrypted data, which is a reserved key used for SOPS metadata", key)
					}
				}
			}
			newBranch = append(newBranch, item)
		}
		for _, item := range md {
			newBranch = append(newBranch, item)
		}
		result = append(result, newBranch)
	}
	return result, nil
}
