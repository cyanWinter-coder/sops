package sops

// collectTreeRepresentations records the location of every
// representation-preserving wrapper (Scalar or RawNumber) in the branches.
// It runs before encryption mutates the tree, so the paths still point at
// the plaintext wrappers. Comments are skipped as they are not scalars.
func collectTreeRepresentations(branches TreeBranches) []Representation {
	var reps []Representation
	for _, branch := range branches {
		collectBranchRepresentations(branch, nil, &reps)
	}
	return reps
}

func collectBranchRepresentations(branch TreeBranch, path []interface{}, reps *[]Representation) {
	for _, item := range branch {
		if _, isComment := item.Key.(Comment); isComment {
			continue
		}
		key, _ := item.Key.(string)
		childPath := append(appendInterfacePath(path), key)
		collectValueRepresentations(item.Value, childPath, reps)
	}
}

func collectValueRepresentations(value interface{}, path []interface{}, reps *[]Representation) {
	switch value := value.(type) {
	case Scalar, RawNumber:
		*reps = append(*reps, Representation{
			Path:    append([]interface{}(nil), path...),
			Wrapper: value,
		})
	case TreeBranch:
		collectBranchRepresentations(value, path, reps)
	case []interface{}:
		for i, child := range value {
			if _, isComment := child.(Comment); isComment {
				continue
			}
			collectValueRepresentations(child, append(appendInterfacePath(path), i), reps)
		}
	}
}

func appendInterfacePath(path []interface{}) []interface{} {
	out := make([]interface{}, len(path), len(path)+1)
	copy(out, path)
	return out
}

// DeepCopy produces a structurally independent copy of a tree value so
// that operations which mutate the tree in place (encryption and decryption
// walk every node and replace values) cannot leave the caller's tree in a
// partially processed state when an error occurs halfway through.
//
// It understands every value type the stores can place in a tree:
// TreeBranch, []interface{}, Scalar, Comment, time.Time, []byte and the
// plain scalar types. Unknown values are copied by reference.
func DeepCopy(in interface{}) interface{} {
	switch in := in.(type) {
	case nil:
		return nil
	case TreeBranch:
		out := make(TreeBranch, len(in))
		for i, item := range in {
			out[i] = TreeItem{
				Key:   DeepCopy(item.Key),
				Value: DeepCopy(item.Value),
			}
		}
		return out
	case TreeBranches:
		out := make(TreeBranches, len(in))
		for i, branch := range in {
			out[i] = DeepCopy(branch).(TreeBranch)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(in))
		for i, v := range in {
			out[i] = DeepCopy(v)
		}
		return out
	case Scalar:
		return Scalar{
			Value:   DeepCopy(in.Value),
			Literal: in.Literal,
			Tag:     in.Tag,
			Style:   in.Style,
		}
	case RawNumber:
		return RawNumber{
			Value:   DeepCopy(in.Value),
			Literal: in.Literal,
		}
	case Comment:
		return Comment{Value: in.Value, Inline: in.Inline}
	case []byte:
		out := make([]byte, len(in))
		copy(out, in)
		return out
	default:
		// strings, ints, float64, bools, time.Time and any other value are
		// either immutable or safe to share.
		return in
	}
}
