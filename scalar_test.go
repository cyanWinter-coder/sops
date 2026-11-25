package sops

import (
	"testing"
	"time"
)

func TestUnwrapScalar(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want interface{}
	}{
		{"plain string", "hello", "hello"},
		{"scalar", Scalar{Value: 1, Tag: "!!int"}, 1},
		{"raw number", RawNumber{Value: 1.5, Literal: "1.50"}, 1.5},
		{"nil", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UnwrapScalar(tc.in); got != tc.want {
				t.Fatalf("UnwrapScalar(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDeepCopyIndependence(t *testing.T) {
	original := TreeBranches{TreeBranch{
		TreeItem{Key: "scalar", Value: Scalar{Value: 1, Literal: "1.0", Tag: "!!float"}},
		TreeItem{Key: "number", Value: RawNumber{Value: 2, Literal: "2.0"}},
		TreeItem{Key: "nested", Value: TreeBranch{
			TreeItem{Key: "leaf", Value: []interface{}{"a", "b"}},
		}},
		TreeItem{Key: "stamp", Value: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		TreeItem{Key: "bytes", Value: []byte{1, 2, 3}},
	}}
	copy := DeepCopy(original).(TreeBranches)

	// Mutate the copy at every level.
	copy[0][0].Value = Scalar{Value: 99}
	copy[0][1].Value = RawNumber{Value: 100}
	nested := copy[0][2].Value.(TreeBranch)
	nested[0].Value.([]interface{})[0] = "changed"
	copy[0][4].Value.([]byte)[0] = 9

	// The original must be untouched at every level.
	if got := original[0][0].Value.(Scalar).Value; got != 1 {
		t.Fatalf("scalar leaked into original: %v", got)
	}
	if got := original[0][1].Value.(RawNumber).Value; got != 2 {
		t.Fatalf("raw number leaked into original: %v", got)
	}
	leaf := original[0][2].Value.(TreeBranch)[0].Value.([]interface{})
	if leaf[0] != "a" {
		t.Fatalf("nested slice leaked into original: %v", leaf)
	}
	if original[0][4].Value.([]byte)[0] != 1 {
		t.Fatalf("byte slice leaked into original: %v", original[0][4].Value)
	}
}

func TestCollectTreeRepresentations(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "plain", Value: "string"},
		TreeItem{Key: "float", Value: Scalar{Value: 1, Literal: "1.0", Tag: "!!float"}},
		TreeItem{Key: "list", Value: []interface{}{
			RawNumber{Value: 2, Literal: "2.0"},
			"kept",
		}},
		TreeItem{Key: Comment{Value: " note"}, Value: nil},
	}}
	reps := collectTreeRepresentations(branches)
	if len(reps) != 2 {
		t.Fatalf("expected 2 representations, got %d: %#v", len(reps), reps)
	}
	if got := reps[0].Path[0]; got != "float" {
		t.Fatalf("first representation path = %v, want float", got)
	}
	listPath := reps[1].Path
	if len(listPath) != 2 || listPath[0] != "list" || listPath[1] != 0 {
		t.Fatalf("list representation path = %v, want [list 0]", listPath)
	}
}
