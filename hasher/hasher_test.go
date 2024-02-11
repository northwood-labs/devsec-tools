package hasher

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// ImageRefTestTable is a table-driven test for the ImageRef.OriginalLine method.
// <https://github.com/golang/go/wiki/TableDrivenTests>
var ImageRefTestTable = map[string]struct {
	Expected string
	Name     string
	Flags    []string
	Args     []string
}{
	"syntax=docker/dockerfile:1": {
		Name:     "#",
		Args:     []string{"syntax=docker/dockerfile:1"},
		Expected: "# syntax=docker/dockerfile:1",
	},
	"golang:1.21-alpine": {
		Name:     "FROM",
		Flags:    []string{"--platform=$BUILDPLATFORM"},
		Args:     []string{"golang:1.21-alpine", "AS", "base-builder"},
		Expected: "FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS base-builder",
	},
	"golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7": {
		Name:  "FROM",
		Flags: []string{"--platform=$BUILDPLATFORM"},
		Args: []string{
			"golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7",
			"AS",
			"fake-second-base",
		},
		Expected: "FROM --platform=$BUILDPLATFORM golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7 AS fake-second-base",
	},
	"ghcr.io/adrianchifor/harpoon:latest": {
		Name:     "FROM",
		Flags:    []string{"--platform=$BUILDPLATFORM"},
		Args:     []string{"ghcr.io/adrianchifor/harpoon:latest", "AS", "fake-third-base"},
		Expected: "FROM --platform=$BUILDPLATFORM ghcr.io/adrianchifor/harpoon:latest AS fake-third-base",
	},
}

// ImageRefRewriteTestTable is a table-driven test for the ImageRef.RewriteLine method.
// <https://github.com/golang/go/wiki/TableDrivenTests>
var ImageRefRewriteTestTable = map[string]struct {
	Expected string
	Digest   string
	Name     string
	Flags    []string
	Args     []string
}{
	"syntax=docker/dockerfile:1": {
		Name:     "#",
		Args:     []string{"syntax=docker/dockerfile:1"},
		Digest:   "docker/dockerfile@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021",
		Expected: "# syntax=docker/dockerfile@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021",
	},
	"golang:1.21-alpine": {
		Name:     "FROM",
		Flags:    []string{"--platform=$BUILDPLATFORM"},
		Args:     []string{"golang:1.21-alpine", "AS", "base-builder"},
		Digest:   "golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7",
		Expected: "FROM --platform=$BUILDPLATFORM golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7 AS base-builder",
	},
	"golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7": {
		Name:  "FROM",
		Flags: []string{"--platform=$BUILDPLATFORM"},
		Args: []string{
			"golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7",
			"AS",
			"fake-second-base",
		},
		Digest:   "golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7",
		Expected: "FROM --platform=$BUILDPLATFORM golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7 AS fake-second-base",
	},
	"ghcr.io/adrianchifor/harpoon:latest": {
		Name:     "FROM",
		Flags:    []string{"--platform=$BUILDPLATFORM"},
		Args:     []string{"ghcr.io/adrianchifor/harpoon:latest", "AS", "fake-third-base"},
		Digest:   "ghcr.io/adrianchifor/harpoon@sha256:842dc97a2ce0bd8b1c84ec0de999aab4349c5f5cecb9423341abd89b8e6903f1",
		Expected: "FROM --platform=$BUILDPLATFORM ghcr.io/adrianchifor/harpoon@sha256:842dc97a2ce0bd8b1c84ec0de999aab4349c5f5cecb9423341abd89b8e6903f1 AS fake-third-base",
	},
}

func TestImageRefOriginal(t *testing.T) {
	for name, tc := range ImageRefTestTable {
		t.Run(name, func(t *testing.T) {
			actual := ImageRef{
				CommandAST: Command{
					Name:  tc.Name,
					Flags: tc.Flags,
					Args:  tc.Args,
				},
			}

			if actual.OriginalLine() != tc.Expected {
				diff := cmp.Diff(tc.Expected, actual.OriginalLine())
				if diff != "" {
					t.Errorf(diff)
				}
			}
		})
	}
}

func TestImageRefRewrite(t *testing.T) {
	for name, tc := range ImageRefRewriteTestTable {
		t.Run(name, func(t *testing.T) {
			actual := ImageRef{
				ImageDigest: tc.Digest,
				CommandAST: Command{
					Name:  tc.Name,
					Flags: tc.Flags,
					Args:  tc.Args,
				},
			}

			if actual.RewriteLine() != tc.Expected {
				diff := cmp.Diff(tc.Expected, actual.OriginalLine())
				if diff != "" {
					t.Errorf(diff)
				}
			}
		})
	}
}
