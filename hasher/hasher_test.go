// Copyright 2024, Ryan Parman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hasher

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	// ImageRefTestTable is a table-driven test for the ImageRef.OriginalLine method.
	// <https://github.com/golang/go/wiki/TableDrivenTests>
	ImageRefTestTable = map[string]struct {
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
			Expected: "FROM --platform=$BUILDPLATFORM golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512" +
				"c2681de49026573b7 AS fake-second-base",
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
	ImageRefRewriteTestTable = map[string]struct {
		Expected string
		Digest   string
		Name     string
		Flags    []string
		Args     []string
	}{
		"syntax=docker/dockerfile:1": {
			Name:   "#",
			Args:   []string{"syntax=docker/dockerfile:1"},
			Digest: "docker/dockerfile@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021",
			Expected: "# syntax=docker/dockerfile@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032ed" +
				"f31be0021",
		},
		"golang:1.21-alpine": {
			Name:   "FROM",
			Flags:  []string{"--platform=$BUILDPLATFORM"},
			Args:   []string{"golang:1.21-alpine", "AS", "base-builder"},
			Digest: "golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7",
			Expected: "FROM --platform=$BUILDPLATFORM golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd5" +
				"12c2681de49026573b7 AS base-builder",
		},
		"golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7": {
			Name:  "FROM",
			Flags: []string{"--platform=$BUILDPLATFORM"},
			Args: []string{
				"golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7",
				"AS",
				"fake-second-base",
			},
			Digest: "golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7",
			Expected: "FROM --platform=$BUILDPLATFORM golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512" +
				"c2681de49026573b7 AS fake-second-base",
		},
		"ghcr.io/adrianchifor/harpoon:latest": {
			Name:  "FROM",
			Flags: []string{"--platform=$BUILDPLATFORM"},
			Args:  []string{"ghcr.io/adrianchifor/harpoon:latest", "AS", "fake-third-base"},
			Digest: "ghcr.io/adrianchifor/harpoon@sha256:842dc97a2ce0bd8b1c84ec0de999aab4349c5f5cecb942" +
				"3341abd89b8e6903f1",
			Expected: "FROM --platform=$BUILDPLATFORM ghcr.io/adrianchifor/harpoon@sha256:842dc97a2ce0bd8b1c84ec0d" +
				"e999aab4349c5f5cecb9423341abd89b8e6903f1 AS fake-third-base",
		},
	}
)

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

func BenchmarkImageRefOriginal(b *testing.B) {
	b.ReportAllocs()

	for name, tc := range ImageRefTestTable {
		b.Run(name, func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				actual := ImageRef{
					CommandAST: Command{
						Name:  tc.Name,
						Flags: tc.Flags,
						Args:  tc.Args,
					},
				}
				actual.OriginalLine()
			}
		})
	}
}

func BenchmarkImageRefOriginalParallel(b *testing.B) {
	b.ReportAllocs()

	for name, tc := range ImageRefTestTable {
		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					actual := ImageRef{
						CommandAST: Command{
							Name:  tc.Name,
							Flags: tc.Flags,
							Args:  tc.Args,
						},
					}
					actual.OriginalLine()
				}
			})
		})
	}
}
