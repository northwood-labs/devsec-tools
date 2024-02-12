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

import "strings"

type (
	ImageRef struct {
		ImageTag    string
		ImageDigest string
		CommandAST  Command
		StartLine   int
		EndLine     int
	}

	Command struct {
		Name  string
		Flags []string
		Args  []string
	}
)

// OriginalLine takes the parsed AST from the Dockerfile and re-merges it into a
// single line.
func (r *ImageRef) OriginalLine() string {
	merged := strings.Join([]string{
		r.CommandAST.Name,
		strings.Join(r.CommandAST.Flags, " "),
		strings.Join(r.CommandAST.Args, " "),
	}, " ")

	return strings.ReplaceAll(merged, "  ", " ")
}

// RewriteLine takes the modified AST from the Dockerfile and merges it into an
// updated single line.
func (r *ImageRef) RewriteLine() string {
	if len(r.CommandAST.Args) > 0 {
		if strings.HasPrefix(r.CommandAST.Args[0], "syntax=") {
			r.CommandAST.Args[0] = "syntax=" + r.ImageDigest
		} else {
			r.CommandAST.Args[0] = r.ImageDigest
		}
	}

	merged := strings.Join([]string{
		r.CommandAST.Name,
		strings.Join(r.CommandAST.Flags, " "),
		strings.Join(r.CommandAST.Args, " "),
	}, " ")

	return strings.ReplaceAll(merged, "  ", " ")
}
