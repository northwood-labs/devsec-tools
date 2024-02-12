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

/*
See "hasher" package for the Go library code.
*/
package main

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/northwood-labs/action-docker-image-digest/hasher"
)

const HR = "==========================================================================================================="

func main() {
	sp := spew.ConfigState{
		Indent:   "    ",
		SortKeys: true,
		SpewKeys: true,
	}

	ast, err := hasher.ReadFile("testdata/Dockerfile")
	if err != nil {
		panic(err)
	}

	sp.Dump(ast)
	fmt.Println(HR)
	fmt.Println(ast.AST.Dump())

	// refs, err := hasher.ParseIntoStruct(ast)
	// if err != nil {
	// 	panic(err)
	// }

	// for i := range refs {
	// 	ref := refs[i]
	// 	sp.Dump(ref)
	// 	sp.Dump(ref.OriginalLine())
	// 	sp.Dump(ref.RewriteLine())

	// 	fmt.Println(HR)
	// }

	// // sp.Dump(hasher.RewriteLines(ast, refs))

	// hasher.WriteFile(ast.Lines, "testdata/Dockerfile2")
}
