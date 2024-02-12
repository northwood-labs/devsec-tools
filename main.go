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

	dockerfile, rawParser, stageList, err := hasher.ReadFile("testdata/Dockerfile")
	if err != nil {
		panic(err)
	}

	err = rawParser.ParseDockerfile("testdata/Dockerfile")
	if err != nil {
		panic(err)
	}

	dockerfileLines, err := hasher.ModifyFromLines(dockerfile, rawParser, stageList)
	if err != nil {
		panic(err)
	}

	sp.Dump(dockerfileLines)
	fmt.Println(HR)

	bites, err := hasher.WriteFile(dockerfileLines, "testdata/Dockerfile.rewritten")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Wrote %d bytes to testdata/Dockerfile.rewritten.\n", bites)
}
