package main

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/northwood-labs/action-docker-image-digest/hasher"
)

const HR = "==========================================================================================================="

func main() {
	spec, err := hasher.ReadFile("testdata/Dockerfile")
	if err != nil {
		panic(err)
	}

	spew.Dump(spec)
	fmt.Println(HR)

	refs, err := hasher.ParseIntoStruct(spec)
	if err != nil {
		panic(err)
	}

	for i := range refs {
		ref := refs[i]
		spew.Dump(ref)

		fmt.Println(HR)
	}
}
