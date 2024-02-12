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
Package hasher is a package that provides the ability to read a Dockerfile from
disk, parse it into an Abstract Syntax Tree (AST), and then rewrite the lines in
the Dockerfile with the SHA256 digest of the image.
*/
package hasher

import (
	"os"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/pkg/errors"
	"github.com/slimtoolkit/slim/pkg/docker/dockerfile/reverse"
	"github.com/slimtoolkit/slim/pkg/docker/dockerfile/spec"
)

var reSyntax = regexp.MustCompile(`(?i)#\s*syntax=(.*)`)

// ReadFile reads the contents of the Dockerfile from disk and parses it into an
// Abstract Syntax Tree (AST).
func ReadFile(fsPath string) (*parser.Result, error) {
	var (
		f           *os.File
		err         error
		emptyResult = &parser.Result{}
	)

	f, err = os.Open(fsPath)
	if err != nil {
		return emptyResult, errors.Wrap(err, "failed to parse Dockerfile")
	}

	defer f.Close()

	result, err := parser.Parse(f)
	if err != nil {
		return result, errors.Wrap(err, "failed to parse Dockerfile")
	}

	return result, nil
}

// ParseIntoStruct parses the Abstract Syntax Tree (AST) into a struct with just
// the information we care about.
func ParseIntoStruct(ast *spec.Dockerfile, authenticator ...authn.Authenticator) ([]ImageRef, error) {
	allLines := []ImageRef{}

	allLines = append(allLines, parseSyntaxLines(ast, authenticator...)...)
	allLines = append(allLines, parseFromLines(ast, authenticator...)...)

	return allLines, nil
}

// RewriteLines uses the information from the Abstract Syntax Tree (AST) and the
// SHA256 digest to rewrite the lines in the Dockerfile.
func RewriteLines(ast *spec.Dockerfile, parsedStructs []ImageRef) []string {
	return []string{}
}

// WriteFile takes the rewritten lines and writes them back to disk as a new
// Dockerfile.
func WriteFile(lines []string, outputPath string) error {
	err := reverse.SaveDockerfileData(outputPath, lines)
	if err != nil {
		return errors.Wrap(err, "failed to write Dockerfile")
	}

	return nil
}

func parseSyntaxLines(ast *spec.Dockerfile, authenticator ...authn.Authenticator) []ImageRef {
	syntaxLines := []ImageRef{}

	for l := range ast.Lines {
		line := ast.Lines[l]
		matches := reSyntax.FindStringSubmatch(line)

		if len(matches) > 1 {
			syntaxLine := ImageRef{
				StartLine: l + 1,
				EndLine:   l + 1,
				ImageTag:  matches[1],
			}

			// Fake it for the syntax line
			astCmd := Command{
				Name: "#",
				Args: []string{matches[1]},
			}

			digest, err := lookupImageDigest(matches[1], authenticator...)
			if err != nil {
				continue
			}

			syntaxLine.ImageDigest = digest
			syntaxLine.CommandAST = astCmd
			syntaxLines = append(syntaxLines, syntaxLine)
		}
	}

	return syntaxLines
}

func parseFromLines(ast *spec.Dockerfile, authenticator ...authn.Authenticator) []ImageRef {
	fromLines := []ImageRef{}

	for i := range ast.Stages {
		stage := ast.Stages[i]
		instructions := stage.AllInstructions

		for j := range instructions {
			instruction := instructions[j]

			if strings.EqualFold(instruction.Name, "FROM") {
				fromLine := ImageRef{
					StartLine: instruction.StartLine,
					EndLine:   instruction.EndLine,
				}

				astCmd := Command{
					Name:  strings.ToUpper(instruction.Name),
					Flags: instruction.Flags,
					Args:  instruction.Args,
				}

				if len(instruction.Args) > 0 {
					fromLine.ImageTag = instruction.Args[0]
				}

				digest, err := lookupImageDigest(fromLine.ImageTag, authenticator...)
				if err != nil {
					continue
				}

				fromLine.ImageDigest = digest
				fromLine.CommandAST = astCmd
				fromLines = append(fromLines, fromLine)
			}
		}
	}

	return fromLines
}

func lookupImageDigest(imageName string, authenticator ...authn.Authenticator) (string, error) {
	if strings.Contains(imageName, "@sha256:") {
		return imageName, nil
	}

	auth := authn.Anonymous
	if len(authenticator) > 0 {
		auth = authenticator[0]
	}

	digest, err := crane.Digest(imageName, crane.WithAuth(auth))
	if err != nil {
		return imageName, errors.Wrapf(err, "failed to get image digest for %s", imageName)
	}

	ref, err := name.ParseReference(imageName, name.WithDefaultRegistry(""))
	if err != nil {
		return imageName, errors.Wrapf(err, "failed to parse the image reference for %s", imageName)
	}

	return ref.Context().Digest(digest).String(), nil
}

// crane.WithAuth(&authn.Basic{
// 	Username: "username",
// 	Password: "password",
// }),fromLines
// crane.WithAuth(&authn.Bearer{
// 	Token: "token",
// }),
