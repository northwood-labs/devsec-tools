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
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	wlParser "github.com/cremindes/whalelint/parser"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/pkg/errors"
)

var reSyntax = regexp.MustCompile(`(?i)syntax=(.*)`)

/*
ReadFile reads the contents of the Dockerfile from disk and parses it into an
Abstract Syntax Tree (AST).

----

Arguments:

  - fsPath (string): The path to the Dockerfile on disk.

----

Returns:

  - *parser.Result: The raw parsed object of the Dockerfile.
  - wlParser.RawDockerfileParser: The raw parsed object of the Dockerfile.
  - []instructions.Stage: A list of stages parsed from the Dockerfile.
  - error: An error object if something went wrong.
*/
func ReadFile(fsPath string) (*parser.Result, wlParser.RawDockerfileParser, []instructions.Stage, error) {
	var (
		f           *os.File
		err         error
		emptyResult = &parser.Result{}
	)

	f, err = os.Open(fsPath)
	if err != nil {
		return emptyResult, wlParser.RawDockerfileParser{}, []instructions.Stage{}, errors.Wrap(
			err,
			"failed to open file",
		)
	}

	defer f.Close()

	dockerfile, err := parser.Parse(f)
	if err != nil {
		return dockerfile, wlParser.RawDockerfileParser{}, []instructions.Stage{}, errors.Wrap(
			err,
			"failed to parse Dockerfile",
		)
	}

	stageList, _, err := instructions.Parse(dockerfile.AST)
	if err != nil {
		return dockerfile, wlParser.RawDockerfileParser{}, []instructions.Stage{}, errors.Wrap(
			err,
			"failed to parse Dockerfile instructions",
		)
	}

	err = wlParser.RawParser.ParseDockerfile(fsPath)
	if err != nil {
		return dockerfile, wlParser.RawDockerfileParser{}, []instructions.Stage{}, errors.Wrap(
			err,
			"failed to parse Dockerfile instructions",
		)
	}

	return dockerfile, wlParser.RawParser, stageList, nil
}

/*
ModifyFromLines takes the raw parsed object of the Dockerfile and staging
information, and performs a rewrite of the FROM lines in the Dockerfile to
include the SHA256 digest of the image.

----

Arguments:

  - dockerfile (*parser.Result): The raw parsed object of the Dockerfile.
  - rawParser (wlParser.RawDockerfileParser): The raw parsed object of the Dockerfile.
  - stageList ([]instructions.Stage): A list of stages parsed from the Dockerfile.

----

Returns:

  - []string: The rewritten lines of the Dockerfile.
  - error: An error object if something went wrong.
*/
func ModifyFromLines(
	dockerfile *parser.Result,
	rawParser wlParser.RawDockerfileParser,
	stageList []instructions.Stage,
) ([]string, error) {
	lines := rawParser.ParseRawLineRange(dockerfile.AST.Location())
	syntaxLines := buildKitSyntax(dockerfile)
	offset := 1

	if len(stageList) > 0 {
		if len(stageList[0].Location) > 0 {
			offset = stageList[0].Location[0].Start.Line
		}
	}

	for i := range stageList {
		stage := stageList[i]

		loc := wlParser.RawParser.StringLocation(
			stage.BaseName,
			stage.Location,
		)

		startLine := loc[0]
		startPos := loc[1]
		endLine := loc[2]
		endPos := loc[3]
		idx := startLine - offset
		ln := lines[idx]

		if startLine != endLine {
			return []string{}, errors.New("multi-line FROM statements are not supported")
		}

		digest, err := lookupImageDigest(stage.BaseName)
		if err != nil {
			continue
		}

		modifiedLn := ln[:startPos] + digest + ln[endPos:]
		lines = slices.Replace(lines, idx, idx+1, modifiedLn)
	}

	return append(syntaxLines, lines...), nil
}

/*
WriteFile takes the rewritten lines and writes them back to disk as a new
Dockerfile.

----

Arguments:

  - lines ([]string): The rewritten lines of the Dockerfile.
  - outputPath (string): The path to the new Dockerfile on disk.

----

Returns:

  - int: The number of bytes written to the new Dockerfile.
  - error: An error object if something went wrong.
*/
func WriteFile(lines []string, outputPath string) (int, error) {
	var bites int

	fp, err := os.Create(outputPath)
	if err != nil {
		return bites, err
	}

	for i := range lines {
		line := lines[i]

		bites, err = fmt.Fprintln(fp, line)
		if err != nil {
			return bites, err
		}
	}

	err = fp.Close()
	if err != nil {
		return bites, err
	}

	return bites, nil
}

/*
lookupImageDigest performs the work of looking up the SHA256 digest for the
image name. If the image name results in an error, the error is ignored and the
digest replacement is skipped.
*/
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

/*
buildKitSyntax performs the work of looking up the syntax= line (and any other
comments before the first FROM line) in the Dockerfile. Performs the same SHA256
digest lookup.
*/
func buildKitSyntax(dockerfile *parser.Result) []string {
	var syntaxLines []string

	// Comments above the first FROM line (might be syntax=).
	if len(dockerfile.AST.Children) > 0 {
		firstChild := dockerfile.AST.Children[0]

		for i := range firstChild.PrevComment {
			comment := firstChild.PrevComment[i]
			matches := reSyntax.FindStringSubmatch(comment)

			if len(matches) > 1 {
				digest, err := lookupImageDigest(matches[1])
				if err != nil {
					continue
				}

				syntaxLines = append(syntaxLines, "# syntax="+digest)
			} else {
				syntaxLines = append(syntaxLines, "# "+comment)
			}
		}
	}

	return syntaxLines
}

// crane.WithAuth(&authn.Basic{
// 	Username: "username",
// 	Password: "password",
// }),fromLines
// crane.WithAuth(&authn.Bearer{
// 	Token: "token",
// }),
