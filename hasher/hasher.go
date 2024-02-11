package hasher

import (
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/slimtoolkit/slim/pkg/docker/dockerfile/parser"
	"github.com/slimtoolkit/slim/pkg/docker/dockerfile/spec"
)

var reSyntax = regexp.MustCompile(`(?i)#\s*syntax=(.*)`)

// ReadFile reads the contents of the Dockerfile from disk and parses it into an
// Abstract Syntax Tree (AST).
func ReadFile(fsPath string) (*spec.Dockerfile, error) {
	spec, err := parser.FromFile(fsPath)
	if err != nil {
		return spec, errors.Wrap(err, "failed to parse Dockerfile")
	}

	return spec, nil
}

// ParseIntoStruct parses the Abstract Syntax Tree (AST) into a struct with just
// the information we care about.
func ParseIntoStruct(spec *spec.Dockerfile, authenticator ...authn.Authenticator) ([]ImageRef, error) {
	allLines := make([]ImageRef, 0)

	syntaxLines, err := parseSyntaxLines(spec, authenticator...)
	if err != nil {
		return allLines, errors.Wrap(err, "failed to parse syntax lines")
	}

	fromLines, err := parseFromLines(spec, authenticator...)
	if err != nil {
		return allLines, errors.Wrap(err, "failed to parse FROM lines")
	}

	allLines = append(allLines, syntaxLines...)
	allLines = append(allLines, fromLines...)

	return allLines, nil
}

// RewriteLines uses the information from the Abstract Syntax Tree (AST) and the
// SHA256 digest to rewrite the lines in the Dockerfile.
func RewriteLines() {}

// WriteFile
func WriteFile() {}

func parseSyntaxLines(spec *spec.Dockerfile, authenticator ...authn.Authenticator) ([]ImageRef, error) {
	syntaxLines := []ImageRef{}

	for l := range spec.Lines {
		line := spec.Lines[l]
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

	return syntaxLines, nil
}

func parseFromLines(spec *spec.Dockerfile, authenticator ...authn.Authenticator) ([]ImageRef, error) {
	fromLines := []ImageRef{}

	for i := range spec.Stages {
		stage := spec.Stages[i]
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

	return fromLines, nil
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
