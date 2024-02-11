package hasher

import "strings"

type (
	ImageRef struct {
		ImageTag    string
		ImageDigest string
		StartLine   int
		EndLine     int
		CommandAST  Command
	}

	Command struct {
		Name  string
		Flags []string
		Args  []string
	}
)

func (r *ImageRef) OriginalLine() string {
	merged := strings.Join([]string{
		r.CommandAST.Name,
		strings.Join(r.CommandAST.Flags, " "),
		strings.Join(r.CommandAST.Args, " "),
	}, " ")

	return strings.ReplaceAll(merged, "  ", " ")
}

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
