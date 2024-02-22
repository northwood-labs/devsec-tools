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

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var (
	fMarkdown bool
	fManpage  bool

	docsCmd = &cobra.Command{
		Use:    "docs",
		Short:  "Generates Markdown documentation for the CLI.",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			if fMarkdown {
				err := doc.GenMarkdownTree(rootCmd, "./docs/markdown")
				if err != nil {
					logger.Fatal().Err(err).Msg("Failed to generate Markdown documentation.")
				}
			} else if fManpage {
				err := doc.GenManTree(rootCmd, &doc.GenManHeader{Title: "devsec-tools"}, "./docs/man")
				if err != nil {
					logger.Fatal().Err(err).Msg("Failed to generate Manpage documentation.")
				}
			} else {
				err := cmd.Help()
				if err != nil {
					logger.Fatal().Err(err).Msg("Failed to display help.")
				}
			}
		},
	}
)

func init() { // lint:allow_init
	docsCmd.Flags().BoolVarP(
		&fMarkdown, "markdown", "g", false, "Generate Markdown documentation.",
	)
	docsCmd.Flags().BoolVarP(
		&fManpage, "manpage", "m", false, "Generate Manpage documentation.",
	)

	docsCmd.MarkFlagsMutuallyExclusive("markdown", "manpage")
	rootCmd.AddCommand(docsCmd)
}
