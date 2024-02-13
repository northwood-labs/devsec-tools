// Copyright 2024, Ryan Parman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"strings"

	"github.com/lithammer/dedent"
	hasher "github.com/northwood-labs/devsec-tools/pkg/dockerfile-hasher"
	"github.com/spf13/cobra"
)

var (
	fDockerfile string
	fRewrite    bool

	// dockerfileHasherCmd represents the dockerfileHasher command
	dockerfileHasherCmd = &cobra.Command{
		Use:   "dockerfile-hasher",
		Short: "Rewrites a Dockerfile with SHA256 digests of the images.",
		Long: strings.TrimSpace(dedent.Dedent(`
		Since Docker tags can be re-pointed to different images, it is often useful
		to rewrite the Dockerfile with the SHA256 digest of the image.

		This command reads the contents of the Dockerfile from disk and parses it
		into an Abstract Syntax Tree (AST). It then rewrites the lines in the
		Dockerfile with the SHA256 digest of the image.

		This is described (briefly) in the Center for Internet Security (CIS) Docker
		Benchmark, in section §6.1.
		`)),
		Run: func(cmd *cobra.Command, args []string) {
			dockerfile, rawParser, stageList, err := hasher.ReadFile(fDockerfile, logger)
			if err != nil {
				panic(err)
			}

			dockerfileLines, err := hasher.ModifyFromLines(
				dockerfile,
				rawParser,
				stageList,
				logger,
			)
			if err != nil {
				panic(err)
			}

			outputStream := ""
			if fRewrite {
				outputStream = fDockerfile
			}

			bites, err := hasher.WriteFile(dockerfileLines, outputStream, logger)
			if err != nil {
				panic(err)
			}

			logger.Info().Int("bytes", bites).Msgf("Wrote %d bytes.", bites)
		},
	}
)

func init() { // lint:allow_init
	dockerfileHasherCmd.Flags().BoolVarP(
		&fRewrite, "write", "w", false, "Write the changes back to the Dockerfile.",
	)
	dockerfileHasherCmd.Flags().StringVarP(
		&fDockerfile, "dockerfile", "f", "Dockerfile", "Path to the Dockerfile to parse/rewrite.",
	)

	dockerfileHasherCmd.MarkFlagRequired("dockerfile")

	rootCmd.AddCommand(dockerfileHasherCmd)
}
