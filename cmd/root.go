// Copyright 2024, Northwood Labs
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
	"context"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	clihelpers "github.com/northwood-labs/cli-helpers"
)

var (
	ctx    = context.Background()
	logger *log.Logger

	fJSON    bool
	fQuiet   bool
	fVerbose int
	fTimeout int

	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		TraverseChildren:  true,
		DisableAutoGenTag: true,
		Use:               "devsec-tools",
		Short:             "A set of useful tools for DevSecOps workflows.",
		Long: clihelpers.LongHelpText(`
		DevSec Tools is a suite of tools that are useful for DevSecOps workflows.
		Its goal is to simplify and streamline the process of developing,
		securing, and operating software and systems for the web.

		You can also find these tools online at https://devsec.tools.
		`),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logger = GetLogger(fVerbose, fJSON)
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Are we running in a Lambda environment?
			if os.Getenv("_LAMBDA_SERVER_PORT") != "" {
				lambda.Start(HandleRequest)
			} else {
				_ = cmd.Help()
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(
		&fJSON, "json", "j", false, "Output as JSON.",
	)
	rootCmd.PersistentFlags().BoolVarP(
		&fQuiet, "quiet", "q", false, "Disable all logging output.",
	)
	rootCmd.PersistentFlags().CountVarP(
		&fVerbose, "verbose", "v", "Enable verbose output.",
	)
	rootCmd.PersistentFlags().IntVarP(
		&fTimeout, "timeout", "t", 3, "Timeout in seconds.",
	)

	rootCmd.MarkFlagsMutuallyExclusive("verbose", "quiet")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
