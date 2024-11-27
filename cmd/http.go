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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	clihelpers "github.com/northwood-labs/cli-helpers"
	"github.com/northwood-labs/devsec-tools/pkg/httptls"
)

// httpCmd represents the http command
var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "Check supported HTTP versions.",
	Long: clihelpers.LongHelpText(`
	Check supported HTTP versions for a website.
	`),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		result, err := httptls.GetSupportedHTTPVersions(domain)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if fJSON {
			out, err := result.ToJSON()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Fprintln(os.Stdout, out)
			os.Exit(0)
		}

		// pp := debug.GetSpew()
		// pp.Dump(result)

		t := NewTable("HTTP Version", "Supported")
		t.Row("1.1", displayBool(result.HTTP11))
		t.Row("2", displayBool(result.HTTP2))
		t.Row("3", displayBool(result.HTTP3))

		fmt.Println(t.Render())
	},
}

func init() {
	rootCmd.AddCommand(httpCmd)
}
