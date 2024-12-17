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
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/charmbracelet/huh/spinner"
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

	If a hostname does not support ANY version of HTTP, please check the
	hostname and try again. Network timeouts are treated as "NO".
	`),
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("Please provide a domain to check.\n")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		domain, err := httptls.ParseDomain(args[0])
		if err != nil {
			logger.Fatal(err)
		}

		var result httptls.HTTPResult

		err = spinner.New().
			Title(fmt.Sprintf("Testing HTTP versions for %s...", domain)).
			Type(spinner.Dots).
			Accessible(fQuiet && !fJSON).
			Action(func(result *httptls.HTTPResult) func() {
				return func() {
					res, e := httptls.GetSupportedHTTPVersions(domain, httptls.Options{
						Logger:         logger,
						TimeoutSeconds: fTimeout,
					})
					if e != nil {
						logger.Error(e)
						os.Exit(1)
					}

					*result = res
				}
			}(&result)).
			Run()
		if err != nil {
			logger.Fatal(err)
		}

		// No results AND ALSO not in quiet mode
		if !result.HTTP11 && !result.HTTP2 && !result.HTTP3 && !fQuiet {
			logger.Errorf(
				"The hostname `%s` does not support ANY versions of HTTP. It is probable that "+
					"the hostname is incorrect.",
				domain,
			)
		}

		if fJSON {
			out, err := json.Marshal(result)
			if err != nil {
				logger.Error(err)
				os.Exit(1)
			}

			fmt.Fprintln(os.Stdout, string(out))
			os.Exit(0)
		}

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
