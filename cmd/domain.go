// Copyright 2024-2025, Northwood Labs
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

	clihelpers "github.com/northwood-labs/cli-helpers"
	"github.com/northwood-labs/devsec-tools/pkg/httptls"
	"github.com/spf13/cobra"
)

var (
	fScheme bool

	// domainCmd represents the domain command
	domainCmd = &cobra.Command{
		Use:   "domain",
		Short: "Trim down a URL to just the domain.",
		Long: clihelpers.LongHelpText(`
		Trim down a URL to just the domain.

		Strips away any path or authentication, leaving only the hostname. If no
		scheme is provided, HTTPS is assumed.
		`),
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("Please provide a domain to check.\n")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := httptls.ParseDomain(args[0], fScheme)
			if err != nil {
				logger.Fatal(err)
			}

			result := httptls.DomainResult{
				Hostname: domain,
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

			t := NewTable("Hostname")
			t.Row(domain)

			fmt.Println(t.Render())
		},
	}
)

func init() {
	domainCmd.Flags().BoolVarP(&fScheme, "scheme", "S", false, "Include the HTTPS scheme in the URL.")

	rootCmd.AddCommand(domainCmd)
}
