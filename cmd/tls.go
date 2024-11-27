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
	"fmt"
	"os"

	clihelpers "github.com/northwood-labs/cli-helpers"
	"github.com/northwood-labs/debug"
	"github.com/northwood-labs/devsec-tools/pkg/httptls"
	"github.com/spf13/cobra"
)

// tlsCmd represents the tls command
var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Check supported TLS versions and ciphers.",
	Long: clihelpers.LongHelpText(`
	Check supported TLS versions and ciphers for a website, including potential
	problems with outdated cipher suites that should probably be disabled.
	`),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		host, port, err := httptls.ParseHostPort(domain)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		result, err := httptls.GetSupportedTLSVersions(host, port)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if fJSON {
			out, err := json.Marshal(result)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Fprintln(os.Stdout, string(out))
			os.Exit(0)
		}

		pp := debug.GetSpew()
		pp.Dump(result)

		t := NewTable("TLS Version", "Cipher Suites", "Strength")

		for i := range result.TLSConnections {
			tlsConnection := result.TLSConnections[i]

			for j := range tlsConnection.CipherSuites {
				cipher := tlsConnection.CipherSuites[j]

				if j == 0 && i == 0 {
					t.Row(tlsConnection.Version, cipher.IANAName, cipher.Strength)
				} else if j == 0 {
					t.Row("", "", "")
					t.Row(tlsConnection.Version, cipher.IANAName, cipher.Strength)
				} else {
					t.Row("", cipher.IANAName, cipher.Strength)
				}
			}
		}

		fmt.Println(t.Render())
	},
}

func init() {
	rootCmd.AddCommand(tlsCmd)
}
