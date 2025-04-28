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

	"github.com/charmbracelet/huh/spinner"
	clihelpers "github.com/northwood-labs/cli-helpers"
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

	Recommended cipher suites:
		https://devsec.tools/learning/recommended-cipher-suites/

	Perfect Forward Secrecy (PFS):
		https://devsec.tools/learning/standards/pfs/

	Authenticated Encryption with Associated Data (AEAD):
		https://devsec.tools/learning/standards/aead/

	U.S. NIST SP 800-52 (NIST):
		https://devsec.tools/learning/standards/nist-sp-800-52/

	U.S. NIST FIPS 186 (FIPS):
		https://devsec.tools/learning/standards/nist-fips-186/
	`),
	Args: func(cmd *cobra.Command, args []string) error {
		if !fStdin && len(args) < 1 {
			return errors.New("Please provide a domain to check.\n")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		var domain string

		if fStdin && sStdin != "" {
			domain = sStdin
		} else if len(args) > 0 {
			domain = args[0]
		}

		host, port, err := httptls.ParseHostPort(domain)
		if err != nil {
			logger.Error(err)
			os.Exit(1)
		}

		var result httptls.TLSResult

		err = spinner.New().
			Title(fmt.Sprintf("Testing TLS versions for %s...", domain)).
			Type(spinner.Dots).
			Output(os.Stderr).
			Accessible(fQuiet && !fJSON).
			Action(func(result *httptls.TLSResult) func() {
				return func() {
					res, e := httptls.GetSupportedTLSVersions(host, port, httptls.Options{
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

		if !result.TLSVersions.TLSv10 &&
			!result.TLSVersions.TLSv11 &&
			!result.TLSVersions.TLSv12 &&
			!result.TLSVersions.TLSv13 &&
			!fQuiet {
			logger.Errorf(
				"The hostname `%s` does not support ANY versions of TLS. It is probable that "+
					"the hostname is incorrect, the website is down, or the website does not support TLS.",
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

		t := NewTable("TLS Version", "Cipher Suites", "Strength", "PFS", "AEAD", "NIST", "FIPS")

		for i := range result.TLSConnections {
			tlsConnection := result.TLSConnections[i]

			for j := range tlsConnection.CipherSuites {
				cipher := tlsConnection.CipherSuites[j]

				if tlsConnection.VersionID == httptls.VersionTLS13 {
					cipher.IANAName = "Standard 1.3 cipher suite"
				}

				if j == 0 && i == 0 {
					t.Row(
						tlsConnection.Version,
						cipher.IANAName,
						cipher.Strength,
						displayBool(cipher.IsPFS, fEmoji),
						displayBool(cipher.IsAEAD, fEmoji),
						displayBool(cipher.IsNIST_SP_800_52, fEmoji),
						displayBool(cipher.IsFIPS186, fEmoji),
					)
				} else if j == 0 {
					t.Row("", "", "")
					t.Row(
						tlsConnection.Version,
						cipher.IANAName,
						cipher.Strength,
						displayBool(cipher.IsPFS, fEmoji),
						displayBool(cipher.IsAEAD, fEmoji),
						displayBool(cipher.IsNIST_SP_800_52, fEmoji),
						displayBool(cipher.IsFIPS186, fEmoji),
					)
				} else {
					t.Row(
						"",
						cipher.IANAName,
						cipher.Strength,
						displayBool(cipher.IsPFS, fEmoji),
						displayBool(cipher.IsAEAD, fEmoji),
						displayBool(cipher.IsNIST_SP_800_52, fEmoji),
						displayBool(cipher.IsFIPS186, fEmoji),
					)
				}
			}
		}

		fmt.Println(t.Render())
	},
}

func init() {
	rootCmd.AddCommand(tlsCmd)
}
