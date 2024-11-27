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

package httptls

import (
	"regexp"
	"slices"
	"testing"
)

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestResolveEndpointToIPs(t *testing.T) { // lint:allow_complexity
	for name, tc := range map[string]struct {
		Input       string
		Expected    []string
		ExpectedErr *regexp.Regexp
	}{
		"scheme:cloudflare.com": {
			Input: "https://cloudflare.com",
			Expected: []string{
				"104.16.132.229",
				"104.16.133.229",
				"2606:4700::6810:84e5",
				"2606:4700::6810:85e5",
			},
		},
		"cloudflare.com": {
			Input: "cloudflare.com",
			Expected: []string{
				"104.16.132.229",
				"104.16.133.229",
				"2606:4700::6810:84e5",
				"2606:4700::6810:85e5",
			},
		},
		"scheme:github.com": {
			Input: "https://github.com",
			Expected: []string{
				"140.82.112.3",
				"140.82.112.4",
				"140.82.113.3",
				"140.82.113.4",
				"140.82.114.3",
				"140.82.114.4",
			},
		},
		"github.com": {
			Input: "github.com",
			Expected: []string{
				"140.82.112.3",
				"140.82.112.4",
				"140.82.113.3",
				"140.82.113.4",
				"140.82.114.3",
				"140.82.114.4",
			},
		},
		"scheme:ryanparman.com": {
			Input: "https://ryanparman.com",
			Expected: []string{
				"172.66.40.211",
				"172.66.43.45",
				"2606:4700:3108::ac42:28d3",
				"2606:4700:3108::ac42:2b2d",
			},
		},
		"ryanparman.com": {
			Input: "ryanparman.com",
			Expected: []string{
				"172.66.40.211",
				"172.66.43.45",
				"2606:4700:3108::ac42:28d3",
				"2606:4700:3108::ac42:2b2d",
			},
		},
		"scheme:example.com": {
			Input: "http://example.com",
			Expected: []string{
				"2606:2800:21f:cb07:6820:80da:af6b:8b2c",
				"93.184.215.14",
			},
		},
		"example.com": {
			Input: "example.com",
			Expected: []string{
				"2606:2800:21f:cb07:6820:80da:af6b:8b2c",
				"93.184.215.14",
			},
		},
		"scheme:http.badssl.com": {
			Input: "http://http.badssl.com",
			Expected: []string{
				"104.154.89.105",
			},
		},
		"http.badssl.com": {
			Input: "http.badssl.com",
			Expected: []string{
				"104.154.89.105",
			},
		},
		"scheme:detectportal.firefox.com": {
			Input: "http://detectportal.firefox.com",
			Expected: []string{
				"2600:1901:0:38d7::",
				"34.107.221.82",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual, err := ResolveEndpointToIPs(tc.Input)

			if len(actual) < 1 {
				t.Errorf("Expected at least one IP address for %s, got '%#v'", tc.Input, len(actual))
			}

			if err != nil && tc.ExpectedErr != nil {
				if !tc.ExpectedErr.MatchString(err.Error()) {
					t.Errorf("Expected error '%#v', got '%#v'", tc.ExpectedErr, err)
				}
			}

			for i := range actual {
				a := actual[i]

				if !slices.Contains(tc.Expected, a) {
					t.Errorf("Expected to find %#v inside %#v", a, tc.Expected)
				}
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
// func TestGetSupportedTLSVersions(t *testing.T) { // lint:allow_complexity
// 	for name, tc := range map[string]struct {
// 		Host        string
// 		Port        int
// 		Expected    bool
// 		ExpectedErr *regexp.Regexp
// 	}{
// 		"tls-v1-0.badssl.com:1010": {
// 			Host: "tls-v1-0.badssl.com",
// 			Port: 1010,
// 		},
// 		"tls-v1-1.badssl.com:1011": {
// 			Host: "tls-v1-1.badssl.com",
// 			Port: 1011,
// 		},
// 		"tls-v1-2.badssl.com:1012": {
// 			Host: "tls-v1-2.badssl.com",
// 			Port: 1012,
// 		},
// 		"tlsv13.nwlabs.dev": {
// 			Host: "tlsv13.nwlabs.dev",
// 			Port: 443,
// 		},
// 	} {
// 		t.Run(name, func(t *testing.T) {
// 			tlsVersions, _ := GetSupportedTLSVersions(tc.Host, tc.Port)
// 		})
// 	}
// }
