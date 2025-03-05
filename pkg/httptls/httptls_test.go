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

package httptls

import (
	"fmt"
	"testing"
)

// <https://github.com/golang/go/wiki/TableDrivenTests>
// func TestResolveEndpointToIPs(t *testing.T) { // lint:allow_complexity
// 	for name, tc := range map[string]struct {
// 		Input       string
// 		Expected    []string
// 		ExpectedErr *regexp.Regexp
// 	}{
// 		"scheme:cloudflare.com": {
// 			Input: "https://cloudflare.com",
// 			Expected: []string{
// 				"104.16.132.229",
// 				"104.16.133.229",
// 				"2606:4700::6810:84e5",
// 				"2606:4700::6810:85e5",
// 			},
// 		},
// 		"cloudflare.com": {
// 			Input: "cloudflare.com",
// 			Expected: []string{
// 				"104.16.132.229",
// 				"104.16.133.229",
// 				"2606:4700::6810:84e5",
// 				"2606:4700::6810:85e5",
// 			},
// 		},
// 		"scheme:github.com": {
// 			Input: "https://github.com",
// 			Expected: []string{
// 				"140.82.112.3",
// 				"140.82.112.4",
// 				"140.82.113.3",
// 				"140.82.113.4",
// 				"140.82.114.3",
// 				"140.82.114.4",
// 			},
// 		},
// 		"github.com": {
// 			Input: "github.com",
// 			Expected: []string{
// 				"140.82.112.3",
// 				"140.82.112.4",
// 				"140.82.113.3",
// 				"140.82.113.4",
// 				"140.82.114.3",
// 				"140.82.114.4",
// 			},
// 		},
// 		"scheme:ryanparman.com": {
// 			Input: "https://ryanparman.com",
// 			Expected: []string{
// 				"172.66.40.211",
// 				"172.66.43.45",
// 				"2606:4700:3108::ac42:28d3",
// 				"2606:4700:3108::ac42:2b2d",
// 			},
// 		},
// 		"ryanparman.com": {
// 			Input: "ryanparman.com",
// 			Expected: []string{
// 				"172.66.40.211",
// 				"172.66.43.45",
// 				"2606:4700:3108::ac42:28d3",
// 				"2606:4700:3108::ac42:2b2d",
// 			},
// 		},
// 		"scheme:example.com": {
// 			Input: "http://example.com",
// 			Expected: []string{
// 				"2606:2800:21f:cb07:6820:80da:af6b:8b2c",
// 				"93.184.215.14",
// 			},
// 		},
// 		"example.com": {
// 			Input: "example.com",
// 			Expected: []string{
// 				"2606:2800:21f:cb07:6820:80da:af6b:8b2c",
// 				"93.184.215.14",
// 			},
// 		},
// 		"scheme:http.badssl.com": {
// 			Input: "http://http.badssl.com",
// 			Expected: []string{
// 				"104.154.89.105",
// 			},
// 		},
// 		"http.badssl.com": {
// 			Input: "http.badssl.com",
// 			Expected: []string{
// 				"104.154.89.105",
// 			},
// 		},
// 		"scheme:detectportal.firefox.com": {
// 			Input: "http://detectportal.firefox.com",
// 			Expected: []string{
// 				"2600:1901:0:38d7::",
// 				"34.107.221.82",
// 			},
// 		},
// 	} {
// 		t.Run(name, func(t *testing.T) {
// 			actual, err := ResolveEndpointToIPs(tc.Input)

// 			if len(actual) < 1 {
// 				t.Errorf("Expected at least one IP address for %s, got '%#v'", tc.Input, len(actual))
// 			}

// 			if err != nil && tc.ExpectedErr != nil {
// 				if !tc.ExpectedErr.MatchString(err.Error()) {
// 					t.Errorf("Expected error '%#v', got '%#v'", tc.ExpectedErr, err)
// 				}
// 			}

// 			for i := range actual {
// 				a := actual[i]

// 				if !slices.Contains(tc.Expected, a) {
// 					t.Errorf("Expected to find %#v inside %#v", a, tc.Expected)
// 				}
// 			}
// 		})
// 	}
// }

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

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestParseDomain(t *testing.T) { // lint:allow_complexity
	for name, tc := range map[string]struct {
		Scheme   bool
		Input    string
		Expected string
	}{
		"example.com[true]": {
			Input:    "example.com",
			Scheme:   true,
			Expected: "https://example.com",
		},
		"https://example.com[true]": {
			Input:    "https://example.com",
			Scheme:   true,
			Expected: "https://example.com",
		},
		"http://example.com[true]": {
			Input:    "http://example.com",
			Scheme:   true,
			Expected: "http://example.com",
		},
		"example.com/path/file.html[true]": {
			Input:    "example.com/path/file.html",
			Scheme:   true,
			Expected: "https://example.com",
		},
		"https://example.com/path/file.html[true]": {
			Input:    "https://example.com/path/file.html",
			Scheme:   true,
			Expected: "https://example.com",
		},
		"example.com[false]": {
			Input:    "example.com",
			Scheme:   false,
			Expected: "example.com",
		},
		"https://example.com[false]": {
			Input:    "https://example.com",
			Scheme:   false,
			Expected: "example.com",
		},
		"http://example.com[false]": {
			Input:    "http://example.com",
			Scheme:   false,
			Expected: "example.com",
		},
		"example.com/path/file.html[false]": {
			Input:    "example.com/path/file.html",
			Scheme:   false,
			Expected: "example.com",
		},
		"https://example.com/path/file.html[false]": {
			Input:    "https://example.com/path/file.html",
			Scheme:   false,
			Expected: "example.com",
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseDomain(tc.Input, tc.Scheme)
			if err != nil {
				t.Errorf("Expected no error, got '%#v'", err)
			}

			if actual != tc.Expected {
				t.Errorf("Expected '%#v', got '%#v'", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestParseHostPort(t *testing.T) { // lint:allow_complexity
	for name, tc := range map[string]struct {
		Input     string
		ExpDomain string
		ExpPort   string
	}{
		"example.com:22": {
			Input:     "example.com:22",
			ExpDomain: "example.com",
			ExpPort:   "22",
		},
		"example.com": {
			Input:     "example.com",
			ExpDomain: "example.com",
			ExpPort:   "443",
		},
		"https://example.com": {
			Input:     "https://example.com",
			ExpDomain: "example.com",
			ExpPort:   "443",
		},
		"http://example.com": {
			Input:     "http://example.com",
			ExpDomain: "example.com",
			ExpPort:   "80",
		},
		"example.com/path/file.html": {
			Input:     "example.com/path/file.html",
			ExpDomain: "example.com",
			ExpPort:   "443",
		},
		"https://example.com/path/file.html": {
			Input:     "https://example.com/path/file.html",
			ExpDomain: "example.com",
			ExpPort:   "443",
		},
	} {
		t.Run(name, func(t *testing.T) {
			actualDomain, actualPort, err := ParseHostPort(tc.Input)
			if err != nil {
				t.Errorf("Expected no error, got '%#v'", err)
			}

			if actualDomain != tc.ExpDomain {
				t.Errorf("Expected '%#v', got '%#v'", tc.ExpDomain, actualDomain)
			}

			if actualPort != tc.ExpPort {
				t.Errorf("Expected '%#v', got '%#v'", tc.ExpPort, actualPort)
			}
		})
	}
}

func ExampleParseDomain() {
	domain, _ := ParseDomain("example.com", true)
	fmt.Println(domain)
	// Output: https://example.com
}

func ExampleParseDomain_scheme() {
	domain, _ := ParseDomain("http://example.com", true)
	fmt.Println(domain)
	// Output: http://example.com
}

func ExampleParseDomain_port() {
	domain, _ := ParseDomain("http://example.com:8080", true)
	fmt.Println(domain)
	// Output: http://example.com:8080
}

func ExampleParseDomain_path() {
	domain, _ := ParseDomain("example.com/abc/123", true)
	fmt.Println(domain)
	// Output: https://example.com
}

func ExampleParseDomain_noScheme() {
	domain, _ := ParseDomain("https://example.com", false)
	fmt.Println(domain)
	// Output: example.com
}

func ExampleParseHostPort_port() {
	domain, port, _ := ParseHostPort("example.com:22")
	fmt.Println(domain, port)
	// Output: example.com 22
}

func ExampleParseHostPort_defacto() {
	domain, port, _ := ParseHostPort("example.com")
	fmt.Println(domain, port)
	// Output: example.com 443
}

func ExampleParseHostPort_http() {
	domain, port, _ := ParseHostPort("http://example.com")
	fmt.Println(domain, port)
	// Output: example.com 80
}
