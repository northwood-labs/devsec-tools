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
	"time"
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
		"scheme:captive.apple.com": {
			Input: "http://captive.apple.com",
			Expected: []string{
				"17.253.23.201",
				"17.253.23.202",
				"17.253.23.203",
				"17.253.23.204",
				"17.253.23.205",
				"17.253.23.206",
				"2620:149:a1e:f000::1",
				"2620:149:a1e:f000::3",
				"2620:149:a1e:f000::5",
				"2620:149:a1e:f100::2",
				"2620:149:a1e:f100::4",
				"2620:149:a1e:f100::6",
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
func TestTCPConnect(t *testing.T) { // lint:allow_complexity
	for name, tc := range map[string]struct {
		IP          string
		Port        int
		Expected    bool
		ExpectedErr *regexp.Regexp
	}{
		// ryanparman.com
		"172.66.40.211:443": {
			IP:       "172.66.40.211",
			Port:     443,
			Expected: true,
		},
		// ryanparman.com
		"172.66.43.45:443": {
			IP:       "172.66.43.45",
			Port:     443,
			Expected: true,
		},
		// ryanparman.com
		"2606:4700:3108::ac42:28d3:443": {
			IP:       "2606:4700:3108::ac42:28d3",
			Port:     443,
			Expected: true,
		},
		// ryanparman.com
		"2606:4700:3108::ac42:2b2d:443": {
			IP:       "2606:4700:3108::ac42:2b2d",
			Port:     443,
			Expected: true,
		},
		// example.com
		"2606:2800:21f:cb07:6820:80da:af6b:8b2c:443": {
			IP:       "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
			Port:     443,
			Expected: true,
		},
		// example.com
		"93.184.215.14:443": {
			IP:       "93.184.215.14",
			Port:     443,
			Expected: true,
		},
		// example.com
		"2606:2800:21f:cb07:6820:80da:af6b:8b2c:80": { // Flaky
			IP:       "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
			Port:     80,
			Expected: true,
		},
		// example.com
		"93.184.215.14:80": { // Flaky
			IP:       "93.184.215.14",
			Port:     80,
			Expected: true,
		},
		// http.badssl.com
		"104.154.89.105:80": {
			IP:       "104.154.89.105",
			Port:     80,
			Expected: true,
		},
		// http.badssl.com
		"104.154.89.105:443": {
			IP:       "104.154.89.105",
			Port:     443,
			Expected: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual, err := TCPConnect(tc.IP, tc.Port, 1*time.Second)
			if err != nil && tc.ExpectedErr != nil {
				if !tc.ExpectedErr.MatchString(err.Error()) {
					t.Errorf("Expected error '%#v', got '%#v'", tc.ExpectedErr, err)
				}
			}

			if actual != tc.Expected {
				t.Errorf("Expected %#v, got %#v", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
// func TestTLSConnect(t *testing.T) { // lint:allow_complexity
// 	for name, tc := range map[string]struct {
// 		Host        string
// 		Port        int
// 		Expected    int
// 		ExpectedErr *regexp.Regexp
// 		TLSVersion  uint16
// 	}{
// 		"cloudflare.com": {
// 			Host:       "cloudflare.com",
// 			Port:       443,
// 			TLSVersion: tls.VersionTLS12,
// 		},
// 		"github.com": {
// 			Host:       "github.com",
// 			Port:       443,
// 			TLSVersion: tls.VersionTLS12,
// 		},
// 		"ryanparman.com": {
// 			Host:       "ryanparman.com",
// 			Port:       443,
// 			TLSVersion: tls.VersionTLS12,
// 		},
// 		"example.com": {
// 			Host:       "example.com",
// 			Port:       443,
// 			TLSVersion: tls.VersionTLS12,
// 		},
// 		"http.badssl.com": {
// 			Host:       "http.badssl.com",
// 			Port:       443,
// 			TLSVersion: tls.VersionTLS12,
// 		},
// 		"captive.apple.com": {
// 			Host:       "captive.apple.com",
// 			Port:       443,
// 			TLSVersion: tls.VersionTLS12,
// 		},
// 		"detectportal.firefox.com": {
// 			Host:       "detectportal.firefox.com",
// 			Port:       443,
// 			TLSVersion: tls.VersionTLS12,
// 		},
// 	} {
// 		t.Run(name, func(t *testing.T) {
// 			actual, chi, err := TLSConnect(tc.Host, tc.Port, 1*time.Second, tc.TLSVersion)
// 			if err != nil && tc.ExpectedErr != nil {
// 				if !tc.ExpectedErr.MatchString(err.Error()) {
// 					t.Errorf("Expected error '%#v', got '%#v'", tc.ExpectedErr, err)
// 				}
// 			}

// 			conn := actual.ConnectionState()
// 			actual.Close()

// 			pp := debug.GetSpew()
// 			pp.Dump(conn)
// 			fmt.Println("---------------------------------------------------------------------------")
// 			pp.Dump(chi)
// 			fmt.Println("---------------------------------------------------------------------------")

// 			// for i := range actual {
// 			// 	a := actual[i]

// 			// 	if !slices.Contains(tc.Expected, a) {
// 			// 		t.Errorf("Expected to find %#v inside %#v", a, tc.Expected)
// 			// 	}
// 			// }

// 			panic("1")
// 		})
// 	}
// }
