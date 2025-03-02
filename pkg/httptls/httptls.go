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
	"cmp"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goware/urlx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/exp/maps"
	"golang.org/x/net/http2"
)

const (
	// VersionTLS10 represents the TLS 1.0 protocol version.
	VersionTLS10 = 0x0301

	// VersionTLS11 represents the TLS 1.1 protocol version.
	VersionTLS11 = 0x0302

	// VersionTLS12 represents the TLS 1.2 protocol version.
	VersionTLS12 = 0x0303

	// VersionTLS13 represents the TLS 1.3 protocol version.
	VersionTLS13 = 0x0304
)

// ParseDomain parses a URL-like string and returns the domain/hostname with an
// `https:` scheme.
func ParseDomain(domain string) (string, error) {
	u, err := urlx.ParseWithDefaultScheme(domain, "https")
	if err != nil {
		return "", fmt.Errorf("could not parse the URL: %w", err)
	}

	return u.Scheme + "://" + u.Host, nil
}

// ParseHostPort parses a domain string and returns the hostname and port. An
// `https:` scheme will return port 443, and an `http:` scheme will return port
// 80.
//
// If a custom port is specified in the domain string, it will be returned as
// the port.
func ParseHostPort(domain string) (string, string, error) {
	u, err := urlx.ParseWithDefaultScheme(domain, "https")
	if err != nil {
		return "", "", fmt.Errorf("could not parse the URL: %w", err)
	}

	if strings.Contains(u.Host, ":") {
		hostPort := strings.Split(u.Host, ":")

		return hostPort[0], hostPort[1], nil
	} else if u.Scheme == "https" {
		return u.Host, "443", nil
	} else if u.Scheme == "http" {
		return u.Host, "80", nil
	}

	return u.Host, u.Port(), nil
}

// ResolveEndpointToIPs resolves a domain to the IPv4 and IPv6 addresses which
// are used to serve it.
//
// Accepts an optional Options struct to configure the logger and other
// connectivity settings.
func ResolveEndpointToIPs(domain string, opts ...Options) ([]string, error) {
	options := handleOpts(opts)
	logger := options.Logger

	host, _, err := ParseHostPort(domain)
	if err != nil {
		return []string{}, err
	}

	logger.Debugf("Resolving host `%s` to IP addresses", host)

	addrs, err := net.LookupHost(host)
	if err != nil {
		host = "www." + host

		logger.Debugf("Resolving host `%s` to IP addresses", host)

		addrs, err = net.LookupHost(host)
		if err != nil {
			return []string{}, fmt.Errorf("could not resolve host `%s`: %w", host, err)
		}
	}

	return addrs, nil
}

// GetSupportedHTTPVersions checks a domain for supported HTTP versions. HTTP
// 1.1, 2, and 3 are checked.
//
// Goroutines are used to check each version concurrently. The results are then
// collected and returned.
func GetSupportedHTTPVersions(domain string, opts ...Options) (HTTPResult, error) {
	options := handleOpts(opts)
	logger := options.Logger
	timeoutSecs := options.TimeoutSeconds

	httpConn := HTTPResult{
		Hostname: domain,
	}
	errors := make(chan error, 3)

	var wg sync.WaitGroup

	results := make(chan struct {
		version   string
		supported bool
	}, 3)

	// Check HTTP/1.1 support
	wg.Add(1)
	go func() {
		defer wg.Done()

		logger.Info("Checking", "domain", domain, "http", "1.1")

		client := &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
		}

		req, err := http.NewRequest("GET", domain, nil)
		if err != nil {
			errors <- fmt.Errorf("could not create HTTP/1.1 request: %w", err)
			return
		}

		resp, err := client.Do(req)

		logger.Debug("Completed", "domain", domain, "http", "1.1")

		if err == nil {
			results <- struct {
				version   string
				supported bool
			}{"HTTP/1.1", true}
			resp.Body.Close()
		} else {
			results <- struct {
				version   string
				supported bool
			}{"HTTP/1.1", false}
		}
	}()

	// Check HTTP/2 support
	wg.Add(1)
	go func() {
		defer wg.Done()

		logger.Info("Checking", "domain", domain, "http", "2")

		client := &http.Client{
			Timeout:   time.Duration(timeoutSecs) * time.Second,
			Transport: &http2.Transport{},
		}

		req, err := http.NewRequest("GET", domain, nil)
		if err != nil {
			errors <- fmt.Errorf("could not create HTTP/2 request: %w", err)
			return
		}

		resp, err := client.Do(req)

		logger.Debug("Completed", "domain", domain, "http", "2")

		if err == nil && resp.ProtoMajor == 2 {
			results <- struct {
				version   string
				supported bool
			}{"HTTP/2", true}
			resp.Body.Close()
		} else {
			results <- struct {
				version   string
				supported bool
			}{"HTTP/2", false}
		}
	}()

	// Check HTTP/3 support
	wg.Add(1)
	go func() {
		defer wg.Done()

		logger.Info("Checking", "domain", domain, "http", "3")

		tr := &http3.Transport{
			TLSClientConfig: &tls.Config{},  // set a TLS client config, if desired
			QUICConfig:      &quic.Config{}, // QUIC connection options
		}
		defer tr.Close()

		client := &http.Client{
			Timeout:   time.Duration(timeoutSecs) * time.Second,
			Transport: tr,
		}

		req, err := http.NewRequest("GET", domain, nil)
		if err != nil {
			errors <- fmt.Errorf("could not create HTTP/3 request: %w", err)
			return
		}

		resp, err := client.Do(req)

		logger.Debug("Completed", "domain", domain, "http", "3")

		if err == nil && resp.ProtoMajor == 3 {
			results <- struct {
				version   string
				supported bool
			}{"HTTP/3", true}
			resp.Body.Close()
		} else {
			results <- struct {
				version   string
				supported bool
			}{"HTTP/3", false}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	for result := range results {
		switch result.version {
		case "HTTP/1.1":
			httpConn.HTTP11 = result.supported
		case "HTTP/2":
			httpConn.HTTP2 = result.supported
		case "HTTP/3":
			httpConn.HTTP3 = result.supported
		}
	}

	if len(errors) > 0 {
		return httpConn, <-errors
	}

	return httpConn, nil
}

// GetSupportedTLSVersions checks a domain for supported TLS versions. SSL v2,
// SSL v3, TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3 are checked.
//
// Goroutines are used to check each version and ciphersuite concurrently. The
// results are then collected and returned.
func GetSupportedTLSVersions(domain, port string, opts ...Options) (TLSResult, error) {
	options := handleOpts(opts)
	logger := options.Logger

	tlsConn := TLSResult{
		Hostname: domain,
	}

	var wg sync.WaitGroup

	supportedVersions := []TLSConnection{}
	ipPort := net.JoinHostPort(domain, port)
	results := make(chan TLSConnection)

	for _, version := range []uint16{
		VersionTLS10, // TLS 1.0
		VersionTLS11, // TLS 1.1
		VersionTLS12, // TLS 1.2
		VersionTLS13, // TLS 1.3
	} {
		wg.Add(1)
		go func(version uint16) {
			defer wg.Done()
			var (
				cs     []uint16
				suites []CipherData
			)

			cs = maps.Keys(CipherList)

			switch version {
			case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12:
				// Go only supports a very limited set of cipher suites. They
				// are all on the secure end of the spectrum, which is good, but
				// it also means that there are things that we cannot test for.
				//
				// https://cs.opensource.google/go/go/+/refs/tags/go1.23.5:src/crypto/tls/cipher_suites.go;l=677-699
				// https://datatracker.ietf.org/doc/html/rfc2246/#appendix-C
				// https://datatracker.ietf.org/doc/html/rfc4346/#appendix-C
				// https://datatracker.ietf.org/doc/html/rfc5246/#appendix-C
				// cs = maps.Keys(CipherList)
				cs = []uint16{
					// Recommended
					0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
					0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
					0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

					// Strong
					0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
					0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
					0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

					// Weak (CBC)
					0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
					0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
					0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
					0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
					0xC023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
					0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

					// Insecure
					// https://cs.opensource.google/go/go/+/refs/tags/go1.23.5:src/crypto/tls/cipher_suites.go;l=73-95
					0xC007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
					0xC011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA

					// tlsrsakex=1
					0x0005, // TLS_RSA_WITH_RC4_128_SHA
					0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
					0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
					0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
					0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
					0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384

					// tls3des=1
					0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
					0xC012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
				}
			case tls.VersionTLS13:
				// In Go, the TLS 1.3 cipher suites are non-configurable. For
				// this reason, we only test one even if all 3 are supported.
				//
				// https://go.dev/blog/tls-cipher-suites
				// https://cs.opensource.google/go/go/+/refs/tags/go1.23.5:src/crypto/tls/cipher_suites.go;l=701-704
				// https://datatracker.ietf.org/doc/html/rfc8446/#appendix-B.4
				cs = []uint16{
					0x1301, // TLS_AES_128_GCM_SHA256
					// 0x1302, // TLS_AES_256_GCM_SHA384
					// 0x1303, // TLS_CHACHA20_POLY1305_SHA256
					// 0x1304, // TLS_AES_128_CCM_SHA256
					// 0x1305, // TLS_AES_128_CCM_8_SHA256
				}
			}

			var innerWg sync.WaitGroup
			innerResults := make(chan CipherData)

			for _, c := range cs {
				innerWg.Add(1)
				go func(c uint16) {
					defer innerWg.Done()

					logger.Info("Checking",
						"endpoint", ipPort,
						"proto", TLSVersion[version],
						"cipher", CipherList[c].IANAName,
					)

					conf := &tls.Config{
						InsecureSkipVerify: true,
						MinVersion:         version,
						MaxVersion:         version,
						CipherSuites:       []uint16{c},
					}

					conn, err := tls.Dial("tcp", ipPort, conf)
					if err != nil {
						return
					}

					state := conn.ConnectionState()
					conn.Close()

					suite := CipherList[state.CipherSuite]
					suite.Populate()

					innerResults <- suite
				}(c)
			}

			go func() {
				innerWg.Wait()
				close(innerResults)
			}()

			for suite := range innerResults {
				suites = append(suites, suite)
			}

			if len(suites) > 0 {
				var versionStr string

				versionInt := int(version)

				switch version {
				case tls.VersionTLS10:
					versionStr = TLSVersion[VersionTLS10]
				case tls.VersionTLS11:
					versionStr = TLSVersion[VersionTLS11]
				case tls.VersionTLS12:
					versionStr = TLSVersion[VersionTLS12]
				case tls.VersionTLS13:
					versionStr = TLSVersion[VersionTLS13]
				}
				results <- TLSConnection{
					VersionID:    versionInt,
					Version:      versionStr,
					CipherSuites: suites,
				}
			}
		}(version)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		supportedVersions = append(supportedVersions, result)
	}

	slices.SortFunc(supportedVersions, func(a, b TLSConnection) int {
		return cmp.Compare(b.VersionID, a.VersionID)
	})

	for i := range supportedVersions {
		slices.SortFunc(supportedVersions[i].CipherSuites, func(a, b CipherData) int {
			return cmp.Or(
				cmp.Compare(a.Strength, b.Strength),
				cmp.Compare(a.IANAName, b.IANAName),
			)
		})
	}

	for i := range supportedVersions {
		supportedVersion := supportedVersions[i]

		switch supportedVersion.VersionID {
		case tls.VersionTLS10:
			tlsConn.TLSVersions.TLSv10 = len(supportedVersion.CipherSuites) > 0
		case tls.VersionTLS11:
			tlsConn.TLSVersions.TLSv11 = len(supportedVersion.CipherSuites) > 0
		case tls.VersionTLS12:
			tlsConn.TLSVersions.TLSv12 = len(supportedVersion.CipherSuites) > 0
		case tls.VersionTLS13:
			tlsConn.TLSVersions.TLSv13 = len(supportedVersion.CipherSuites) > 0
		}
	}

	tlsConn.TLSConnections = supportedVersions

	return tlsConn, nil
}
