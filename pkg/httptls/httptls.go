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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/goware/urlx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/exp/maps"
	"golang.org/x/net/http2"
)

const (
	VersionSSL20 = 0x0002
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// getHost parses the provided domain name, and returns the host or (host +
// port), whichever pairing was provided.
func getHost(domain string) (string, error) {
	u, err := urlx.Parse(domain)
	if err != nil {
		return "", fmt.Errorf("could not parse the URL: %w", err)
	}

	return u.Host, nil
}

func ResolveEndpointToIPs(domain string) ([]string, error) {
	host, err := getHost(domain)
	if err != nil {
		return []string{}, err
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		host = "www." + host

		addrs, err = net.LookupHost(host)
		if err != nil {
			return []string{}, fmt.Errorf("could not resolve host `%s`: %w", host, err)
		}
	}

	return addrs, nil
}

func GetSupportedHTTPVersions(domain string) (Connection, error) {
    httpConn := Connection{
		Hostname: domain,
	}
    errors := make(chan error, 2)

	var wg sync.WaitGroup

	results := make(chan struct {
        version string
        supported bool
    }, 2)

    // Check HTTP/1.1 support
    wg.Add(1)
    go func() {
        defer wg.Done()

        client := &http.Client{}

		req, err := http.NewRequest("GET", domain, nil)
        if err != nil {
            errors <- fmt.Errorf("could not create HTTP/1.1 request: %w", err)
            return
        }

        resp, err := client.Do(req)
        if err == nil {
            results <- struct {
                version string
                supported bool
            }{"HTTP/1.1", true}
            resp.Body.Close()
        } else {
            results <- struct {
                version string
                supported bool
            }{"HTTP/1.1", false}
        }
    }()

    // Check HTTP/2 support
    wg.Add(1)
    go func() {
        defer wg.Done()

		client := &http.Client{
            Transport: &http2.Transport{},
        }

		req, err := http.NewRequest("GET", domain, nil)
        if err != nil {
            errors <- fmt.Errorf("could not create HTTP/2 request: %w", err)
            return
        }

        resp, err := client.Do(req)
        if err == nil && resp.ProtoMajor == 2 {
            results <- struct {
                version string
                supported bool
            }{"HTTP/2", true}
            resp.Body.Close()
        } else {
            results <- struct {
                version string
                supported bool
            }{"HTTP/2", false}
        }
    }()

    // Check HTTP/3 support
    wg.Add(1)
    go func() {
        defer wg.Done()

		tr := &http3.Transport{
			TLSClientConfig: &tls.Config{},  // set a TLS client config, if desired
			QUICConfig:      &quic.Config{}, // QUIC connection options
		}
		defer tr.Close()

		client := &http.Client{
			Transport: tr,
		}

		req, err := http.NewRequest("GET", domain, nil)
        if err != nil {
            errors <- fmt.Errorf("could not create HTTP/3 request: %w", err)
            return
        }

        resp, err := client.Do(req)
        if err == nil && resp.ProtoMajor == 3 {
            results <- struct {
                version string
                supported bool
            }{"HTTP/3", true}
            resp.Body.Close()
        } else {
            results <- struct {
                version string
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

func GetSupportedTLSVersions(domain string, port int) ([]TLSConnection, error) {
	var wg sync.WaitGroup

	supportedVersions := []TLSConnection{}
	ipPort := net.JoinHostPort(domain, fmt.Sprintf("%d", port))
	results := make(chan TLSConnection)

	for _, version := range []uint16{
		VersionSSL20, // SSL v2
		VersionSSL30, // SSL v3
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
			case VersionSSL20, VersionSSL30:
				// https://datatracker.ietf.org/doc/html/rfc6101#appendix-C
				cs = []uint16{
					0x0000, // TLS_NULL_WITH_NULL_NULL
					0x0001, // TLS_RSA_WITH_NULL_MD5
					0x0002, // TLS_RSA_WITH_NULL_SHA
					0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
					0x0004, // TLS_RSA_WITH_RC4_128_MD5
					0x0005, // TLS_RSA_WITH_RC4_128_SHA
					0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
					0x0007, // TLS_RSA_WITH_IDEA_CBC_SHA
					0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
					0x0009, // TLS_RSA_WITH_DES_CBC_SHA
					0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
					0x000B, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
					0x000C, // TLS_DH_DSS_WITH_DES_CBC_SHA
					0x000D, // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
					0x000E, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
					0x000F, // TLS_DH_RSA_WITH_DES_CBC_SHA
					0x0010, // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
					0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
					0x0012, // TLS_DHE_DSS_WITH_DES_CBC_SHA
					0x0013, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
					0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
					0x0015, // TLS_DHE_RSA_WITH_DES_CBC_SHA
					0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
					0x0017, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
					0x0018, // TLS_DH_anon_WITH_RC4_128_MD5
					0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
					0x001A, // TLS_DH_anon_WITH_DES_CBC_SHA
					0x001B, // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
					// TLS_FORTEZZA_KEA_WITH_NULL_SHA
					// TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
					// TLS_FORTEZZA_KEA_WITH_RC4_128_SHA
				}
			case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12:
				// https://datatracker.ietf.org/doc/html/rfc2246/#appendix-C
				// https://datatracker.ietf.org/doc/html/rfc4346/#appendix-C
				// https://datatracker.ietf.org/doc/html/rfc5246/#appendix-C
				cs = maps.Keys(CipherList)
			case tls.VersionTLS13:
				// https://datatracker.ietf.org/doc/html/rfc8446/#appendix-B.4
				cs = []uint16{
					0x1301, // TLS_AES_128_GCM_SHA256
					0x1302, // TLS_AES_256_GCM_SHA384
					0x1303, // TLS_CHACHA20_POLY1305_SHA256
					0x1304, // TLS_AES_128_CCM_SHA256
					0x1305, // TLS_AES_128_CCM_8_SHA256
				}
			}

			var innerWg sync.WaitGroup
			innerResults := make(chan CipherData)

			for _, c := range cs {
				innerWg.Add(1)
				go func(c uint16) {
					defer innerWg.Done()

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
				switch version {
				case VersionSSL20:
					versionStr = "SSLv2"
				case VersionSSL30:
					versionStr = "SSLv3"
				case tls.VersionTLS10:
					versionStr = "TLS v1.0"
				case tls.VersionTLS11:
					versionStr = "TLS v1.1"
				case tls.VersionTLS12:
					versionStr = "TLS v1.2"
				case tls.VersionTLS13:
					versionStr = "TLS v1.3"
				}
				results <- TLSConnection{
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

	return supportedVersions, nil
}
