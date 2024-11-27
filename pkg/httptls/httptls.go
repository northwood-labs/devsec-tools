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
	"time"

	"github.com/goware/urlx"
	"golang.org/x/net/http2"
)

const (
	VersionSSL20 = 0x0002
	VersionSSL30 = 0x0300
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

func TCPConnect(ip string, port int, timeout time.Duration) (bool, error) {
	ipPort := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", ipPort, timeout)
	if err != nil {
		return false, fmt.Errorf("could not dial %s within %s: %w", ipPort, timeout, err)
	}

	conn.Close()

	return true, nil
}

func GetSupportedTLSVersions(domain string, port int) ([]TLSConnection, error) {
	supportedVersions := []TLSConnection{}
	ipPort := net.JoinHostPort(domain, fmt.Sprintf("%d", port))

	for _, version := range []uint16{
		0x0002, // SSL v2
		0x0300, // SSL v3
		0x0301, // TLS 1.0
		0x0302, // TLS 1.1
		0x0303, // TLS 1.2
		0x0304, // TLS 1.3
	} {
		var (
			cs     []uint16
			suites []CipherData
		)

		// cs = maps.Keys(CipherList)

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
				0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
				0x0030, // TLS_DH_DSS_WITH_AES_128_CBC_SHA
				0x0031, // TLS_DH_RSA_WITH_AES_128_CBC_SHA
				0x0032, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
				0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
				0x0034, // TLS_DH_anon_WITH_AES_128_CBC_SHA
				0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
				0x0036, // TLS_DH_DSS_WITH_AES_256_CBC_SHA
				0x0037, // TLS_DH_RSA_WITH_AES_256_CBC_SHA
				0x0038, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
				0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
				0x003A, // TLS_DH_anon_WITH_AES_256_CBC_SHA
				0x003B, // TLS_RSA_WITH_NULL_SHA256
				0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
				0x003D, // TLS_RSA_WITH_AES_256_CBC_SHA256
				0x003E, // TLS_DH_DSS_WITH_AES_128_CBC_SHA256
				0x003F, // TLS_DH_RSA_WITH_AES_128_CBC_SHA256
				0x0040, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
				0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
				0x0068, // TLS_DH_DSS_WITH_AES_256_CBC_SHA256
				0x0069, // TLS_DH_RSA_WITH_AES_256_CBC_SHA256
				0x006A, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
				0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
				0x006C, // TLS_DH_anon_WITH_AES_128_CBC_SHA256
				0x006D, // TLS_DH_anon_WITH_AES_256_CBC_SHA256
			}
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

		for c := range cs {
			conf := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         version,
				MaxVersion:         version,
				CipherSuites:       []uint16{uint16(c)},
			}

			conn, err := tls.Dial("tcp", ipPort, conf)
			if err != nil {
				continue
			}

			state := conn.ConnectionState()
			conn.Close()

			suite := CipherList[state.CipherSuite]
			suite.Populate()

			suites = append(suites, suite)
		}

		switch version {
		case VersionSSL20:
			if len(suites) > 0 {
				supportedVersions = append(supportedVersions, TLSConnection{
					Version:      "SSLv2",
					CipherSuites: suites,
				})
			}
		case VersionSSL30:
			if len(suites) > 0 {
				supportedVersions = append(supportedVersions, TLSConnection{
					Version:      "SSLv3",
					CipherSuites: suites,
				})
			}
		case tls.VersionTLS10:
			if len(suites) > 0 {
				supportedVersions = append(supportedVersions, TLSConnection{
					Version:      "TLS v1.0",
					CipherSuites: suites,
				})
			}
		case tls.VersionTLS11:
			if len(suites) > 0 {
				supportedVersions = append(supportedVersions, TLSConnection{
					Version:      "TLS v1.1",
					CipherSuites: suites,
				})
			}
		case tls.VersionTLS12:
			if len(suites) > 0 {
				supportedVersions = append(supportedVersions, TLSConnection{
					Version:      "TLS v1.2",
					CipherSuites: suites,
				})
			}
		case tls.VersionTLS13:
			if len(suites) > 0 {
				supportedVersions = append(supportedVersions, TLSConnection{
					Version:      "TLS v1.3",
					CipherSuites: suites,
				})
			}
		}
	}

	return supportedVersions, nil
}

func GetSupportedHTTPVersions(domain string) ([]string, error) {
	supportedVersions := []string{}

	// Check HTTP/1.1 support
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	req, err := http.NewRequest("GET", domain, nil)
	if err != nil {
		return supportedVersions, fmt.Errorf("could not create HTTP request: %w", err)
	}

	resp, err := client.Do(req)
	if err == nil {
		supportedVersions = append(supportedVersions, "HTTP/1.1")
		resp.Body.Close()
	}

	// Check HTTP/2 support
	client = &http.Client{
		Timeout:   1 * time.Second,
		Transport: &http2.Transport{},
	}

	req, err = http.NewRequest("GET", domain, nil)
	if err != nil {
		return supportedVersions, fmt.Errorf("could not create HTTP request: %w", err)
	}

	resp, err = client.Do(req)
	if err == nil && resp.ProtoMajor == 2 {
		supportedVersions = append(supportedVersions, "HTTP/2")
		resp.Body.Close()
	}

	return supportedVersions, nil
}

// o.SupportedSuites = append(o.SupportedSuites, fmt.Sprintf("Unknown, 0x%x", suite))
// o.SupportedCurves = append(o.SupportedCurves, fmt.Sprintf("Unknown, 0x%x", curve))
// o.SupportedPoints = append(o.SupportedPoints, fmt.Sprintf("0x%x", point))
