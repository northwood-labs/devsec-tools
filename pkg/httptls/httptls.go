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
	"time"

	"github.com/goware/urlx"
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

func TLSConnect(
	host string,
	port int,
	timeout time.Duration,
	forceTLS ...uint16,
) (*tls.Conn, *tls.ClientHelloInfo, error) {
	listPort := ""
	if port != 80 && port != 443 {
		listPort = fmt.Sprintf(":%d", port)
	}

	var clientHello *tls.ClientHelloInfo

	config := &tls.Config{
		ServerName: host + listPort,
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = hi

			return nil, nil
		},
	}

	if len(forceTLS) > 0 {
		config.MinVersion = forceTLS[0]
		config.MaxVersion = forceTLS[0]
	}

	timeoutDialer := &net.Dialer{
		Timeout: timeout,
	}

	hostPort := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn2 := &tls.Conn{}

	conn1, err := tls.DialWithDialer(timeoutDialer, "tcp", hostPort, config)
	if err != nil {
		conn1.Close()
		hostPort = "www." + hostPort
		config.ServerName = hostPort

		conn2, err = tls.DialWithDialer(timeoutDialer, "tcp", hostPort, config)
		if err != nil {
			return &tls.Conn{}, clientHello, fmt.Errorf("could not dial %s within %s: %w", hostPort, timeout, err)
		}

		return conn2, clientHello, nil
	}

	return conn1, clientHello, nil
}

// o.SupportedSuites = append(o.SupportedSuites, fmt.Sprintf("Unknown, 0x%x", suite))
// o.SupportedCurves = append(o.SupportedCurves, fmt.Sprintf("Unknown, 0x%x", curve))
// o.SupportedPoints = append(o.SupportedPoints, fmt.Sprintf("0x%x", point))
