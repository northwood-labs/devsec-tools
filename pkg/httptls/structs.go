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

	"github.com/charmbracelet/log"
	"github.com/valkey-io/valkey-go"
)

const LinkCSInfo = "https://ciphersuite.info/cs/%s"

type (
	// Options is used to pass options to the HTTP and TLS functions.
	Options struct {
		// Logger is an instance of the charmbracelet/log logger.
		Logger *log.Logger

		// TimeoutSeconds is the number of seconds to wait before timing out.
		TimeoutSeconds int

		// ValkeyClient is an instance of the Valkey client.
		ValkeyClient *valkey.Client
	}

	// HTTPResult represents the results of an HTTP check.
	HTTPResult struct {
		// Hostname represents the hostname of the connection.
		Hostname string `json:"hostname"`

		// HTTP11 represents whether or not the connection supports HTTP/1.1.
		HTTP11 bool `json:"http11"`

		// HTTP2 represents whether or not the connection supports HTTP/2.
		HTTP2 bool `json:"http2"`

		// HTTP3 represents whether or not the connection supports HTTP/3.
		HTTP3 bool `json:"http3"`
	}

	// TLSResult represents the results of a TLS check.
	TLSResult struct {
		// Hostname represents the hostname of the connection.
		Hostname string `json:"hostname"`

		// TLSConnections represents the TLS connections that the connection advertises.
		TLSConnections []TLSConnection `json:"tlsConnections,omitempty"`
	}

	// TLSConnection represents a single TLS connection, and is part of the TLSResult struct.
	TLSConnection struct {
		// VersionID represents the version of TLS as an integer.
		VersionID int `json:"versionId,omitempty"`

		// Version represents the version of TLS.
		Version string `json:"version,omitempty"`

		// CipherSuite represents the cipher suites that the connection advertises.
		CipherSuites []CipherData `json:"cipherSuites,omitempty"`
	}
)

// Populate populates the CipherData struct with human-readable values, based on
// integer values that are collected during scanning.
func (c *CipherData) Populate() {
	c.URL = fmt.Sprintf(LinkCSInfo, c.IANAName)
	c.Strength = StrengthList[c.strength]
	c.KeyExchange = KeyExchangeList[c.keyExchange]
	c.Authentication = AuthenticationList[c.authentication]
	c.EncryptionAlgo = EncryptionAlgoList[c.encryptionAlgo]
	c.Hash = HashList[c.hash]

	// Apply PFS settings
	if _, ok := PFSList[c.keyExchange]; ok {
		c.IsPFS = true
	}

	// Apply AEAD settings
	if _, ok := AEADList[c.encryptionAlgo]; ok {
		c.IsAEAD = true
	}
}

func handleOpts(opts []Options) *Options {
	logger := &log.Logger{}
	timeout := 3

	var vkClient *valkey.Client

	for _, opt := range opts {
		if opt.Logger != nil {
			logger = opt.Logger
		}

		if opt.TimeoutSeconds > 0 {
			timeout = opt.TimeoutSeconds
		}

		if opt.ValkeyClient != nil {
			vkClient = opt.ValkeyClient
		}

		break
	}

	return &Options{
		Logger:         logger,
		TimeoutSeconds: timeout,
		ValkeyClient:   vkClient,
	}
}
