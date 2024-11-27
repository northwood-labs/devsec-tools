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
	"encoding/json"
	"fmt"
)

type (
	Connection struct {
		// Hostname represents the hostname of the connection.
		Hostname string `json:"hostname"`

		// TLSConnections represents the TLS connections that the connection advertises.
		TLSConnections []TLSConnection `json:"tlsConnections,omitempty"`

		// HTTP11 represents whether or not the connection supports HTTP/1.1.
		HTTP11 bool `json:"http11"`

		// HTTP2 represents whether or not the connection supports HTTP/2.
		HTTP2 bool `json:"http2"`

		// HTTP3 represents whether or not the connection supports HTTP/3.
		HTTP3 bool `json:"http3"`
	}

	TLSConnection struct {
		// Version represents the version of TLS.
		Version string `json:"version,omitempty"`

		// CipherSuite represents the cipher suites that the connection advertises.
		CipherSuites []CipherData `json:"cipherSuites,omitempty"`
	}
)

func (c *CipherData) Populate() {
	c.URL = fmt.Sprintf(LinkCSInfo, c.IANAName)
	c.Strength = StrengthList[c.strength]
	c.KeyExchange = KeyExchangeList[c.keyExchange]
	c.Authentication = AuthenticationList[c.authentication]
	c.EncryptionAlgo = EncryptionAlgoList[c.encryptionAlgo]
	c.Hash = HashList[c.hash]

	if problem, ok := ProblemList["kex"][c.keyExchange]; ok {
		c.Problems = append(c.Problems, ProblemData{
			Class:       "kex",
			Description: problem.Description,
			URLs:        problem.URLs,
		})
	}

	if problem, ok := ProblemList["authsig"][c.authentication]; ok {
		c.Problems = append(c.Problems, ProblemData{
			Class:       "authsig",
			Description: problem.Description,
			URLs:        problem.URLs,
		})
	}

	if problem, ok := ProblemList["encryption"][c.encryptionAlgo]; ok {
		c.Problems = append(c.Problems, ProblemData{
			Class:       "encryption",
			Description: problem.Description,
			URLs:        problem.URLs,
		})
	}

	if problem, ok := ProblemList["hash"][c.hash]; ok {
		c.Problems = append(c.Problems, ProblemData{
			Class:       "hash",
			Description: problem.Description,
			URLs:        problem.URLs,
		})
	}
}

func (t *TLSConnection) ToJSON() (string, error) {
	for i := range t.CipherSuites {
		t.CipherSuites[i].Populate()
	}

	b, err := json.Marshal(t)

	return string(b), err
}
