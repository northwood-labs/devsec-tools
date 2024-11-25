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
	TLSConnection struct {
		// Version represents the version of TLS.
		Version string `json:"version"`

		// CipherSuite represents the cipher suites that the connection advertises.
		CipherSuites []CipherData `json:"cipherSuites"`

		// ECH represents whether or not the server supports Encrypted Client Hello.
		ECH bool `json:"ech"`
	}
)

func (c *CipherData) Populate() {
	c.Strength = StrengthList[c.strength]
	c.KeyExchange = KeyExchangeList[c.keyExchange]
	c.Authentication = AuthenticationList[c.authentication]
	c.EncryptionAlgo = EncryptionAlgoList[c.encryptionAlgo]
	c.Hash = HashList[c.hash]

	for i := range c.problems {
		p := c.problems[i]

		c.Problems = append(c.Problems, ProblemData{
			Type:        ProblemTypeList[p],
			Description: ProblemList[p],
			URLs:        append(ProblemURLList[p], fmt.Sprintf(LinkCSInfo, c.IANAName)),
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
