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

type Signature int

const (
	// Signature algorithms
	SigAnonymous Signature = 0x0000
	SigRSA       Signature = 0x0001
	SigDSA       Signature = 0x0002
	SigECDSA     Signature = 0x0003
	// 0x0004-0x0006   Reserved
	SigED25519 Signature = 0x0007
	SigED448   Signature = 0x0008
	// 0x0009-0x003F   Reserved
	SigGOST256 Signature = 0x0040
	SigGOST512 Signature = 0x0041
	// 0x0042-0x00DF   Reserved
	// 0x00E0-0x00FF   Reserved for Private Use

	// The following are not assigned real values from the IANA.
	SigNULL Signature = 0x0100
)

var AuthenticationList = map[Signature]string{
	SigAnonymous: "Anonymous",
	SigRSA:       "RSA",
	SigDSA:       "NIST Digital Signature (DSA)",
	SigECDSA:     "Elliptic Curve Digital Signature (ECDSA)",
	SigED25519:   "Edwards-curve Digital Signature (ED25519)",
	SigED448:     "Edwards-curve Digital Signature (ED448)",
	SigGOST256:   "Russian GOST 256-bit",
	SigGOST512:   "Russian GOST 512-bit",
	SigNULL:      "NULL",
}
