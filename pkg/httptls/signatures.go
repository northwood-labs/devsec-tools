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

	SigECCPWD      Signature = 0x0101
	SigKRB5        Signature = 0x0102
	SigPSK         Signature = 0x0103
	SigSHA1        Signature = 0x0104
	SigSHA1DSS     Signature = 0x0105
	SigSHA1RSA     Signature = 0x0106
	SigSHA256      Signature = 0x0107
	SigSHA384      Signature = 0x0108
	SigSM2         Signature = 0x0109
	SigGOSTR341094 Signature = 0x0110
	SigGOSTR341001 Signature = 0x0111
)

var (
	// AuthenticationList is a map of signature algorithms to their human-readable names.
	AuthenticationList = map[Signature]string{
		SigAnonymous:   "Anonymous",
		SigDSA:         "NIST Digital Signature (DSA)",
		SigECCPWD:      "ECCPWD",
		SigECDSA:       "Elliptic Curve Digital Signature (ECDSA)",
		SigED25519:     "Edwards-curve Digital Signature (ED25519)",
		SigED448:       "Edwards-curve Digital Signature (ED448)",
		SigGOST256:     "Russian GOST 256-bit",
		SigGOST512:     "Russian GOST 512-bit",
		SigGOSTR341001: "GOST R 34.10-2001 (GOSTR341001)",
		SigGOSTR341094: "GOST R 34.10-1994 (GOSTR341094)",
		SigKRB5:        "Kerberos",
		SigNULL:        "NULL",
		SigPSK:         "Pre-Shared Keys (PSK)",
		SigRSA:         "RSA",
		SigSHA1:        "Secure Hash Algorithm 1 (SHA-1)",
		SigSHA1DSS:     "Secure Hash Algorithm 1 (SHA-1) with NIST DSS (SHA-1 DSS)",
		SigSHA1RSA:     "Secure Hash Algorithm 1 (SHA-1) with RSA (SHA-1 RSA)",
		SigSHA256:      "Secure Hash Algorithm 256 (SHA-256)",
		SigSHA384:      "Secure Hash Algorithm 384 (SHA-384)",
		SigSM2:         "ShangMi-2 (SM2)",
	}

	// NIST_SP_800_52AuthList is oddly-named, but more understandable in this
	// format. As opposed to AEAD or PFS, the NIST SP 800-52 list requires
	// cipher suites which are a combination of cipher suites sections (key
	// exchange + auth sig + encryption + hash).
	//
	// See §3.3.1.1.1 Cipher Suites for ECDSA Certificates
	// See §3.3.1.1.2 Cipher Suites for RSA Certificates
	NIST_SP_800_52AuthList = map[Signature]bool{
		SigECDSA: true,
		SigRSA:   true,
	}

	// FIPS-186 defines an allowed set of signature authentication algorithms.
	FIPS186List = map[Signature]bool{
		SigECDSA: true,
		SigRSA:   true,
	}
)
