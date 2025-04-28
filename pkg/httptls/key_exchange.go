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

type KeyExchange int

const (
	// Key exchange algorithms
	KexNone KeyExchange = iota
	KexDH
	KexDHE
	KexECCPWD
	KexECDH
	KexECDHE
	KexGOSTR341094
	KexGOSTR341001
	KexKRB5
	KexNULL
	KexPSK
	KexRSA
	KexSRP
	KexSM2
)

var (
	// KeyExchangeList is a map of key exchange algorithms to their human-readable names.
	KeyExchangeList = map[KeyExchange]string{
		KexNone:        "None",
		KexDH:          "Diffie-Hellman (Non-Ephemeral) (ECDH)",
		KexDHE:         "Diffie-Hellman (Ephemeral) (ECDHE)",
		KexECCPWD:      "ECCPWD",
		KexECDH:        "Elliptic Curve Diffie-Hellman (Non-Ephemeral) (ECDH)",
		KexECDHE:       "Elliptic Curve Diffie-Hellman (Ephemeral) (ECDHE)",
		KexGOSTR341094: "GOST R 34.10-1994",
		KexGOSTR341001: "GOST R 34.10-2001",
		KexKRB5:        "Kerberos (KRB5)",
		KexNULL:        "NULL",
		KexPSK:         "Pre-Shared Keys (PSK)",
		KexRSA:         "RSA",
		KexSRP:         "Secure Remote Password (SRP)",
		KexSM2:         "ShangMi-2 (SM2)",
	}

	// PFSList is a map of key exchange algorithms which fall under the definition
	// of Perfect Forward Secrecy (PFS). Perfect Forward Secrecy (PFS) is a property
	// of secure communication protocols in which compromise of long-term keys does
	// not compromise past session keys.
	PFSList = map[KeyExchange]bool{
		KexDHE:   true,
		KexECDHE: true,
	}

	// NIST_SP_800_52KexList is oddly-named, but more understandable in this
	// format. As opposed to AEAD or PFS, the NIST SP 800-52 list requires
	// cipher suites which are a combination of cipher suites sections (key
	// exchange + auth sig + encryption + hash).
	//
	// See §3.3.1.1.1 Cipher Suites for ECDSA Certificates
	// See §3.3.1.1.2 Cipher Suites for RSA Certificates
	NIST_SP_800_52KexList = map[KeyExchange]bool{
		KexDHE:   true,
		KexECDHE: true,
	}
)
