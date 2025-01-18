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
	KexGOST256
	KexKRB5
	KexNULL
	KexPSK
	KexRSA
	KexSRP
	KexSM2
)

// KeyExchangeList is a map of key exchange algorithms to their human-readable names.
var KeyExchangeList = map[KeyExchange]string{
	KexNone:    "None",
	KexDH:      "Diffie-Hellman (Non-Ephemeral) (ECDH)",
	KexDHE:     "Diffie-Hellman (Ephemeral) (ECDHE)",
	KexECCPWD:  "ECCPWD",
	KexECDH:    "Elliptic Curve Diffie-Hellman (Non-Ephemeral) (ECDH)",
	KexECDHE:   "Elliptic Curve Diffie-Hellman (Ephemeral) (ECDHE)",
	KexGOST256: "Russian GOST 256-bit",
	KexKRB5:    "Kerberos (KRB5)",
	KexNULL:    "NULL",
	KexPSK:     "Pre-Shared Keys (PSK)",
	KexRSA:     "RSA",
	KexSRP:     "Secure Remote Password (SRP)",
	KexSM2:     "ShangMi-2 (SM2)",
}

// PFSList is a map of key exchange algorithms which fall under the definition
// of Perfect Forward Secrecy (PFS). Perfect Forward Secrecy (PFS) is a property
// of secure communication protocols in which compromise of long-term keys does
// not compromise past session keys.
var PFSList = map[KeyExchange]bool{
	KexDHE:   true,
	KexECDHE: true,
}
