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

// CipherData represents the data associated with a cipher suite.
type CipherData struct {
	// IANAName represents the official name of the cipher suite.
	IANAName string `json:"ianaName,omitempty"`

	// OpenSSLName represents the name of the cipher suite used by the
	// OpenSSL library.
	OpenSSLName string `json:"opensslName,omitempty"`

	// GNUTLSName represents the name of the cipher suite used by the
	// GNU-TLS library.
	GNUTLSName string `json:"gnutlsName,omitempty"`

	// URL is a link to the Cipher Suite's information page.
	URL string `json:"url,omitempty"`

	// Strength is a string representation of the strength of the cipher
	// suite.
	Strength string `json:"strength"`

	// KeyExchange is a string representation of the key exchange algorithm.
	KeyExchange string `json:"keyExchange"`

	// Authentication is a string representation of the key authentication
	// algorithm.
	Authentication string `json:"authentication"`

	// EncryptionAlgoisastring representation of the encryption
	// algorithm.
	EncryptionAlgo string `json:"encryption"`

	// Hash is a string representation of the hashing function.
	Hash string `json:"hash"`

	// IsPFS is a boolean indicating whether the cipher suite provides Perfect
	// Forward Secrecy.
	IsPFS bool `json:"isPFS"`

	// IsAEAD is a boolean indicating whether the cipher suite provides AEAD.
	IsAEAD bool `json:"isAEAD"`

	// IsNIST_SP_800_52 is a boolean indicating whether the cipher suite is
	// permitted by NIST SP 800-52.
	//
	// https://doi.org/10.6028/NIST.SP.800-52r2
	IsNIST_SP_800_52 bool `json:"isNISTSP80052"`

	// IsFIPS186 is a boolean indicating whether the cipher suite is permitted
	// by NIST FIPS 186 Digital Signature Standard.
	//
	// https://doi.org/10.6028/NIST.FIPS.186-5
	// https://doi.org/10.6028/NIST.SP.800-186
	IsFIPS186 bool `json:"isFIPS186"`

	// Private
	strength       CipherStrength
	keyExchange    KeyExchange
	authentication Signature
	encryptionAlgo EncryptionAlgo
	hash           Hash
}

// CipherList is a map of all IANA-identified cipher suites to their respective
// data. The blocks that are commented-out are the ones that are not supported
// by our underlying library.
//
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml is the
// official source for this information.
var CipherList = map[uint16]CipherData{
	0x0000: {
		IANAName: "TLS_NULL_WITH_NULL_NULL",

		strength:       StrengthInsecure,
		keyExchange:    KexNULL,
		authentication: SigNULL,
		encryptionAlgo: EncryptNULL,
		hash:           HashNULL,
	},
	0x0001: {
		IANAName:    "TLS_RSA_WITH_NULL_MD5",
		OpenSSLName: "NULL-MD5",
		GNUTLSName:  "TLS_RSA_NULL_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptNULL,
		hash:           HashMD5,
	},
	0x0002: {
		IANAName:    "TLS_RSA_WITH_NULL_SHA",
		OpenSSLName: "NULL-SHA",
		GNUTLSName:  "TLS_RSA_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0x0003: {
		IANAName: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC440,
		hash:           HashMD5,
	},
	0x0004: {
		IANAName:   "TLS_RSA_WITH_RC4_128_MD5",
		GNUTLSName: "TLS_RSA_ARCFOUR_128_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC4128,
		hash:           HashMD5,
	},
	0x0005: {
		IANAName:   "TLS_RSA_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_RSA_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0x0006: {
		IANAName: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC2CBC40,
		hash:           HashMD5,
	},
	0x0007: {
		IANAName:    "TLS_RSA_WITH_IDEA_CBC_SHA",
		OpenSSLName: "IDEA-CBC-SHA",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptIDEACBC,
		hash:           HashSHA1,
	},
	0x0008: {
		IANAName: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptDES40CBC,
		hash:           HashSHA1,
	},
	0x0009: {
		IANAName: "TLS_RSA_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x000A: {
		IANAName:    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "DES-CBC3-SHA",
		GNUTLSName:  "TLS_RSA_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x000B: {
		IANAName: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptDES40CBC,
		hash:           HashSHA1,
	},
	0x000C: {
		IANAName: "TLS_DH_DSS_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x000D: {
		IANAName: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x000E: {
		IANAName: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptDES40CBC,
		hash:           HashSHA1,
	},
	0x000F: {
		IANAName: "TLS_DH_RSA_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x0010: {
		IANAName: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x0011: {
		IANAName: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptDES40CBC,
		hash:           HashSHA1,
	},
	0x0012: {
		IANAName: "TLS_DHE_DSS_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x0013: {
		IANAName:    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "DHE-DSS-DES-CBC3-SHA",
		GNUTLSName:  "TLS_DHE_DSS_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x0014: {
		IANAName: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptDES40CBC,
		hash:           HashSHA1,
	},
	0x0015: {
		IANAName: "TLS_DHE_RSA_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x0016: {
		IANAName:    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "DHE-RSA-DES-CBC3-SHA",
		GNUTLSName:  "TLS_DHE_RSA_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x0017: {
		IANAName: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptRC440,
		hash:           HashMD5,
	},
	0x0018: {
		IANAName:   "TLS_DH_anon_WITH_RC4_128_MD5",
		GNUTLSName: "TLS_DH_ANON_ARCFOUR_128_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptRC4128,
		hash:           HashMD5,
	},
	0x0019: {
		IANAName: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptDES40CBC,
		hash:           HashSHA1,
	},
	0x001A: {
		IANAName: "TLS_DH_anon_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x001B: {
		IANAName:    "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "ADH-DES-CBC3-SHA",
		GNUTLSName:  "TLS_DH_ANON_3DES_EDE_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	// 0x001C-0x001D   Reserved to avoid conflicts with SSLv3
	0x001E: {
		IANAName: "TLS_KRB5_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x001F: {
		IANAName: "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x0020: {
		IANAName: "TLS_KRB5_WITH_RC4_128_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0x0021: {
		IANAName: "TLS_KRB5_WITH_IDEA_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptIDEACBC,
		hash:           HashSHA1,
	},
	0x0022: {
		IANAName: "TLS_KRB5_WITH_DES_CBC_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashMD5,
	},
	0x0023: {
		IANAName: "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashMD5,
	},
	0x0024: {
		IANAName: "TLS_KRB5_WITH_RC4_128_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptRC4128,
		hash:           HashMD5,
	},
	0x0025: {
		IANAName: "TLS_KRB5_WITH_IDEA_CBC_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptIDEACBC,
		hash:           HashMD5,
	},
	0x0026: {
		IANAName: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptDESCBC40,
		hash:           HashSHA1,
	},
	0x0027: {
		IANAName: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptRC2CBC40,
		hash:           HashSHA1,
	},
	0x0028: {
		IANAName: "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptRC440,
		hash:           HashSHA1,
	},
	0x0029: {
		IANAName: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptDESCBC40,
		hash:           HashMD5,
	},
	0x002A: {
		IANAName: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptRC2CBC40,
		hash:           HashMD5,
	},
	0x002B: {
		IANAName: "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexKRB5,
		authentication: SigKRB5,
		encryptionAlgo: EncryptRC440,
		hash:           HashMD5,
	},
	0x002C: {
		IANAName:    "TLS_PSK_WITH_NULL_SHA",
		OpenSSLName: "PSK-NULL-SHA",
		GNUTLSName:  "TLS_PSK_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0x002D: {
		IANAName:    "TLS_DHE_PSK_WITH_NULL_SHA",
		OpenSSLName: "DHE-PSK-NULL-SHA",
		GNUTLSName:  "TLS_DHE_PSK_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0x002E: {
		IANAName:    "TLS_RSA_PSK_WITH_NULL_SHA",
		OpenSSLName: "RSA-PSK-NULL-SHA",
		GNUTLSName:  "TLS_RSA_PSK_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0x002F: {
		IANAName:    "TLS_RSA_WITH_AES_128_CBC_SHA",
		OpenSSLName: "AES128-SHA",
		GNUTLSName:  "TLS_RSA_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0030: {
		IANAName: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0031: {
		IANAName: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0032: {
		IANAName:    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		OpenSSLName: "DHE-DSS-AES128-SHA",
		GNUTLSName:  "TLS_DHE_DSS_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0033: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		OpenSSLName: "DHE-RSA-AES128-SHA",
		GNUTLSName:  "TLS_DHE_RSA_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0034: {
		IANAName:    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
		OpenSSLName: "ADH-AES128-SHA",
		GNUTLSName:  "TLS_DH_ANON_AES_128_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0035: {
		IANAName:    "TLS_RSA_WITH_AES_256_CBC_SHA",
		OpenSSLName: "AES256-SHA",
		GNUTLSName:  "TLS_RSA_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x0036: {
		IANAName: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x0037: {
		IANAName: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x0038: {
		IANAName:    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		OpenSSLName: "DHE-DSS-AES256-SHA",
		GNUTLSName:  "TLS_DHE_DSS_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x0039: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		OpenSSLName: "DHE-RSA-AES256-SHA",
		GNUTLSName:  "TLS_DHE_RSA_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x003A: {
		IANAName:    "TLS_DH_anon_WITH_AES_256_CBC_SHA",
		OpenSSLName: "ADH-AES256-SHA",
		GNUTLSName:  "TLS_DH_ANON_AES_256_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x003B: {
		IANAName:    "TLS_RSA_WITH_NULL_SHA256",
		OpenSSLName: "NULL-SHA256",
		GNUTLSName:  "TLS_RSA_NULL_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA256,
	},
	0x003C: {
		IANAName:    "TLS_RSA_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "AES128-GCM-SHA256",
		GNUTLSName:  "TLS_RSA_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x003D: {
		IANAName:    "TLS_RSA_WITH_AES_256_CBC_SHA256",
		OpenSSLName: "AES256-SHA256",
		GNUTLSName:  "TLS_RSA_AES_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA256,
	},
	0x003E: {
		IANAName: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x003F: {
		IANAName: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x0040: {
		IANAName:    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "DHE-DSS-AES128-SHA256",
		GNUTLSName:  "TLS_DHE_DSS_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x0041: {
		IANAName:    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		OpenSSLName: "CAMELLIA128-SHA",
		GNUTLSName:  "TLS_RSA_CAMELLIA_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA1,
	},
	0x0042: {
		IANAName: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA1,
	},
	0x0043: {
		IANAName: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA1,
	},
	0x0044: {
		IANAName:    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
		OpenSSLName: "DHE-DSS-CAMELLIA128-SHA",
		GNUTLSName:  "TLS_DHE_DSS_CAMELLIA_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA1,
	},
	0x0045: {
		IANAName:    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		OpenSSLName: "DHE-RSA-CAMELLIA128-SHA",
		GNUTLSName:  "TLS_DHE_RSA_CAMELLIA_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA1,
	},
	0x0046: {
		IANAName:    "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
		OpenSSLName: "ADH-CAMELLIA128-SHA",
		GNUTLSName:  "TLS_DH_ANON_CAMELLIA_128_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA1,
	},
	// 0x0047-0x004F   Reserved to avoid conflicts with deployed implementations
	// 0x0050-0x0058   Reserved to avoid conflicts
	// 0x0059-0x005C   Reserved to avoid conflicts with deployed implementations
	// 0x005D-0x005F   Unassigned
	// 0x0060-0x0066   Reserved to avoid conflicts with widely deployed implementations
	0x0060: {
		// Unofficial, but (at one point) widely-deployed.
		IANAName: "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC456,
		hash:           HashMD5,
	},
	0x0061: {
		// Unofficial, but (at one point) widely-deployed.
		IANAName: "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC2CBC56,
		hash:           HashMD5,
	},
	0x0062: {
		// Unofficial, but (at one point) widely-deployed.
		IANAName: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x0063: {
		// Unofficial, but (at one point) widely-deployed.
		IANAName: "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptDESCBC,
		hash:           HashSHA1,
	},
	0x0064: {
		// Unofficial, but (at one point) widely-deployed.
		IANAName: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC456,
		hash:           HashSHA1,
	},
	0x0065: {
		// Unofficial, but (at one point) widely-deployed.
		IANAName: "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptRC456,
		hash:           HashSHA1,
	},
	0x0066: {
		// Unofficial, but (at one point) widely-deployed.
		IANAName: "TLS_DHE_DSS_WITH_RC4_128_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0x0067: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "DHE-RSA-AES128-SHA256",
		GNUTLSName:  "TLS_DHE_RSA_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x0068: {
		IANAName: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA256,
	},
	0x0069: {
		IANAName: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA256,
	},
	0x006A: {
		IANAName:    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		OpenSSLName: "DHE-DSS-AES256-SHA256",
		GNUTLSName:  "TLS_DHE_DSS_AES_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA256,
	},
	0x006B: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		OpenSSLName: "DHE-RSA-AES256-SHA256",
		GNUTLSName:  "TLS_DHE_RSA_AES_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA256,
	},
	0x006C: {
		IANAName:    "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "ADH-AES128-SHA256",
		GNUTLSName:  "TLS_DH_ANON_AES_128_CBC_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x006D: {
		IANAName:    "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
		OpenSSLName: "ADH-AES256-SHA256",
		GNUTLSName:  "TLS_DH_ANON_AES_256_CBC_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA256,
	},
	// 0x006E-0x0083   Unassigned
	0x0080: {
		// Unassigned
		IANAName:    "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
		OpenSSLName: "GOST94-GOST89-GOST89",

		strength:       StrengthInsecure,
		keyExchange:    KexGOSTR341094,
		authentication: SigGOSTR341094,
		encryptionAlgo: EncryptMagmaCTR,
		hash:           HashGOSTR,
	},
	0x0081: {
		// Unassigned
		IANAName:    "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
		OpenSSLName: "GOST2001-GOST89-GOST89",

		strength:       StrengthInsecure,
		keyExchange:    KexGOSTR341001,
		authentication: SigGOSTR341001,
		encryptionAlgo: EncryptMagmaCTR,
		hash:           HashGOSTR,
	},
	0x0082: {
		// Unassigned
		IANAName:    "TLS_GOSTR341094_WITH_NULL_GOSTR3411",
		OpenSSLName: "GOST94-NULL-GOST94",

		strength:       StrengthInsecure,
		keyExchange:    KexGOSTR341094,
		authentication: SigGOSTR341094,
		encryptionAlgo: EncryptNULL,
		hash:           HashGOSTR,
	},
	0x0083: {
		// Unassigned
		IANAName:    "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
		OpenSSLName: "GOST2001-NULL-GOST94",

		strength:       StrengthInsecure,
		keyExchange:    KexGOSTR341001,
		authentication: SigGOSTR341001,
		encryptionAlgo: EncryptNULL,
		hash:           HashGOSTR,
	},
	0x0084: {
		IANAName:    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		OpenSSLName: "CAMELLIA256-SHA",
		GNUTLSName:  "TLS_RSA_CAMELLIA_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA1,
	},
	0x0085: {
		IANAName: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA1,
	},
	0x0086: {
		IANAName: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA1,
	},
	0x0087: {
		IANAName:    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
		OpenSSLName: "DHE-DSS-CAMELLIA256-SHA",
		GNUTLSName:  "TLS_DHE_DSS_CAMELLIA_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA1,
	},
	0x0088: {
		IANAName:    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
		OpenSSLName: "DHE-RSA-CAMELLIA256-SHA",
		GNUTLSName:  "TLS_DHE_RSA_CAMELLIA_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA1,
	},
	0x0089: {
		IANAName:    "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
		OpenSSLName: "ADH-CAMELLIA256-SHA",
		GNUTLSName:  "TLS_DH_ANON_CAMELLIA_256_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA1,
	},
	0x008A: {
		IANAName:   "TLS_PSK_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_PSK_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0x008B: {
		IANAName:    "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "PSK-3DES-EDE-CBC-SHA",
		GNUTLSName:  "TLS_PSK_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x008C: {
		IANAName:    "TLS_PSK_WITH_AES_128_CBC_SHA",
		OpenSSLName: "PSK-AES128-CBC-SHA",
		GNUTLSName:  "TLS_PSK_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x008D: {
		IANAName:    "TLS_PSK_WITH_AES_256_CBC_SHA",
		OpenSSLName: "PSK-AES256-CBC-SHA",
		GNUTLSName:  "TLS_PSK_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x008E: {
		IANAName:   "TLS_DHE_PSK_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_DHE_PSK_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0x008F: {
		IANAName:    "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "DHE-PSK-3DES-EDE-CBC-SHA",
		GNUTLSName:  "TLS_DHE_PSK_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x0090: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
		OpenSSLName: "DHE-PSK-AES128-CBC-SHA",
		GNUTLSName:  "TLS_DHE_PSK_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0091: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
		OpenSSLName: "DHE-PSK-AES256-CBC-SHA",
		GNUTLSName:  "TLS_DHE_PSK_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x0092: {
		IANAName:   "TLS_RSA_PSK_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_RSA_PSK_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0x0093: {
		IANAName:    "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "RSA-PSK-3DES-EDE-CBC-SHA",
		GNUTLSName:  "TLS_RSA_PSK_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0x0094: {
		IANAName:    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
		OpenSSLName: "RSA-PSK-AES128-CBC-SHA",
		GNUTLSName:  "TLS_RSA_PSK_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0x0095: {
		IANAName:    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
		OpenSSLName: "RSA-PSK-AES256-CBC-SHA",
		GNUTLSName:  "TLS_RSA_PSK_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0x0096: {
		IANAName:    "TLS_RSA_WITH_SEED_CBC_SHA",
		OpenSSLName: "SEED-SHA",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptSEEDCBC,
		hash:           HashSHA1,
	},
	0x0097: {
		IANAName: "TLS_DH_DSS_WITH_SEED_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptSEEDCBC,
		hash:           HashSHA1,
	},
	0x0098: {
		IANAName: "TLS_DH_RSA_WITH_SEED_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptSEEDCBC,
		hash:           HashSHA1,
	},
	0x0099: {
		IANAName:    "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
		OpenSSLName: "DHE-DSS-SEED-SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptSEEDCBC,
		hash:           HashSHA1,
	},
	0x009A: {
		IANAName:    "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
		OpenSSLName: "DHE-RSA-SEED-SHA",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptSEEDCBC,
		hash:           HashSHA1,
	},
	0x009B: {
		IANAName:    "TLS_DH_anon_WITH_SEED_CBC_SHA",
		OpenSSLName: "ADH-SEED-SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptSEEDCBC,
		hash:           HashSHA1,
	},
	0x009C: {
		IANAName:    "TLS_RSA_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "AES128-GCM-SHA256",
		GNUTLSName:  "TLS_RSA_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x009D: {
		IANAName:    "TLS_RSA_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "AES256-GCM-SHA384",
		GNUTLSName:  "TLS_RSA_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x009E: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "DHE-RSA-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_DHE_RSA_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x009F: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "DHE-RSA-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_DHE_RSA_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00A0: {
		IANAName: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x00A1: {
		IANAName: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00A2: {
		IANAName:    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "DHE-DSS-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_DHE_DSS_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x00A3: {
		IANAName:    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "DHE-DSS-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_DHE_DSS_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00A4: {
		IANAName: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x00A5: {
		IANAName: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00A6: {
		IANAName:    "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "ADH-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_DH_ANON_AES_128_GCM_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x00A7: {
		IANAName:    "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "ADH-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_DH_ANON_AES_256_GCM_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00A8: {
		IANAName:    "TLS_PSK_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "PSK-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_PSK_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x00A9: {
		IANAName:    "TLS_PSK_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "PSK-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_PSK_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00AA: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "DHE-PSK-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_DHE_PSK_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x00AB: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "DHE-PSK-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_DHE_PSK_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00AC: {
		IANAName:    "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "RSA-PSK-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_RSA_PSK_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x00AD: {
		IANAName:    "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "RSA-PSK-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_RSA_PSK_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x00AE: {
		IANAName:    "TLS_PSK_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "PSK-AES128-CBC-SHA256",
		GNUTLSName:  "TLS_PSK_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x00AF: {
		IANAName:    "TLS_PSK_WITH_AES_256_CBC_SHA384",
		OpenSSLName: "PSK-AES256-CBC-SHA384",
		GNUTLSName:  "TLS_PSK_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0x00B0: {
		IANAName:    "TLS_PSK_WITH_NULL_SHA256",
		OpenSSLName: "PSK-NULL-SHA256",
		GNUTLSName:  "TLS_PSK_NULL_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA256,
	},
	0x00B1: {
		IANAName:    "TLS_PSK_WITH_NULL_SHA384",
		OpenSSLName: "PSK-NULL-SHA384",
		GNUTLSName:  "TLS_PSK_NULL_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA384,
	},
	0x00B2: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "DHE-PSK-AES128-CBC-SHA256",
		GNUTLSName:  "TLS_DHE_PSK_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x00B3: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
		OpenSSLName: "DHE-PSK-AES256-CBC-SHA384",
		GNUTLSName:  "TLS_DHE_PSK_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0x00B4: {
		IANAName:    "TLS_DHE_PSK_WITH_NULL_SHA256",
		OpenSSLName: "DHE-PSK-NULL-SHA256",
		GNUTLSName:  "TLS_DHE_PSK_NULL_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA256,
	},
	0x00B5: {
		IANAName:    "TLS_DHE_PSK_WITH_NULL_SHA384",
		OpenSSLName: "DHE-PSK-NULL-SHA384",
		GNUTLSName:  "TLS_DHE_PSK_NULL_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA384,
	},
	0x00B6: {
		IANAName:    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "RSA-PSK-AES128-CBC-SHA256",
		GNUTLSName:  "TLS_RSA_PSK_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0x00B7: {
		IANAName:    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
		OpenSSLName: "RSA-PSK-AES256-CBC-SHA384",
		GNUTLSName:  "TLS_RSA_PSK_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0x00B8: {
		IANAName:    "TLS_RSA_PSK_WITH_NULL_SHA256",
		OpenSSLName: "RSA-PSK-NULL-SHA256",
		GNUTLSName:  "TLS_RSA_PSK_NULL_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA256,
	},
	0x00B9: {
		IANAName:    "TLS_RSA_PSK_WITH_NULL_SHA384",
		OpenSSLName: "RSA-PSK-NULL-SHA384",
		GNUTLSName:  "TLS_RSA_PSK_NULL_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA384,
	},
	0x00BA: {
		IANAName:    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_RSA_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0x00BB: {
		IANAName: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0x00BC: {
		IANAName: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0x00BD: {
		IANAName:    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "DHE-DSS-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_DHE_DSS_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0x00BE: {
		IANAName:    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "DHE-RSA-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_DHE_RSA_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0x00BF: {
		IANAName:    "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "ADH-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_DH_ANON_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0x00C0: {
		IANAName:    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		OpenSSLName: "CAMELLIA256-SHA256",
		GNUTLSName:  "TLS_RSA_CAMELLIA_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA256,
	},
	0x00C1: {
		IANAName: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA256,
	},
	0x00C2: {
		IANAName: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA256,
	},
	0x00C3: {
		IANAName:    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		OpenSSLName: "DHE-DSS-CAMELLIA256-SHA256",
		GNUTLSName:  "TLS_DHE_DSS_CAMELLIA_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA256,
	},
	0x00C4: {
		IANAName:    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		OpenSSLName: "DHE-RSA-CAMELLIA256-SHA256",
		GNUTLSName:  "TLS_DHE_RSA_CAMELLIA_256_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA256,
	},
	0x00C5: {
		IANAName:    "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
		OpenSSLName: "ADH-CAMELLIA256-SHA256",
		GNUTLSName:  "TLS_DH_ANON_CAMELLIA_256_CBC_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA256,
	},
	0x00C6: {
		IANAName: "TLS_SM4_GCM_SM3",

		strength:       StrengthInsecure,
		keyExchange:    KexSM2,
		authentication: SigSM2,
		encryptionAlgo: EncryptSM4GCM,
		hash:           HashSM3,
	},
	0x00C7: {
		IANAName: "TLS_SM4_CCM_SM3",

		strength:       StrengthInsecure,
		keyExchange:    KexSM2,
		authentication: SigSM2,
		encryptionAlgo: EncryptSM4CCM,
		hash:           HashSM3,
	},
	// 0x00C8-0x00FE   Unassigned
	0x00FF: {IANAName: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"}, // TLS_RENEGO_PROTECTION_REQUEST
	// 0x0100-0x0900   Unassigned
	// 0x0A00-0x0A09   Unassigned
	// 0x0A0A          Reserved
	// 0x0A0B-0x0AFF   Unassigned
	// 0x0B00-0x12FF   Unassigned
	// 0x1300          Unassigned
	0x1301: {
		IANAName:    "TLS_AES_128_GCM_SHA256",
		OpenSSLName: "TLS_AES_128_GCM_SHA256",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0x1302: {
		IANAName:    "TLS_AES_256_GCM_SHA384",
		OpenSSLName: "TLS_AES_256_GCM_SHA384",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0x1303: {
		IANAName: "TLS_CHACHA20_POLY1305_SHA256",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptChaChaPoly,
		hash:           HashSHA256,
	},
	// 0x1304: {
	// 	IANAName:    "TLS_AES_128_CCM_SHA256",
	// 	OpenSSLName: "TLS_AES_128_CCM_SHA256",

	// 	strength:       StrengthSecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigECDSA,
	// 	encryptionAlgo: EncryptAES128CCM,
	// 	hash:           HashSHA256,
	// },
	// 0x1305: {
	// 	IANAName: "TLS_AES_128_CCM_8_SHA256",

	// 	strength:       StrengthSecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigECDSA,
	// 	encryptionAlgo: EncryptAES128CCM8,
	// 	hash:           HashSHA256,
	// },
	// 0x1306: {IANAName: "TLS_AEGIS_256_SHA512"},
	// 0x1307: {IANAName: "TLS_AEGIS_128L_SHA256"},
	// 0x1308-0x13FF   Unassigned
	// 0x1400-0x19FF   Unassigned
	// 0x1A00-0x1A19   Unassigned
	// 0x1A1A          Reserved
	// 0x1A1B-0x1AFF   Unassigned
	// 0x1B00-0x29FF   Unassigned
	// 0x2A00-0x2A29   Unassigned
	// 0x2A2A          Reserved
	// 0x2A2B-0x2AFF   Unassigned
	// 0x2B00-0x39FF   Unassigned
	// 0x3A00-0x3A39   Unassigned
	// 0x3A3A          Reserved
	// 0x3A3B-0x3AFF   Unassigned
	// 0x3B00-0x49FF   Unassigned
	// 0x4A00-0x4A49   Unassigned
	// 0x4A4A          Reserved
	// 0x4A4B-0x4AFF   Unassigned
	// 0x4B00-0x55FF   Unassigned
	0x5600: {IANAName: "TLS_FALLBACK_SCSV"},
	// 0x5601-0x56FF   Unassigned
	// 0x5700-0x59FF   Unassigned
	// 0x5A00-0x5A59   Unassigned
	// 0x5A5A          Reserved
	// 0x5A5B-0x5AFF   Unassigned
	// 0x5B00-0x69FF   Unassigned
	// 0x6A00-0x6A69   Unassigned
	// 0x6A6A          Reserved
	// 0x6A6B-0x6AFF   Unassigned
	// 0x6B00-0x79FF   Unassigned
	// 0x7A00-0x7A79   Unassigned
	// 0x7A7A          Reserved
	// 0x7A7B-0x7AFF   Unassigned
	// 0x7B00-0x89FF   Unassigned
	// 0x8A00-0x8A89   Unassigned
	// 0x8A8A          Reserved
	// 0x8A8B-0x8AFF   Unassigned
	// 0x8B00-0x99FF   Unassigned
	// 0x9A00-0x9A99   Unassigned
	// 0x9A9A          Reserved
	// 0x9A9B-0x9AFF   Unassigned
	// 0x9B00-0xA9FF   Unassigned
	// 0xAA00-0xAAA9   Unassigned
	// 0xAAAA          Reserved
	// 0xAAAB-0xAAFF   Unassigned
	// 0xAB00-0xB9FF   Unassigned
	// 0xBA00-0xBAB9   Unassigned
	// 0xBABA          Reserved
	// 0xBABB-0xBAFF   Unassigned
	// 0xBB00-0xBFFF   Unassigned
	// 0xC000          Unassigned
	0xC001: {
		IANAName: "TLS_ECDH_ECDSA_WITH_NULL_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0xC002: {
		IANAName: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0xC003: {
		IANAName: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC004: {
		IANAName: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC005: {
		IANAName: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC006: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
		OpenSSLName: "ECDHE-ECDSA-NULL-SHA",
		GNUTLSName:  "TLS_ECDHE_ECDSA_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0xC007: {
		IANAName:   "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_ECDHE_ECDSA_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0xC008: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "ECDHE-ECDSA-DES-CBC3-SHA",
		GNUTLSName:  "TLS_ECDHE_ECDSA_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC009: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		OpenSSLName: "ECDHE-ECDSA-AES128-SHA",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC00A: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		OpenSSLName: "ECDHE-ECDSA-AES256-SHA",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC00B: {
		IANAName: "TLS_ECDH_RSA_WITH_NULL_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0xC00C: {
		IANAName: "TLS_ECDH_RSA_WITH_RC4_128_SHA",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0xC00D: {
		IANAName: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC00E: {
		IANAName: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC00F: {
		IANAName: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC010: {
		IANAName:    "TLS_ECDHE_RSA_WITH_NULL_SHA",
		OpenSSLName: "ECDHE-RSA-NULL-SHA",
		GNUTLSName:  "TLS_ECDHE_RSA_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0xC011: {
		IANAName:   "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_ECDHE_RSA_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0xC012: {
		IANAName:    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "DES-CBC3-SHA",
		GNUTLSName:  "TLS_RSA_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC013: {
		IANAName:    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		OpenSSLName: "ECDHE-RSA-AES128-SHA",
		GNUTLSName:  "TLS_ECDHE_RSA_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC014: {
		IANAName:    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		OpenSSLName: "ECDHE-RSA-AES256-SHA",
		GNUTLSName:  "TLS_ECDHE_RSA_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC015: {
		IANAName:    "TLS_ECDH_anon_WITH_NULL_SHA",
		OpenSSLName: "AECDH-NULL-SHA",
		GNUTLSName:  "TLS_ECDH_ANON_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0xC016: {
		IANAName:   "TLS_ECDH_anon_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_ECDH_ANON_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0xC017: {
		IANAName:    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "AECDH-DES-CBC3-SHA",
		GNUTLSName:  "TLS_ECDH_ANON_3DES_EDE_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigAnonymous,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC018: {
		IANAName:    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
		OpenSSLName: "AECDH-AES128-SHA",
		GNUTLSName:  "TLS_ECDH_ANON_AES_128_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC019: {
		IANAName:    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
		OpenSSLName: "AECDH-AES256-SHA",
		GNUTLSName:  "TLS_ECDH_ANON_AES_256_CBC_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC01A: {
		IANAName:    "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "SRP-3DES-EDE-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC01B: {
		IANAName:    "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "SRP-RSA-3DES-EDE-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1RSA,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC01C: {
		IANAName:    "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "SRP-DSS-3DES-EDE-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1DSS,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC01D: {
		IANAName:    "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
		OpenSSLName: "SRP-AES-128-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC01E: {
		IANAName:    "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
		OpenSSLName: "SRP-RSA-AES-128-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_RSA_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1RSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC01F: {
		IANAName:    "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
		OpenSSLName: "SRP-DSS-AES-128-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_DSS_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1DSS,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC020: {
		IANAName:    "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
		OpenSSLName: "SRP-AES-256-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC021: {
		IANAName:    "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
		OpenSSLName: "SRP-RSA-AES-256-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_RSA_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1RSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC022: {
		IANAName:    "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
		OpenSSLName: "SRP-DSS-AES-256-CBC-SHA",
		GNUTLSName:  "TLS_SRP_SHA_DSS_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexSRP,
		authentication: SigSHA1DSS,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC023: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "ECDHE-ECDSA-AES128-SHA256",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0xC024: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		OpenSSLName: "ECDHE-ECDSA-AES256-SHA384",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0xC025: {
		IANAName: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0xC026: {
		IANAName: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0xC027: {
		IANAName:    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "ECDHE-RSA-AES128-SHA256",
		GNUTLSName:  "TLS_ECDHE_RSA_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0xC028: {
		IANAName:    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		OpenSSLName: "ECDHE-RSA-AES256-SHA384",
		GNUTLSName:  "TLS_ECDHE_RSA_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0xC029: {
		IANAName: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0xC02A: {
		IANAName: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0xC02B: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "ECDHE-ECDSA-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_128_GCM_SHA256",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0xC02C: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "ECDHE-ECDSA-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_256_GCM_SHA384",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0xC02D: {
		IANAName: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0xC02E: {
		IANAName: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0xC02F: {
		IANAName:    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		OpenSSLName: "ECDHE-RSA-AES128-GCM-SHA256",
		GNUTLSName:  "TLS_ECDHE_RSA_AES_128_GCM_SHA256",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0xC030: {
		IANAName:    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		OpenSSLName: "ECDHE-RSA-AES256-GCM-SHA384",
		GNUTLSName:  "TLS_ECDHE_RSA_AES_256_GCM_SHA384",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0xC031: {
		IANAName: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	0xC032: {
		IANAName: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256GCM,
		hash:           HashSHA384,
	},
	0xC033: {
		IANAName:   "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
		GNUTLSName: "TLS_ECDHE_PSK_ARCFOUR_128_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptRC4128,
		hash:           HashSHA1,
	},
	0xC034: {
		IANAName:    "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
		OpenSSLName: "ECDHE-PSK-3DES-EDE-CBC-SHA",
		GNUTLSName:  "TLS_ECDHE_PSK_3DES_EDE_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: Encrypt3DESEDECBC,
		hash:           HashSHA1,
	},
	0xC035: {
		IANAName:    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
		OpenSSLName: "ECDHE-PSK-AES128-CBC-SHA",
		GNUTLSName:  "TLS_ECDHE_PSK_AES_128_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA1,
	},
	0xC036: {
		IANAName:    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
		OpenSSLName: "ECDHE-PSK-AES256-CBC-SHA",
		GNUTLSName:  "TLS_ECDHE_PSK_AES_256_CBC_SHA1",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA1,
	},
	0xC037: {
		IANAName:    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
		OpenSSLName: "ECDHE-PSK-AES128-CBC-SHA256",
		GNUTLSName:  "TLS_ECDHE_PSK_AES_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CBC,
		hash:           HashSHA256,
	},
	0xC038: {
		IANAName:    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
		OpenSSLName: "ECDHE-PSK-AES256-CBC-SHA384",
		GNUTLSName:  "TLS_ECDHE_PSK_AES_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CBC,
		hash:           HashSHA384,
	},
	0xC039: {
		IANAName:    "TLS_ECDHE_PSK_WITH_NULL_SHA",
		OpenSSLName: "ECDHE-PSK-NULL-SHA",
		GNUTLSName:  "TLS_ECDHE_PSK_NULL_SHA1",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA1,
	},
	0xC03A: {
		IANAName:    "TLS_ECDHE_PSK_WITH_NULL_SHA256",
		OpenSSLName: "ECDHE-PSK-NULL-SHA256",
		GNUTLSName:  "TLS_ECDHE_PSK_NULL_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA256,
	},
	0xC03B: {
		IANAName:    "TLS_ECDHE_PSK_WITH_NULL_SHA384",
		OpenSSLName: "ECDHE-PSK-NULL-SHA384",
		GNUTLSName:  "TLS_ECDHE_PSK_NULL_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptNULL,
		hash:           HashSHA384,
	},
	0xC03C: {
		IANAName: "TLS_RSA_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC03D: {
		IANAName: "TLS_RSA_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC03E: {
		IANAName: "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC03F: {
		IANAName: "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC040: {
		IANAName: "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC041: {
		IANAName: "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC042: {
		IANAName: "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC043: {
		IANAName: "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC044: {
		IANAName: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC045: {
		IANAName: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC046: {
		IANAName: "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC047: {
		IANAName: "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC048: {
		IANAName: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC049: {
		IANAName: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC04A: {
		IANAName: "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC04B: {
		IANAName: "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC04C: {
		IANAName: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC04D: {
		IANAName: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC04E: {
		IANAName: "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC04F: {
		IANAName: "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC050: {
		IANAName: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC051: {
		IANAName: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC052: {
		IANAName: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC053: {
		IANAName: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC054: {
		IANAName: "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC055: {
		IANAName: "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC056: {
		IANAName: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC057: {
		IANAName: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC058: {
		IANAName: "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC059: {
		IANAName: "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC05A: {
		IANAName: "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC05B: {
		IANAName: "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC05C: {
		IANAName: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC05D: {
		IANAName: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC05E: {
		IANAName: "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC05F: {
		IANAName: "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC060: {
		IANAName: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC061: {
		IANAName: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC062: {
		IANAName: "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC063: {
		IANAName: "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC064: {
		IANAName: "TLS_PSK_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC065: {
		IANAName: "TLS_PSK_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC066: {
		IANAName: "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC067: {
		IANAName: "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC068: {
		IANAName: "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC069: {
		IANAName: "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC06A: {
		IANAName: "TLS_PSK_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC06B: {
		IANAName: "TLS_PSK_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC06C: {
		IANAName: "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC06D: {
		IANAName: "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC06E: {
		IANAName: "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA128GCM,
		hash:           HashSHA256,
	},
	0xC06F: {
		IANAName: "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA256GCM,
		hash:           HashSHA384,
	},
	0xC070: {
		IANAName: "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA128CBC,
		hash:           HashSHA256,
	},
	0xC071: {
		IANAName: "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptARIA256CBC,
		hash:           HashSHA384,
	},
	0xC072: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "ECDHE-ECDSA-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_ECDHE_ECDSA_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC073: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		OpenSSLName: "ECDHE-ECDSA-CAMELLIA256-SHA384",
		GNUTLSName:  "TLS_ECDHE_ECDSA_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC074: {
		IANAName: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC075: {
		IANAName: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC076: {
		IANAName:    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "ECDHE-RSA-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_ECDHE_RSA_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC077: {
		IANAName:    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		OpenSSLName: "ECDHE-RSA-CAMELLIA256-SHA384",
		GNUTLSName:  "TLS_ECDHE_RSA_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC078: {
		IANAName: "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC079: {
		IANAName: "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC07A: {
		IANAName:   "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_RSA_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC07B: {
		IANAName:   "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_RSA_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC07C: {
		IANAName:   "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_DHE_RSA_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC07D: {
		IANAName:   "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_DHE_RSA_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC07E: {
		IANAName: "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC07F: {
		IANAName: "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC080: {
		IANAName:   "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_DHE_DSS_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC081: {
		IANAName:   "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_DHE_DSS_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC082: {
		IANAName: "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC083: {
		IANAName: "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDH,
		authentication: SigDSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC084: {
		IANAName:   "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_DH_ANON_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC085: {
		IANAName:   "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_DH_ANON_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthInsecure,
		keyExchange:    KexDH,
		authentication: SigAnonymous,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC086: {
		IANAName:   "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_ECDHE_ECDSA_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC087: {
		IANAName:   "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_ECDHE_ECDSA_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC088: {
		IANAName: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC089: {
		IANAName: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigECDSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC08A: {
		IANAName:   "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_ECDHE_RSA_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC08B: {
		IANAName:   "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_ECDHE_RSA_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC08C: {
		IANAName: "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC08D: {
		IANAName: "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDH,
		authentication: SigRSA,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC08E: {
		IANAName:   "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_PSK_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC08F: {
		IANAName:   "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_PSK_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC090: {
		IANAName:   "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_DHE_PSK_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC091: {
		IANAName:   "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_DHE_PSK_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC092: {
		IANAName:   "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		GNUTLSName: "TLS_RSA_PSK_CAMELLIA_128_GCM_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia128GCM,
		hash:           HashSHA256,
	},
	0xC093: {
		IANAName:   "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		GNUTLSName: "TLS_RSA_PSK_CAMELLIA_256_GCM_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia256GCM,
		hash:           HashSHA384,
	},
	0xC094: {
		IANAName:    "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "PSK-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_PSK_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC095: {
		IANAName:    "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		OpenSSLName: "PSK-CAMELLIA256-SHA384",
		GNUTLSName:  "TLS_PSK_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC096: {
		IANAName:    "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "DHE-PSK-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_DHE_PSK_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC097: {
		IANAName:    "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		OpenSSLName: "DHE-PSK-CAMELLIA256-SHA384",
		GNUTLSName:  "TLS_DHE_PSK_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC098: {
		IANAName:    "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "RSA-PSK-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_RSA_PSK_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC099: {
		IANAName:    "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		OpenSSLName: "RSA-PSK-CAMELLIA256-SHA384",
		GNUTLSName:  "TLS_RSA_PSK_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC09A: {
		IANAName:    "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		OpenSSLName: "ECDHE-PSK-CAMELLIA128-SHA256",
		GNUTLSName:  "TLS_ECDHE_PSK_CAMELLIA_128_CBC_SHA256",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia128CBC,
		hash:           HashSHA256,
	},
	0xC09B: {
		IANAName:    "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		OpenSSLName: "ECDHE-PSK-CAMELLIA256-SHA384",
		GNUTLSName:  "TLS_ECDHE_PSK_CAMELLIA_256_CBC_SHA384",

		strength:       StrengthWeak,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptCamellia256CBC,
		hash:           HashSHA384,
	},
	0xC09C: {
		IANAName:    "TLS_RSA_WITH_AES_128_CCM",
		OpenSSLName: "AES128-CCM",
		GNUTLSName:  "TLS_RSA_AES_128_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CCM,
		hash:           HashSHA256,
	},
	0xC09D: {
		IANAName:    "TLS_RSA_WITH_AES_256_CCM",
		OpenSSLName: "AES256-CCM",
		GNUTLSName:  "TLS_RSA_AES_256_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CCM,
		hash:           HashSHA256,
	},
	0xC09E: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_128_CCM",
		OpenSSLName: "DHE-RSA-AES128-CCM",
		GNUTLSName:  "TLS_DHE_RSA_AES_128_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CCM,
		hash:           HashSHA256,
	},
	0xC09F: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_256_CCM",
		OpenSSLName: "DHE-RSA-AES256-CCM",
		GNUTLSName:  "TLS_DHE_RSA_AES_256_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CCM,
		hash:           HashSHA256,
	},
	0xC0A0: {
		IANAName:    "TLS_RSA_WITH_AES_128_CCM_8",
		OpenSSLName: "AES128-CCM8",
		GNUTLSName:  "TLS_RSA_AES_128_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CCM8,
		hash:           HashSHA256,
	},
	0xC0A1: {
		IANAName:    "TLS_RSA_WITH_AES_256_CCM_8",
		OpenSSLName: "AES256-CCM8",
		GNUTLSName:  "TLS_RSA_AES_256_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexRSA,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CCM8,
		hash:           HashSHA256,
	},
	0xC0A2: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_128_CCM_8",
		OpenSSLName: "DHE-RSA-AES128-CCM8",
		GNUTLSName:  "TLS_DHE_RSA_AES_128_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES128CCM8,
		hash:           HashSHA256,
	},
	0xC0A3: {
		IANAName:    "TLS_DHE_RSA_WITH_AES_256_CCM_8",
		OpenSSLName: "DHE-RSA-AES256-CCM8",
		GNUTLSName:  "TLS_DHE_RSA_AES_256_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptAES256CCM8,
		hash:           HashSHA256,
	},
	0xC0A4: {
		IANAName:    "TLS_PSK_WITH_AES_128_CCM",
		OpenSSLName: "PSK-AES128-CCM",
		GNUTLSName:  "TLS_PSK_AES_128_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CCM,
		hash:           HashSHA256,
	},
	0xC0A5: {
		IANAName:    "TLS_PSK_WITH_AES_256_CCM",
		OpenSSLName: "PSK-AES256-CCM",
		GNUTLSName:  "TLS_PSK_AES_256_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CCM,
		hash:           HashSHA256,
	},
	0xC0A6: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_128_CCM",
		OpenSSLName: "DHE-PSK-AES128-CCM",
		GNUTLSName:  "TLS_DHE_PSK_AES_128_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CCM,
		hash:           HashSHA256,
	},
	0xC0A7: {
		IANAName:    "TLS_DHE_PSK_WITH_AES_256_CCM",
		OpenSSLName: "DHE-PSK-AES256-CCM",
		GNUTLSName:  "TLS_DHE_PSK_AES_256_CCM",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CCM,
		hash:           HashSHA256,
	},
	0xC0A8: {
		IANAName:    "TLS_PSK_WITH_AES_128_CCM_8",
		OpenSSLName: "PSK-AES128-CCM8",
		GNUTLSName:  "TLS_PSK_AES_128_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CCM8,
		hash:           HashSHA256,
	},
	0xC0A9: {
		IANAName:    "TLS_PSK_WITH_AES_256_CCM_8",
		OpenSSLName: "PSK-AES256-CCM8",
		GNUTLSName:  "TLS_PSK_AES_256_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexPSK,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CCM8,
		hash:           HashSHA256,
	},
	0xC0AA: {
		IANAName:    "TLS_PSK_DHE_WITH_AES_128_CCM_8",
		OpenSSLName: "DHE-PSK-AES128-CCM8",
		GNUTLSName:  "TLS_DHE_PSK_AES_128_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128CCM8,
		hash:           HashSHA256,
	},
	0xC0AB: {
		IANAName:    "TLS_PSK_DHE_WITH_AES_256_CCM_8",
		OpenSSLName: "DHE-PSK-AES256-CCM8",
		GNUTLSName:  "TLS_DHE_PSK_AES_256_CCM_8",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES256CCM8,
		hash:           HashSHA256,
	},
	0xC0AC: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
		OpenSSLName: "ECDHE-ECDSA-AES128-CCM",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_128_CCM",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128CCM,
		hash:           HashSHA256,
	},
	0xC0AD: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
		OpenSSLName: "ECDHE-ECDSA-AES256-CCM",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_256_CCM",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256CCM,
		hash:           HashSHA256,
	},
	0xC0AE: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
		OpenSSLName: "ECDHE-ECDSA-AES128-CCM8",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_128_CCM_8",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES128CCM8,
		hash:           HashSHA256,
	},
	0xC0AF: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
		OpenSSLName: "ECDHE-ECDSA-AES256-CCM8",
		GNUTLSName:  "TLS_ECDHE_ECDSA_AES_256_CCM_8",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptAES256CCM8,
		hash:           HashSHA256,
	},
	// 0xC0B0: {
	// 	IANAName: "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",

	// 	strength:       StrengthRecommended,
	// 	keyExchange:    KexECCPWD,
	// 	authentication: SigECCPWD,
	// 	encryptionAlgo: EncryptAES128GCM,
	// 	hash:           HashSHA256,
	// },
	// 0xC0B1: {
	// 	IANAName: "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",

	// 	strength:       StrengthRecommended,
	// 	keyExchange:    KexECCPWD,
	// 	authentication: SigECCPWD,
	// 	encryptionAlgo: EncryptAES256GCM,
	// 	hash:           HashSHA384,
	// },
	// 0xC0B2: {
	// 	IANAName: "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",

	// 	strength:       StrengthSecure,
	// 	keyExchange:    KexECCPWD,
	// 	authentication: SigECCPWD,
	// 	encryptionAlgo: EncryptAES128CCM,
	// 	hash:           HashSHA256,
	// },
	// 0xC0B3: {
	// 	IANAName: "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",

	// 	strength:       StrengthSecure,
	// 	keyExchange:    KexECCPWD,
	// 	authentication: SigECCPWD,
	// 	encryptionAlgo: EncryptAES256CCM,
	// 	hash:           HashSHA384,
	// },
	// 0xC0B4: {
	// 	IANAName: "TLS_SHA256_SHA256",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexNone,
	// 	authentication: SigSHA256,
	// 	encryptionAlgo: EncryptNULL,
	// 	hash:           HashSHA256,
	// },
	// 0xC0B5: {
	// 	IANAName: "TLS_SHA384_SHA384",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexNone,
	// 	authentication: SigSHA384,
	// 	encryptionAlgo: EncryptNULL,
	// 	hash:           HashSHA384,
	// },
	// 0xC0B6-0xC0FF   Unassigned
	// 0xC100: {
	// 	IANAName: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexGOST256,
	// 	authentication: SigGOST256,
	// 	encryptionAlgo: EncryptKuznyechikCTR,
	// 	hash:           HashGOSTR,
	// },
	// 0xC101: {
	// 	IANAName: "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexGOST256,
	// 	authentication: SigGOST256,
	// 	encryptionAlgo: EncryptMagmaCTR,
	// 	hash:           HashGOSTR,
	// },
	// 0xC102: {
	// 	IANAName: "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexGOST256,
	// 	authentication: SigGOST256,
	// 	encryptionAlgo: Encrypt28147CNT,
	// 	hash:           HashGOSTR,
	// },
	// 0xC103: {
	// 	IANAName: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigNULL,
	// 	encryptionAlgo: EncryptKuznyechikMGML,
	// 	hash:           HashNone,
	// },
	// 0xC104: {
	// 	IANAName: "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigNULL,
	// 	encryptionAlgo: EncryptMagmaMGML,
	// 	hash:           HashNone,
	// },
	// 0xC105: {
	// 	IANAName: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigNULL,
	// 	encryptionAlgo: EncryptKuznyechikMGMS,
	// 	hash:           HashNone,
	// },
	// 0xC106: {
	// 	IANAName: "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",

	// 	strength:       StrengthInsecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigNULL,
	// 	encryptionAlgo: EncryptMagmaMGMS,
	// 	hash:           HashNone,
	// },
	// 0xC107-0xC1FF   Unassigned
	// 0xC200-0xC9FF   Unassigned
	// 0xCA00-0xCAC9   Unassigned
	// 0xCACA          Reserved
	// 0xCACB-0xCAFF   Unassigned
	// 0xCB00-0xCBFF   Unassigned
	// 0xCC00-0xCC12   Unassigned
	0xCC13: {
		// Unassigned
		IANAName: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD", // Now 0xCCA8

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptChaChaPoly,
		hash:           HashSHA256,
	},
	0xCC14: {
		// Unassigned
		IANAName: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD", // Now 0xCCA9

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptChaChaPoly,
		hash:           HashSHA256,
	},
	0xCC15: {
		// Unassigned
		IANAName: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD", // Now 0xCCAA

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptChaChaPoly,
		hash:           HashSHA256,
	},
	// 0xCC16-0xCCA7   Unassigned
	0xCCA8: {
		IANAName:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		OpenSSLName: "ECDHE-RSA-CHACHA20-POLY1305",
		GNUTLSName:  "TLS_ECDHE_RSA_CHACHA20_POLY1305",

		strength:       StrengthSecure,
		keyExchange:    KexECDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptChaChaPoly,
		hash:           HashSHA256,
	},
	0xCCA9: {
		IANAName:    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		OpenSSLName: "ECDHE-ECDSA-CHACHA20-POLY1305",
		GNUTLSName:  "TLS_ECDHE_ECDSA_CHACHA20_POLY1305",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigECDSA,
		encryptionAlgo: EncryptChaChaPoly,
		hash:           HashSHA256,
	},
	0xCCAA: {
		IANAName:    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		OpenSSLName: "DHE-RSA-CHACHA20-POLY1305",
		GNUTLSName:  "TLS_DHE_RSA_CHACHA20_POLY1305",

		strength:       StrengthWeak,
		keyExchange:    KexDHE,
		authentication: SigRSA,
		encryptionAlgo: EncryptChaChaPoly,
		hash:           HashSHA256,
	},
	// 0xCCAB: {
	// 	IANAName:    "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	// 	OpenSSLName: "PSK-CHACHA20-POLY1305",
	// 	GNUTLSName:  "TLS_PSK_CHACHA20_POLY1305",

	// 	strength:       StrengthWeak,
	// 	keyExchange:    KexPSK,
	// 	authentication: SigPSK,
	// 	encryptionAlgo: EncryptChaChaPoly,
	// 	hash:           HashSHA256,
	// },
	// 0xCCAC: {
	// 	IANAName:    "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	// 	OpenSSLName: "ECDHE-PSK-CHACHA20-POLY1305",
	// 	GNUTLSName:  "TLS_ECDHE_PSK_CHACHA20_POLY1305",

	// 	strength:       StrengthRecommended,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigPSK,
	// 	encryptionAlgo: EncryptChaChaPoly,
	// 	hash:           HashSHA256,
	// },
	// 0xCCAD: {
	// 	IANAName:    "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	// 	OpenSSLName: "DHE-PSK-CHACHA20-POLY1305",
	// 	GNUTLSName:  "TLS_DHE_PSK_CHACHA20_POLY1305",

	// 	strength:       StrengthWeak,
	// 	keyExchange:    KexDHE,
	// 	authentication: SigPSK,
	// 	encryptionAlgo: EncryptChaChaPoly,
	// 	hash:           HashSHA256,
	// },
	// 0xCCAE: {
	// 	IANAName:    "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
	// 	OpenSSLName: "RSA-PSK-CHACHA20-POLY1305",
	// 	GNUTLSName:  "TLS_RSA_PSK_CHACHA20_POLY1305",

	// 	strength:       StrengthWeak,
	// 	keyExchange:    KexRSA,
	// 	authentication: SigPSK,
	// 	encryptionAlgo: EncryptChaChaPoly,
	// 	hash:           HashSHA256,
	// },
	// 0xCCAF-0xCCFF	Unassigned
	// 0xCD00-0xCFFF	Unassigned
	// 0xD000           Unassigned
	0xD001: {
		IANAName: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",

		strength:       StrengthRecommended,
		keyExchange:    KexECDHE,
		authentication: SigPSK,
		encryptionAlgo: EncryptAES128GCM,
		hash:           HashSHA256,
	},
	// 0xD002: {
	// 	IANAName: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",

	// 	strength:       StrengthRecommended,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigPSK,
	// 	encryptionAlgo: EncryptAES256GCM,
	// 	hash:           HashSHA384,
	// },
	// 0xD003: {
	// 	IANAName: "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",

	// 	strength:       StrengthSecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigPSK,
	// 	encryptionAlgo: EncryptAES128CCM8,
	// 	hash:           HashSHA256,
	// },
	// // 0xD004           Unassigned
	// 0xD005: {
	// 	IANAName: "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",

	// 	strength:       StrengthSecure,
	// 	keyExchange:    KexECDHE,
	// 	authentication: SigPSK,
	// 	encryptionAlgo: EncryptAES128CCM,
	// 	hash:           HashSHA256,
	// },
	// 0xD006-0xD0FF    Unassigned
	// 0xD100-0xD9FF    Unassigned
	// 0xDA00-0xDAD9    Unassigned
	// 0xDADA           Reserved
	// 0xDADB-0xDAFF    Unassigned
	// 0xDB00-0xE9FF    Unassigned
	// 0xEA00-0xEAE9    Unassigned
	// 0xEAEA           Reserved
	// 0xEAEB-0xEAFF    Unassigned
	// 0xEB00-0xF9FF    Unassigned
	// 0xFA00-0xFAC9    Unassigned
	// 0xFAFA           Reserved
	// 0xFAFB-0xFAFF    Unassigned
	// 0xFB00-0xFDFF    Unassigned
	// 0xFE00-0xFEFD    Unassigned
	// 0xFEFE-0xFEFF    Reserved to avoid conflicts with widely deployed implementations
	// 0xFF00-0xFFFF    Reserved for Private Use
}
