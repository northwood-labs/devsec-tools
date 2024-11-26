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

import "strings"

type (
	Number interface {
		int | KeyExchange | Signature
	}

	Problem struct {
		Name        string
		Class       string
		Description string
		URLs        []string
	}

	ProblemMap struct {
		Name        string
		Description string
		URLs        []string
	}

	ProblemData struct {
		// Type is a string representation of the classification of the problem.
		Type string `json:"type,omitempty"`

		// A friendly description of the problem.
		Description string `json:"description,omitempty"`

		// A set of URLs with more information about this problem.
		URLs []string `json:"urls,omitempty"`
	}
)

const (
	// Links to more information
	LinkCSAWSALB           = "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html"
	LinkCSCloudflare       = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/cipher-suites/supported-cipher-suites/"
	LinkCSInfo             = "https://ciphersuite.info/cs/%s"
	LinkDeprecateLegacyTLS = "https://datatracker.ietf.org/doc/html/rfc8996"
	LinkECH                = "https://blog.cloudflare.com/announcing-encrypted-client-hello/"
	LinkExport             = "https://freakattack.com"
	LinkNISTDSS            = "https://csrc.nist.gov/pubs/fips/186-5/final"
	LinkObsoleteKEX        = "https://datatracker.ietf.org/doc/html/draft-ietf-tls-deprecate-obsolete-kex"
	LinkRC2                = "https://www.schneier.com/wp-content/uploads/2016/02/paper-relatedkey.pdf"
	LinkRC4                = "https://datatracker.ietf.org/doc/html/rfc7465"
)

var (
	ProblemDescription = map[string]ProblemMap{
		"3DES": {
			Name: "Triple-DES",
			Description: "Alhough Triple-DES (3DES) has not yet been fully broken, it suffers from several " +
				"vulnerabilities (known as 'Lucky 13' vulnerabilities).",
			URLs: []string{
				"https://sweet32.info",
			},
		},
		"CBC": {
			Name: "CBC",
			Description: "The CBC encryption algorithm suffers from a handful of vulnerabilites (known as 'BEAST' " +
				"vulnerabilities). GCM encryption should be preferred over CBC.",
			URLs: []string{
				"https://www.isg.rhul.ac.uk/tls/Lucky13.html",
			},
		},
		"EXPORT": {
			Name: "EXPORT",
			Description: "Before the year 2000, the U.S. government required any cryptography that was exported " +
				"from the U.S. to be subject to either substantially-reduced encryption keys or the use of backdoors " +
				"in the encryption algorithms known to the U.S. government. By modern standards, even in the U.S., " +
				"these are considered insecure and should not be used.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States",
			},
		},
		"GOST-R": {
			Name: "GOST-R",
			Description: "GOST-R was standardized for use by the government of the Russian Federation, and has not " +
				"been accepted as an international standard.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/GOST_(block_cipher)",
				"https://datatracker.ietf.org/doc/html/rfc7091/",
			},
		},
		"MD5": {
			Name: "MD5",
			Description: "The MD5 algorithm was partially cracked in 1996, was fully cracked in 2005, and as of " +
				"2008 is no longer considered a secure hashing algorithm.",
			URLs: []string{
				"https://www.schneier.com/blog/archives/2008/12/forging_ssl_cer.html",
			},
		},
		"NULL": {
			Name: "NULL",
			Description: "Every ciphersuite needs 4 algorithms to be secure: key exchange, authentication signing, " +
				"encryption, and hashing. This is missing one or more of those.",
		},
		"SHA-1": {
			Name: "SHA-1",
			Description: "The SHA-1 algorithm was cracked in 2017 and is no longer considered a secure hashing " +
				"algorithm.",
			URLs: []string{
				"https://shattered.io",
			},
		},
		"RC2": {
			Name:        "RC2",
			Description: "The RC2 algorithm was cracked in 1997. It is no longer considered secure.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/RC2",
				"https://www.schneier.com/wp-content/uploads/2016/02/paper-relatedkey.pdf",
			},
		},
		"RC4": {
			Name: "RC4",
			Description: "The RC4 algorithm was cracked in 2013, was prohibited from being part of TLS in 2015, " +
				"and was removed from all major web browsers in 2016. It is no longer considered secure.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/RC4",
				"https://en.wikipedia.org/wiki/Transport_Layer_Security#RC4_attacks",
				"https://datatracker.ietf.org/doc/html/rfc7465",
				"https://blog.qualys.com/product-tech/2013/03/19/rc4-in-tls-is-broken-now-what",
				"https://blog.cloudflare.com/killing-rc4-the-long-goodbye/",
			},
		},
		"ShangMi": {
			Name: "ShangMi",
			Description: "ShāngMì was standardized for use by the government of China, and has not been accepted " +
				"as an international standard.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/SM3_(hash_function)",
				"https://en.wikipedia.org/wiki/SM4_(cipher)",
				"https://datatracker.ietf.org/doc/html/rfc8998",
			},
		},
	}

	ProblemList = map[string]map[any]Problem{
		"kex": {
			KexNone: {
				Name:        KeyExchangeList[KexNone],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			KexNULL: {
				Name:        KeyExchangeList[KexNULL],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			KexDH: {
				Name:        KeyExchangeList[KexDH],
				Class:       "",
				Description: "",
			},
			KexDHE: {
				Name:        KeyExchangeList[KexDHE],
				Class:       "",
				Description: "",
			},
			KexECCPWD: {
				Name:        KeyExchangeList[KexECCPWD],
				Class:       "",
				Description: "",
			},
			KexECDH: {
				Name:        KeyExchangeList[KexECDH],
				Class:       "",
				Description: "",
			},
			KexECDHE: {
				Name:        KeyExchangeList[KexECDHE],
				Class:       "",
				Description: "",
			},
			KexGOST256: {
				Name:        KeyExchangeList[KexGOST256],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			KexKRB5: {
				Name:        KeyExchangeList[KexKRB5],
				Class:       "",
				Description: "",
			},
			KexPSK: {
				Name:        KeyExchangeList[KexPSK],
				Class:       "",
				Description: "",
			},
			KexRSA: {
				Name:        KeyExchangeList[KexRSA],
				Class:       "",
				Description: "",
			},
			KexSRP: {
				Name:        KeyExchangeList[KexSRP],
				Class:       "",
				Description: "",
			},
			KexSM2: {
				Name:        KeyExchangeList[KexSM2],
				Class:       ProblemDescription["ShangMi"].Name,
				Description: ProblemDescription["ShangMi"].Description,
				URLs:        ProblemDescription["ShangMi"].URLs,
			},
		},
		"authsig": {
			SigAnonymous: {
				Name:        AuthenticationList[SigAnonymous],
				Class:       "",
				Description: "",
			},
			SigDSA: {
				Name:        AuthenticationList[SigDSA],
				Class:       "",
				Description: "",
			},
			SigECCPWD: {
				Name:        AuthenticationList[SigECCPWD],
				Class:       "",
				Description: "",
			},
			SigECDSA: {
				Name:        AuthenticationList[SigECDSA],
				Class:       "",
				Description: "",
			},
			SigED25519: {
				Name:        AuthenticationList[SigED25519],
				Class:       "",
				Description: "",
			},
			SigED448: {
				Name:        AuthenticationList[SigED448],
				Class:       "",
				Description: "",
			},
			SigGOST256: {
				Name:        AuthenticationList[SigGOST256],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			SigGOST512: {
				Name:        AuthenticationList[SigGOST512],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			SigKRB5: {
				Name:        AuthenticationList[SigKRB5],
				Class:       "",
				Description: "",
			},
			SigNULL: {
				Name:        AuthenticationList[SigNULL],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			SigPSK: {
				Name:        AuthenticationList[SigPSK],
				Class:       "",
				Description: "",
			},
			SigRSA: {
				Name:        AuthenticationList[SigRSA],
				Class:       "",
				Description: "",
			},
			SigSHA1: {
				Name:        AuthenticationList[SigSHA1],
				Class:       "",
				Description: "",
			},
			SigSHA1DSS: {
				Name:        AuthenticationList[SigSHA1DSS],
				Class:       "",
				Description: "",
			},
			SigSHA1RSA: {
				Name:        AuthenticationList[SigSHA1RSA],
				Class:       "",
				Description: "",
			},
			SigSHA256: {
				Name:        AuthenticationList[SigSHA256],
				Class:       "",
				Description: "",
			},
			SigSHA384: {
				Name:        AuthenticationList[SigSHA384],
				Class:       "",
				Description: "",
			},
			SigSM2: {
				Name:        AuthenticationList[SigSM2],
				Class:       ProblemDescription["ShangMi"].Name,
				Description: ProblemDescription["ShangMi"].Description,
				URLs:        ProblemDescription["ShangMi"].URLs,
			},
		},
		"encryption": {
			Encrypt28147CNT: {
				Name:        EncryptionAlgoList[Encrypt28147CNT],
				Class:       "",
				Description: "",
			},
			Encrypt3DESEDECBC: {
				Name:        EncryptionAlgoList[Encrypt3DESEDECBC],
				Class:       ProblemDescription["3DES"].Name,
				Description: ProblemDescription["3DES"].Description,
				URLs:        ProblemDescription["3DES"].URLs,
			},
			EncryptAES128CBC: {
				Name:        EncryptionAlgoList[EncryptAES128CBC],
				Class:       "",
				Description: "",
			},
			EncryptAES128CCM: {
				Name:        EncryptionAlgoList[EncryptAES128CCM],
				Class:       "",
				Description: "",
			},
			EncryptAES128CCM8: {
				Name:        EncryptionAlgoList[EncryptAES128CCM8],
				Class:       "",
				Description: "",
			},
			EncryptAES128GCM: {
				Name:        EncryptionAlgoList[EncryptAES128GCM],
				Class:       "",
				Description: "",
			},
			EncryptAES256CBC: {
				Name:        EncryptionAlgoList[EncryptAES256CBC],
				Class:       "",
				Description: "",
			},
			EncryptAES256CCM: {
				Name:        EncryptionAlgoList[EncryptAES256CCM],
				Class:       "",
				Description: "",
			},
			EncryptAES256CCM8: {
				Name:        EncryptionAlgoList[EncryptAES256CCM8],
				Class:       "",
				Description: "",
			},
			EncryptAES256GCM: {
				Name:        EncryptionAlgoList[EncryptAES256GCM],
				Class:       "",
				Description: "",
			},
			EncryptARIA128CBC: {
				Name:        EncryptionAlgoList[EncryptARIA128CBC],
				Class:       "",
				Description: "",
			},
			EncryptARIA128GCM: {
				Name:        EncryptionAlgoList[EncryptARIA128GCM],
				Class:       "",
				Description: "",
			},
			EncryptARIA256CBC: {
				Name:        EncryptionAlgoList[EncryptARIA256CBC],
				Class:       "",
				Description: "",
			},
			EncryptARIA256GCM: {
				Name:        EncryptionAlgoList[EncryptARIA256GCM],
				Class:       "",
				Description: "",
			},
			EncryptCamellia128CBC: {
				Name:        EncryptionAlgoList[EncryptCamellia128CBC],
				Class:       "",
				Description: "",
			},
			EncryptCamellia128GCM: {
				Name:        EncryptionAlgoList[EncryptCamellia128GCM],
				Class:       "",
				Description: "",
			},
			EncryptCamellia256CBC: {
				Name:        EncryptionAlgoList[EncryptCamellia256CBC],
				Class:       "",
				Description: "",
			},
			EncryptCamellia256GCM: {
				Name:        EncryptionAlgoList[EncryptCamellia256GCM],
				Class:       "",
				Description: "",
			},
			EncryptChaChaPoly: {
				Name:        EncryptionAlgoList[EncryptChaChaPoly],
				Class:       "",
				Description: "",
			},
			EncryptDESCBC: {
				Name:        EncryptionAlgoList[EncryptDESCBC],
				Class:       "",
				Description: "",
			},
			EncryptDESCBC40: {
				Name:        EncryptionAlgoList[EncryptDESCBC40],
				Class:       "",
				Description: "",
			},
			EncryptDES40CBC: {
				Name:        EncryptionAlgoList[EncryptDES40CBC],
				Class:       "",
				Description: "",
			},
			EncryptIDEACBC: {
				Name:        EncryptionAlgoList[EncryptIDEACBC],
				Class:       "",
				Description: "",
			},
			EncryptKuznyechikCTR: {
				Name:        EncryptionAlgoList[EncryptKuznyechikCTR],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			EncryptKuznyechikMGML: {
				Name:        EncryptionAlgoList[EncryptKuznyechikMGML],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			EncryptKuznyechikMGMS: {
				Name:        EncryptionAlgoList[EncryptKuznyechikMGMS],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			EncryptMagmaCTR: {
				Name:        EncryptionAlgoList[EncryptMagmaCTR],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			EncryptMagmaMGML: {
				Name:        EncryptionAlgoList[EncryptMagmaMGML],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			EncryptMagmaMGMS: {
				Name:        EncryptionAlgoList[EncryptMagmaMGMS],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			EncryptNULL: {
				Name:        EncryptionAlgoList[EncryptNULL],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			EncryptRC2CBC40: {
				Name: EncryptionAlgoList[EncryptRC2CBC40],
				Class: strings.Join(
					[]string{
						ProblemDescription["RC2"].Name,
						ProblemDescription["CBC"].Name,
						ProblemDescription["EXPORT"].Name,
					},
					", ",
				),
				Description: ProblemDescription["RC2"].Description + "\n\n" +
					ProblemDescription["CBC"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(
					append(ProblemDescription["CBC"].URLs, ProblemDescription["EXPORT"].URLs...),
					ProblemDescription["CBC"].URLs...),
			},
			EncryptRC4128: {
				Name:        EncryptionAlgoList[EncryptRC4128],
				Class:       "",
				Description: "",
			},
			EncryptRC440: {
				Name:        EncryptionAlgoList[EncryptRC440],
				Class:       "",
				Description: "",
			},
			EncryptSEEDCBC: {
				Name:        EncryptionAlgoList[EncryptSEEDCBC],
				Class:       ProblemDescription["CBC"].Name,
				Description: ProblemDescription["CBC"].Description,
				URLs:        ProblemDescription["CBC"].URLs,
			},
			EncryptSM4CCM: {
				Name:        EncryptionAlgoList[EncryptSM4CCM],
				Class:       ProblemDescription["ShangMi"].Name,
				Description: ProblemDescription["ShangMi"].Description,
				URLs:        ProblemDescription["ShangMi"].URLs,
			},
			EncryptSM4GCM: {
				Name:        EncryptionAlgoList[EncryptSM4GCM],
				Class:       ProblemDescription["ShangMi"].Name,
				Description: ProblemDescription["ShangMi"].Description,
				URLs:        ProblemDescription["ShangMi"].URLs,
			},
		},
		"hash": {
			HashNone: {
				Name:        HashList[HashNone],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			HashNULL: {
				Name:        HashList[HashNULL],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			HashMD5: {
				Name:        HashList[HashMD5],
				Class:       ProblemDescription["MD5"].Name,
				Description: ProblemDescription["MD5"].Description,
				URLs:        ProblemDescription["MD5"].URLs,
			},
			HashSHA1: {
				Name:        HashList[HashSHA1],
				Class:       ProblemDescription["SHA-1"].Name,
				Description: ProblemDescription["SHA-1"].Description,
				URLs:        ProblemDescription["SHA-1"].URLs,
			},
			HashGOSTR: {
				Name:        HashList[HashGOSTR],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			HashSM3: {
				Name:        HashList[HashSM3],
				Class:       ProblemDescription["ShangMi"].Name,
				Description: ProblemDescription["ShangMi"].Description,
				URLs:        ProblemDescription["ShangMi"].URLs,
			},
		},
	}
)

// ProblemList = map[Problem]string{
// 	ProblemNonEphemeral: "Ephemeral exchange algorithms are more secure because they clean-up leftover data. " +
// 		"Non-ephemeral exchange algorithms (like this one) leave leftover data behind, which can allow an " +
// 		"attacker to gain access to the encryption keys.",
// 	ProblemRSA: "While not a vulnerability, RSA authentication with keys longer than 3072 bits may experience " +
// 		"heavy performance issues. This can lead to denial-of-service style attacks.",
// 	ProblemTLSVersion: "The IETF has officially deprecated TLS versions 1.0 and 1.1 in RFC-8996. There are " +
// 		"known vulnerabilities in this TLS versions.",
// }
// ProblemTypeList = map[Problem]string{
// 	ProblemNonEphemeral: "Non-Ephemeral",
// 	Problem3DES:         "Triple-DES",
// 	ProblemCBC:          "CBC",
// 	ProblemRC4:          "RC4",
// 	ProblemRSA:          "RSA Authentication",
// 	ProblemSHA1:         "SHA-1",
// 	ProblemTLSVersion:   "Legacy TLS",
// }
// ProblemURLList = map[Problem][]string{
// 	ProblemNonEphemeral: {LinkCSAWSALB, LinkCSCloudflare, LinkObsoleteKEX},
// 	Problem3DES:         {LinkCSAWSALB, LinkCSCloudflare, Link3DES},
// 	ProblemCBC:          {LinkCSAWSALB, LinkCSCloudflare, LinkCBC},
// 	ProblemRC4:          {LinkCSAWSALB, LinkCSCloudflare, LinkRC4},
// 	ProblemRSA:          {LinkCSAWSALB, LinkCSCloudflare},
// 	ProblemSHA1:         {LinkCSAWSALB, LinkCSCloudflare, LinkSHA1},
// 	ProblemTLSVersion:   {LinkCSAWSALB, LinkCSCloudflare, LinkDeprecateLegacyTLS},
// }
