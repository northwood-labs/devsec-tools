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
		Class string `json:"class,omitempty"`

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
	LinkObsoleteKEX        = "https://datatracker.ietf.org/doc/html/draft-ietf-tls-deprecate-obsolete-kex"
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
		"Anon": {
			Name:        "Anon",
			Description: "Anonymous key exchanges are generally vulnerable to Man-in-the-Middle attacks.",
			URLs: []string{
				"https://datatracker.ietf.org/doc/html/rfc6251",
				"https://www.researchgate.net/publication/310823569_Practical_Anonymous_Password_Authentication_and_TLS_with_Anonymous_Client_Authentication",
			},
		},
		"ARIA": {
			Name: "ARIA",
			Description: "ARIA was standardized for use by the government of South Korea, and has not " +
				"been accepted as an international standard.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/ARIA_(cipher)",
				"https://datatracker.ietf.org/doc/html/rfc5794",
			},
		},
		"CBC": {
			Name: "CBC",
			Description: "The CBC encryption algorithm suffers from a handful of vulnerabilites (known as 'BEAST' " +
				"vulnerabilities). GCM encryption should be preferred over CBC.",
			URLs: []string{
				"https://www.isg.rhul.ac.uk/tls/Lucky13.html",
				"https://docs.veracode.com/r/prevent-ssl-lucky13",
				"https://www.ietf.org/proceedings/89/slides/slides-89-irtfopen-1.pdf",
			},
		},
		"CCM": {
			Name:        "CCM",
			Description: "CCM is slower and less secure than GCM algorithms.",
			URLs: []string{
				"https://datatracker.ietf.org/doc/html/rfc6655",
			},
		},
		"DES": {
			Name: "DES",
			Description: "The DES algorithm was cracked in 1997, and was removed from U.S. NIST standards " +
				"(FIPS 46-3) in 2005. It is no longer considered secure.",
			URLs: []string{
				"https://csrc.nist.rip/news/2005/withdrawal-of-fips-46-3-fips-74-and-fips-81",
				"https://en.wikipedia.org/wiki/Data_Encryption_Standard",
			},
		},
		"DH": {
			Name: "DH",
			Description: "The older Diffie-Hellman (DH, DHE) key exchange algorithms are vulnerable to a handful " +
				"of security vulnerabilities. The newer ECDHE key exchange algorithms are more secure.",
			URLs: []string{
				"https://raccoon-attack.com",
			},
		},
		"DHE": {
			Name: "DHE",
			Description: "The older Diffie-Hellman (DH, DHE) key exchange algorithms are vulnerable to a handful " +
				"of security vulnerabilities. The newer ECDHE key exchange algorithms are more secure.",
			URLs: []string{
				"https://raccoon-attack.com",
				"https://web.archive.org/web/20241010094103/https://dheatattack.com/",
			},
		},
		"DSS": {
			Name: "DSS",
			Description: "The Digital Signature Standard (DSS) was deprecated by NIST in 2013. It has been replaced " +
				"by ECDHE/ECDSA.",
			URLs: []string{
				"https://csrc.nist.gov/pubs/fips/186-4/final",
			},
		},
		"ECCPWD": {
			Name: "ECCPWD",
			Description: "ECCPWD is a password-authenticated key exchange algorithm. It is not widely used and is " +
				"not on any IETF standards track.",
			URLs: []string{
				"https://datatracker.ietf.org/doc/html/rfc8492",
			},
		},
		"EXPORT": {
			Name: "EXPORT",
			Description: "Before the year 2000, the U.S. government required any cryptography that was exported " +
				"from the U.S. to be subject to either substantially-reduced encryption keys or the use of backdoors " +
				"in the encryption algorithms known to the U.S. government. By modern standards, even in the U.S., " +
				"these are considered insecure and should not be used.",
			URLs: []string{
				"https://freakattack.com",
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
		"IDEA": {
			Name: "IDEA",
			Description: "IDEA is slower and less secure than modern encryption algorithms. Modern algorithms " +
				"should be used instead.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm",
			},
		},
		"KRB5": {
			Name:        "KRB5",
			Description: "Kerberos v5 over TLS is not widely used and is not on any IETF standards track.",
			URLs: []string{
				"https://datatracker.ietf.org/doc/html/rfc6251",
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
		"Non-Ephemeral": {
			Name: "Non-Ephemeral",
			Description: "Cryptographic keys may designate they can be used for long-term (static, archived) use or " +
				"used for a single session (ephemeral). In TLS, long-term keys are considered less secure " +
				"than ephemeral.",
			URLs: []string{
				"https://csrc.nist.gov/glossary/term/ephemeral_key",
				"https://en.wikipedia.org/wiki/Cryptographic_key_types#Long_term_versus_single_use",
			},
		},
		"NULL": {
			Name: "NULL",
			Description: "Every ciphersuite needs 4 algorithms to be secure: key exchange, authentication signing, " +
				"encryption, and hashing. This is missing one or more of those.",
		},
		"PSK": {
			Name: "PSK",
			Description: "Pre-Shared Keys over TLS are generally used in closed environments, such as IoT devices. " +
				"It is uncommon to see them used on the open web.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/TLS-PSK",
			},
		},
		"SRP": {
			Name: "SRP",
			Description: "Secure Remote Password over TLS are generally used in closed environments, such as " +
				"IoT devices. It is uncommon to see them used on the open web.",
			URLs: []string{
				"https://en.wikipedia.org/wiki/TLS-SRP",
				"https://datatracker.ietf.org/doc/html/rfc5054",
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
		"RSA Auth": {
			Name: "RSA Auth",
			Description: "While not a vulnerability, RSA authentication with keys longer than 3072 bits may " +
				"experience heavy performance issues. This can lead to denial-of-service style attacks.",
		},
		"RSA KEX": {
			Name: "RSA KEX",
			Description: "Using RSA for key exchange (starts with 'TLS_RSA') was cracked in 2017. For TLS 1.2, " +
				"only ECDHE key exchanges should be used.",
			URLs: []string{
				"https://robotattack.org",
			},
		},
		"SHA-1": {
			Name: "SHA-1",
			Description: "The SHA-1 algorithm was cracked in 2017 and is no longer considered a secure hashing " +
				"algorithm.",
			URLs: []string{
				"https://shattered.io",
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
				Name: KeyExchangeList[KexDH],
				Class: strings.Join(
					[]string{
						ProblemDescription["DH"].Name,
						ProblemDescription["Non-Ephemeral"].Name,
					},
					", ",
				),
				Description: ProblemDescription["DH"].Description + "\n\n" +
					ProblemDescription["Non-Ephemeral"].Description,
				URLs: append(ProblemDescription["DH"].URLs, ProblemDescription["Non-Ephemeral"].URLs...),
			},
			KexDHE: {
				Name:        KeyExchangeList[KexDHE],
				Class:       ProblemDescription["DHE"].Name,
				Description: ProblemDescription["DHE"].Description,
				URLs:        ProblemDescription["DHE"].URLs,
			},
			KexECCPWD: {
				Name:        KeyExchangeList[KexECCPWD],
				Class:       ProblemDescription["ECCPWD"].Name,
				Description: ProblemDescription["ECCPWD"].Description,
				URLs:        ProblemDescription["ECCPWD"].URLs,
			},
			KexECDH: {
				Name:        KeyExchangeList[KexECDH],
				Class:       ProblemDescription["Non-Ephemeral"].Name,
				Description: ProblemDescription["Non-Ephemeral"].Description,
				URLs:        ProblemDescription["Non-Ephemeral"].URLs,
			},
			// KexECDHE: {},
			KexGOST256: {
				Name:        KeyExchangeList[KexGOST256],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			KexKRB5: {
				Name:        KeyExchangeList[KexKRB5],
				Class:       ProblemDescription["KRB5"].Name,
				Description: ProblemDescription["KRB5"].Description,
				URLs:        ProblemDescription["KRB5"].URLs,
			},
			KexPSK: {
				Name:        KeyExchangeList[KexPSK],
				Class:       ProblemDescription["PSK"].Name,
				Description: ProblemDescription["PSK"].Description,
				URLs:        ProblemDescription["PSK"].URLs,
			},
			KexRSA: {
				Name:        KeyExchangeList[KexRSA],
				Class:       ProblemDescription["RSA KEX"].Name,
				Description: ProblemDescription["RSA KEX"].Description,
				URLs:        ProblemDescription["RSA KEX"].URLs,
			},
			KexSRP: {
				Name:        KeyExchangeList[KexSRP],
				Class:       ProblemDescription["SRP"].Name,
				Description: ProblemDescription["SRP"].Description,
				URLs:        ProblemDescription["SRP"].URLs,
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
				Class:       ProblemDescription["Anon"].Name,
				Description: ProblemDescription["Anon"].Description,
				URLs:        ProblemDescription["Anon"].URLs,
			},
			SigDSA: {
				Name:        AuthenticationList[SigDSA],
				Class:       ProblemDescription["DSS"].Name,
				Description: ProblemDescription["DSS"].Description,
				URLs:        ProblemDescription["DSS"].URLs,
			},
			SigECCPWD: {
				Name:        AuthenticationList[SigECCPWD],
				Class:       ProblemDescription["ECCPWD"].Name,
				Description: ProblemDescription["ECCPWD"].Description,
				URLs:        ProblemDescription["ECCPWD"].URLs,
			},
			// SigECDSA: {},
			// SigED25519: {},
			// SigED448: {},
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
				Class:       ProblemDescription["KRB5"].Name,
				Description: ProblemDescription["KRB5"].Description,
				URLs:        ProblemDescription["KRB5"].URLs,
			},
			SigNULL: {
				Name:        AuthenticationList[SigNULL],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			SigPSK: {
				Name:        AuthenticationList[SigPSK],
				Class:       ProblemDescription["PSK"].Name,
				Description: ProblemDescription["PSK"].Description,
				URLs:        ProblemDescription["PSK"].URLs,
			},
			SigRSA: {
				Name:        AuthenticationList[SigRSA],
				Class:       ProblemDescription["RSA Auth"].Name,
				Description: ProblemDescription["RSA Auth"].Description,
			},
			SigSHA1: {
				Name:        AuthenticationList[SigSHA1],
				Class:       ProblemDescription["SHA-1"].Name,
				Description: ProblemDescription["SHA-1"].Description,
				URLs:        ProblemDescription["SHA-1"].URLs,
			},
			SigSHA1DSS: {
				Name:        AuthenticationList[SigSHA1DSS],
				Class:       ProblemDescription["SHA-1"].Name,
				Description: ProblemDescription["SHA-1"].Description,
				URLs:        ProblemDescription["SHA-1"].URLs,
			},
			SigSHA1RSA: {
				Name:        AuthenticationList[SigSHA1RSA],
				Class:       ProblemDescription["SHA-1"].Name,
				Description: ProblemDescription["SHA-1"].Description,
				URLs:        ProblemDescription["SHA-1"].URLs,
			},
			// SigSHA256: {},
			// SigSHA384: {},
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
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			Encrypt3DESEDECBC: {
				Name:        EncryptionAlgoList[Encrypt3DESEDECBC],
				Class:       ProblemDescription["3DES"].Name,
				Description: ProblemDescription["3DES"].Description,
				URLs:        ProblemDescription["3DES"].URLs,
			},
			EncryptAES128CBC: {
				Name:        EncryptionAlgoList[EncryptAES128CBC],
				Class:       ProblemDescription["CBC"].Name,
				Description: ProblemDescription["CBC"].Description,
				URLs:        ProblemDescription["CBC"].URLs,
			},
			EncryptAES128CCM: {
				Name:        EncryptionAlgoList[EncryptAES128CCM],
				Class:       ProblemDescription["CCM"].Name,
				Description: ProblemDescription["CCM"].Description,
				URLs:        ProblemDescription["CCM"].URLs,
			},
			EncryptAES128CCM8: {
				Name:        EncryptionAlgoList[EncryptAES128CCM8],
				Class:       ProblemDescription["CCM"].Name,
				Description: ProblemDescription["CCM"].Description,
				URLs:        ProblemDescription["CCM"].URLs,
			},
			// EncryptAES128GCM: {},
			EncryptAES256CBC: {
				Name:        EncryptionAlgoList[EncryptAES256CBC],
				Class:       ProblemDescription["CBC"].Name,
				Description: ProblemDescription["CBC"].Description,
				URLs:        ProblemDescription["CBC"].URLs,
			},
			EncryptAES256CCM: {
				Name:        EncryptionAlgoList[EncryptAES256CCM],
				Class:       ProblemDescription["CCM"].Name,
				Description: ProblemDescription["CCM"].Description,
				URLs:        ProblemDescription["CCM"].URLs,
			},
			EncryptAES256CCM8: {
				Name:        EncryptionAlgoList[EncryptAES256CCM8],
				Class:       ProblemDescription["CCM"].Name,
				Description: ProblemDescription["CCM"].Description,
				URLs:        ProblemDescription["CCM"].URLs,
			},
			// EncryptAES256GCM: {},
			EncryptARIA128CBC: {
				Name: EncryptionAlgoList[EncryptARIA128CBC],
				Class: strings.Join(
					[]string{
						ProblemDescription["ARIA"].Name,
						ProblemDescription["CBC"].Name,
					},
					", ",
				),
				Description: ProblemDescription["ARIA"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(ProblemDescription["ARIA"].URLs, ProblemDescription["CBC"].URLs...),
			},
			EncryptARIA128GCM: {
				Name:        EncryptionAlgoList[EncryptARIA128GCM],
				Class:       ProblemDescription["ARIA"].Name,
				Description: ProblemDescription["ARIA"].Description,
				URLs:        ProblemDescription["ARIA"].URLs,
			},
			EncryptARIA256CBC: {
				Name: EncryptionAlgoList[EncryptARIA256CBC],
				Class: strings.Join(
					[]string{
						ProblemDescription["ARIA"].Name,
						ProblemDescription["CBC"].Name,
					},
					", ",
				),
				Description: ProblemDescription["ARIA"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(ProblemDescription["ARIA"].URLs, ProblemDescription["CBC"].URLs...),
			},
			EncryptARIA256GCM: {
				Name:        EncryptionAlgoList[EncryptARIA256GCM],
				Class:       ProblemDescription["ARIA"].Name,
				Description: ProblemDescription["ARIA"].Description,
				URLs:        ProblemDescription["ARIA"].URLs,
			},
			EncryptCamellia128CBC: {
				Name:        EncryptionAlgoList[EncryptCamellia128CBC],
				Class:       ProblemDescription["CBC"].Name,
				Description: ProblemDescription["CBC"].Description,
				URLs:        ProblemDescription["CBC"].URLs,
			},
			// EncryptCamellia128GCM: {},
			EncryptCamellia256CBC: {
				Name:        EncryptionAlgoList[EncryptCamellia256CBC],
				Class:       ProblemDescription["CBC"].Name,
				Description: ProblemDescription["CBC"].Description,
				URLs:        ProblemDescription["CBC"].URLs,
			},
			// EncryptCamellia256GCM: {},
			// EncryptChaChaPoly: {},
			EncryptDESCBC: {
				Name: EncryptionAlgoList[EncryptDESCBC],
				Class: strings.Join(
					[]string{
						ProblemDescription["DES"].Name,
						ProblemDescription["CBC"].Name,
					},
					", ",
				),
				Description: ProblemDescription["DES"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(ProblemDescription["DES"].URLs, ProblemDescription["CBC"].URLs...),
			},
			EncryptDESCBC40: {
				Name: EncryptionAlgoList[EncryptDESCBC40],
				Class: strings.Join(
					[]string{
						ProblemDescription["DES"].Name,
						ProblemDescription["CBC"].Name,
						ProblemDescription["EXPORT"].Name,
					},
					", ",
				),
				Description: ProblemDescription["DES"].Description + "\n\n" +
					ProblemDescription["EXPORT"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(
					append(ProblemDescription["DES"].URLs, ProblemDescription["EXPORT"].URLs...),
					ProblemDescription["CBC"].URLs...),
			},
			EncryptDES40CBC: {
				Name: EncryptionAlgoList[EncryptDES40CBC],
				Class: strings.Join(
					[]string{
						ProblemDescription["DES"].Name,
						ProblemDescription["CBC"].Name,
						ProblemDescription["EXPORT"].Name,
					},
					", ",
				),
				Description: ProblemDescription["DES"].Description + "\n\n" +
					ProblemDescription["EXPORT"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(
					append(ProblemDescription["DES"].URLs, ProblemDescription["EXPORT"].URLs...),
					ProblemDescription["CBC"].URLs...),
			},
			EncryptIDEACBC: {
				Name: EncryptionAlgoList[EncryptIDEACBC],
				Class: strings.Join(
					[]string{
						ProblemDescription["IDEA"].Name,
						ProblemDescription["CBC"].Name,
					},
					", ",
				),
				Description: ProblemDescription["IDEA"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(ProblemDescription["IDEA"].URLs, ProblemDescription["CBC"].URLs...),
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
					ProblemDescription["EXPORT"].Description + "\n\n" +
					ProblemDescription["CBC"].Description,
				URLs: append(
					append(ProblemDescription["RC2"].URLs, ProblemDescription["EXPORT"].URLs...),
					ProblemDescription["CBC"].URLs...),
			},
			EncryptRC4128: {
				Name:        EncryptionAlgoList[EncryptRC4128],
				Class:       ProblemDescription["RC4"].Name,
				Description: ProblemDescription["RC4"].Description,
				URLs:        ProblemDescription["RC4"].URLs,
			},
			EncryptRC440: {
				Name: EncryptionAlgoList[EncryptRC440],
				Class: strings.Join(
					[]string{
						ProblemDescription["RC4"].Name,
						ProblemDescription["EXPORT"].Name,
					},
					", ",
				),
				Description: ProblemDescription["RC4"].Description + "\n\n" +
					ProblemDescription["EXPORT"].Description,
				URLs: append(ProblemDescription["RC4"].URLs, ProblemDescription["EXPORT"].URLs...),
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
			HashGOSTR: {
				Name:        HashList[HashGOSTR],
				Class:       ProblemDescription["GOST-R"].Name,
				Description: ProblemDescription["GOST-R"].Description,
				URLs:        ProblemDescription["GOST-R"].URLs,
			},
			HashMD5: {
				Name:        HashList[HashMD5],
				Class:       ProblemDescription["MD5"].Name,
				Description: ProblemDescription["MD5"].Description,
				URLs:        ProblemDescription["MD5"].URLs,
			},
			HashNULL: {
				Name:        HashList[HashNULL],
				Class:       ProblemDescription["NULL"].Name,
				Description: ProblemDescription["NULL"].Description,
			},
			HashSHA1: {
				Name:        HashList[HashSHA1],
				Class:       ProblemDescription["SHA-1"].Name,
				Description: ProblemDescription["SHA-1"].Description,
				URLs:        ProblemDescription["SHA-1"].URLs,
			},
			// HashSHA224: {},
			// HashSHA256: {},
			// HashSHA384: {},
			// HashSHA512: {},
			HashSM3: {
				Name:        HashList[HashSM3],
				Class:       ProblemDescription["ShangMi"].Name,
				Description: ProblemDescription["ShangMi"].Description,
				URLs:        ProblemDescription["ShangMi"].URLs,
			},
		},
	}
)

// 	ProblemTLSVersion: "The IETF has officially deprecated TLS versions 1.0 and 1.1 in RFC-8996. There are " +
// 		"known vulnerabilities in this TLS versions.",
