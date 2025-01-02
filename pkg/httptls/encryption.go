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

type EncryptionAlgo int

const (
	// Encryption algorithms
	Encrypt28147CNT EncryptionAlgo = iota
	Encrypt3DESEDECBC
	EncryptAES128CBC
	EncryptAES128CCM
	EncryptAES128CCM8
	EncryptAES128GCM
	EncryptAES256CBC
	EncryptAES256CCM
	EncryptAES256CCM8
	EncryptAES256GCM
	EncryptARIA128CBC
	EncryptARIA128GCM
	EncryptARIA256CBC
	EncryptARIA256GCM
	EncryptCamellia128CBC
	EncryptCamellia128GCM
	EncryptCamellia256CBC
	EncryptCamellia256GCM
	EncryptChaChaPoly
	EncryptDESCBC
	EncryptDESCBC40
	EncryptDES40CBC
	EncryptIDEACBC
	EncryptKuznyechikCTR
	EncryptKuznyechikMGML
	EncryptKuznyechikMGMS
	EncryptMagmaCTR
	EncryptMagmaMGML
	EncryptMagmaMGMS
	EncryptNULL
	EncryptRC2CBC40
	EncryptRC4128
	EncryptRC440
	EncryptSEEDCBC
	EncryptSM4CCM
	EncryptSM4GCM
)

// EncryptionAlgoList is a map of encryption algorithms to their human-readable names.
var EncryptionAlgoList = map[EncryptionAlgo]string{
	Encrypt28147CNT:       "28147-CNT",         // Russia; Россия
	Encrypt3DESEDECBC:     "3DES-EDE-CBC",      // Ancient
	EncryptAES128CBC:      "AES-128-CBC",       // International Standard
	EncryptAES128CCM:      "AES-128-CCM",       // International Standard
	EncryptAES128CCM8:     "AES-128-CCM-8",     // International Standard
	EncryptAES128GCM:      "AES-128-GCM",       // International Standard
	EncryptAES256CBC:      "AES-256-CBC",       // International Standard
	EncryptAES256CCM:      "AES-256-CCM",       // International Standard
	EncryptAES256CCM8:     "AES-256-CCM-8",     // International Standard
	EncryptAES256GCM:      "AES-256-GCM",       // International Standard
	EncryptARIA128CBC:     "ARIA-128-CBC",      // South Korea; 대한민국
	EncryptARIA128GCM:     "ARIA-128-GCM",      // South Korea; 대한민국
	EncryptARIA256CBC:     "ARIA-256-CBC",      // South Korea; 대한민국
	EncryptARIA256GCM:     "ARIA-256-GCM",      // South Korea; 대한민국
	EncryptCamellia128CBC: "Camellia-128-CBC",  // Japan, 日本
	EncryptCamellia128GCM: "Camellia-128-GCM",  // Japan, 日本
	EncryptCamellia256CBC: "Camellia-256-CBC",  // Japan, 日本
	EncryptCamellia256GCM: "Camellia-256-GCM",  // Japan, 日本
	EncryptChaChaPoly:     "CHACHA20-POLY1305", // International Standard
	EncryptDESCBC:         "DES-CBC",           // Ancient
	EncryptDESCBC40:       "DES-CBC-40",        // Ancient
	EncryptDES40CBC:       "DES-40-CBC",        // Ancient
	EncryptIDEACBC:        "IDEA-CBC",          // Ancient
	EncryptKuznyechikCTR:  "Kuznyechik-CTR",    // Russia; Россия
	EncryptKuznyechikMGML: "Kuznyechik-MGM-L",  // Russia; Россия
	EncryptKuznyechikMGMS: "Kuznyechik-MGM-S",  // Russia; Россия
	EncryptMagmaCTR:       "Magma-CTR",         // Russia; Россия
	EncryptMagmaMGML:      "Magma-MGM-L",       // Russia; Россия
	EncryptMagmaMGMS:      "Magma-MGM-S",       // Russia; Россия
	EncryptNULL:           "NULL",              //
	EncryptRC2CBC40:       "RC2-CBC-40",        // Ancient
	EncryptRC4128:         "RC4-128",           // Ancient
	EncryptRC440:          "RC4-40",            // Ancient
	EncryptSEEDCBC:        "SEED-CBC",          // Ancient
	EncryptSM4CCM:         "SM4-CCM",           // China; 中国
	EncryptSM4GCM:         "SM4-GCM",           // China; 中国
}

// AEADList is a map of Authenticated Encryption with Associated Data (AEAD)
// encryption modes of operation. AEAD offers a much higher degree if security
// than traditional encryption algorithms. They consist of GCM, CCM, and
// Poly1305 modes.
var AEADList = map[EncryptionAlgo]bool{
	EncryptAES128CCM:      true, // International Standard
	EncryptAES128CCM8:     true, // International Standard
	EncryptAES128GCM:      true, // International Standard
	EncryptAES256CCM:      true, // International Standard
	EncryptAES256CCM8:     true, // International Standard
	EncryptAES256GCM:      true, // International Standard
	EncryptARIA128GCM:     true, // South Korea; 대한민국
	EncryptARIA256GCM:     true, // South Korea; 대한민국
	EncryptCamellia128GCM: true, // Japan, 日本
	EncryptCamellia256GCM: true, // Japan, 日本
	EncryptChaChaPoly:     true, // International Standard
	EncryptSM4CCM:         true, // China; 中国
	EncryptSM4GCM:         true, // China; 中国
}
