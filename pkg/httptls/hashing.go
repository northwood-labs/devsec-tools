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

type Hash int

const (
	// Hashing functions
	HashNone      Hash = 0x0000
	HashMD5       Hash = 0x0001
	HashSHA1      Hash = 0x0002
	HashSHA224    Hash = 0x0003
	HashSHA256    Hash = 0x0004
	HashSHA384    Hash = 0x0005
	HashSHA512    Hash = 0x0006
	HashReserved  Hash = 0x0007
	HashIntrinsic Hash = 0x0008
	// 0x0009-0x00DF   Reserved
	// 0x00E0-0x00FF   Reserved for Private Use

	// The following are not assigned real values from the IANA.
	HashGOST Hash = 0x0100
	HashNULL Hash = 0x0101
	HashSM3  Hash = 0x0102
)

var HashList = map[Hash]string{
	HashNone:   "None",
	HashMD5:    "MD5",
	HashSHA1:   "SHA-1",
	HashSHA224: "SHA-224",
	HashSHA256: "SHA-256",
	HashSHA384: "SHA-384",
	HashSHA512: "SHA-512",
	HashGOST:   "GOSTR341012",
	HashNULL:   "NULL",
	HashSM3:    "SM3",
}
