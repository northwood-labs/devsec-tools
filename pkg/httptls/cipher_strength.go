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

type CipherStrength int

const (
	// Cipher strength groupings
	StrengthInsecure CipherStrength = iota
	StrengthWeak
	StrengthSecure
	StrengthRecommended
)

// StrengthList is a map of cipher strengths to their human-readable names.
var StrengthList = map[CipherStrength]string{
	StrengthInsecure:    "Insecure",
	StrengthWeak:        "Weak",
	StrengthSecure:      "Secure",
	StrengthRecommended: "Recommended",
}
