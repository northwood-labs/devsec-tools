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

type (
	Problem int

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
	// Problem types
	ProblemNonEphemeral Problem = iota
	Problem3DES
	ProblemCBC
	ProblemRC4
	ProblemRSA
	ProblemSHA1
	ProblemTLSVersion
)

var (
	ProblemList = map[Problem]string{
		ProblemNonEphemeral: "Ephemeral exchange algorithms are more secure because they clean-up leftover data. " +
			"Non-ephemeral exchange algorithms (like this one) leave leftover data behind, which can allow an " +
			"attacker to gain access to the encryption keys.",
		Problem3DES: "Though Triple-DES (3DES) has not yet been broken, it suffers from several vulnerabilities " +
			"(known as 'Lucky 13').",
		ProblemCBC: "The CBC encryption algorithm suffers from a handful of vulnerabilites (known as 'BEAST'). " +
			"GCM encryption should be preferred over CBC.",
		ProblemRC4: "The IETF has officially prohibited RC4 for use in TLS in RFC-7465.",
		ProblemRSA: "While not a vulnerability, RSA authentication with keys longer than 3072 bits may experience " +
			"heavy performance issues. This can lead to denial-of-service style attacks.",
		ProblemSHA1: "The Secure Hash Algorithm 1 (SHA-1) was cracked in 2017",
		ProblemTLSVersion: "The IETF has officially deprecated TLS versions 1.0 and 1.1 in RFC-8996. There are " +
			"known vulnerabilities in this TLS versions.",
	}

	ProblemTypeList = map[Problem]string{
		ProblemNonEphemeral: "Non-Ephemeral",
		Problem3DES:         "Triple-DES",
		ProblemCBC:          "CBC",
		ProblemRC4:          "RC4",
		ProblemRSA:          "RSA Authentication",
		ProblemSHA1:         "SHA-1",
		ProblemTLSVersion:   "Legacy TLS",
	}

	ProblemURLList = map[Problem][]string{
		ProblemNonEphemeral: {LinkCSAWSALB, LinkCSCloudflare, LinkObsoleteKEX},
		Problem3DES:         {LinkCSAWSALB, LinkCSCloudflare, Link3DES},
		ProblemCBC:          {LinkCSAWSALB, LinkCSCloudflare, LinkCBC},
		ProblemRC4:          {LinkCSAWSALB, LinkCSCloudflare, LinkRC4},
		ProblemRSA:          {LinkCSAWSALB, LinkCSCloudflare},
		ProblemSHA1:         {LinkCSAWSALB, LinkCSCloudflare, LinkSHA1},
		ProblemTLSVersion:   {LinkCSAWSALB, LinkCSCloudflare, LinkDeprecateLegacyTLS},
	}
)
