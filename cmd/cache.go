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

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/valkey-io/valkey-go"
)

func GetCacheClient() (*valkey.Client, error) {
	servers := os.Getenv("DST_CACHE_HOSTS")

	if servers == "" {
		return nil, nil
	}

	client, err := valkey.NewClient(
		valkey.ClientOption{
			InitAddress: strings.Split(servers, ";"),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache client: %w", err)
	}

	return &client, nil
}
