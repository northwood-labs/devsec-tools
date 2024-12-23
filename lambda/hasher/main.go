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

package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/northwood-labs/golang-utils/debug"
)

func main() {
	lambda.Start(HandleRequest)
}

func HandleRequest(ctx context.Context, event any) error {
	lctx, _ := lambdacontext.FromContext(ctx)

	pp := debug.GetSpew()
	pp.Dump(lctx)

	return nil
}
