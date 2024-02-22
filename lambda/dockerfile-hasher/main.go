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

func HandleRequest(ctx context.Context, event interface{}) error {
	lctx, _ := lambdacontext.FromContext(ctx)

	pp := debug.GetSpew()
	pp.Dump(lctx)

	return nil
}
