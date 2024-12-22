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
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/charmbracelet/log"
	"github.com/northwood-labs/debug"
	"github.com/northwood-labs/devsec-tools/pkg/httptls"
)

type (
	InputRequest struct {
		URL string `json:"url"`
	}

	ErrorResponse struct {
		Message string `json:"error"`
	}
)

func HandleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	lctx, _ := lambdacontext.FromContext(ctx)

	// Set logs to JSON format for Lambda
	logger.SetFormatter(log.JSONFormatter)
	logger.Debug("Received event",
		"event", event,
		"requestID", lctx.AwsRequestID,
	)

	var input InputRequest

	// Get the input JSON
	switch event.HTTPMethod {
	case http.MethodGet:
		if v, ok := event.QueryStringParameters["url"]; ok {
			input.URL = v
		}
	case http.MethodPost:
		err := json.Unmarshal([]byte(event.Body), &input)
		if err != nil {
			e := ErrorResponse{Message: "Invalid JSON payload."}
			b, _ := json.Marshal(e)

			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       string(b),
			}, nil
		}
	default:
		e := ErrorResponse{Message: "Only GET and POST methods are supported."}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 405,
			Body:       string(b),
		}, nil
	}

	pp := debug.GetSpew()
	pp.Dump(input)

	// Handle the correct test
	switch event.Path {
	case "/http":
		return handleLambdaHTTP(input)
	case "/tls":
		return handleLambdaTLS(input)
	}

	// Return an error if the path is invalid
	eMsg := "Invalid endpoint path: %s. See https://devsec.tools/api for more information."
	e := ErrorResponse{Message: fmt.Sprintf(eMsg, event.Path)}
	b, _ := json.Marshal(e)

	return events.APIGatewayProxyResponse{
		StatusCode: 400,
		Body:       string(b),
	}, nil
}

func handleLambdaHTTP(input InputRequest) (events.APIGatewayProxyResponse, error) {
	domain, err := httptls.ParseDomain(input.URL)
	if err != nil {
		e := ErrorResponse{Message: "Could not understand given URL."}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       string(b),
		}, nil
	}

	var result httptls.HTTPResult

	result, err = httptls.GetSupportedHTTPVersions(domain, httptls.Options{
		Logger:         logger,
		TimeoutSeconds: 3,
	})
	if err != nil {
		e := ErrorResponse{Message: fmt.Sprintf("Error when testing the endpoint: %s", err.Error())}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       string(b),
		}, nil
	}

	// No results AND ALSO not in quiet mode
	if !result.HTTP11 && !result.HTTP2 && !result.HTTP3 {
		e := ErrorResponse{Message: fmt.Sprintf(
			"The hostname `%s` does not support ANY versions of HTTP. It is probable that "+
				"either the hostname is incorrect, or the website is down.",
			domain,
		)}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       string(b),
		}, nil
	}

	b, err := json.Marshal(result)
	if err != nil {
		e := ErrorResponse{Message: fmt.Sprintf("Error when preparing results as JSON: %s", err.Error())}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       string(b),
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(b),
	}, nil
}

func handleLambdaTLS(input InputRequest) (events.APIGatewayProxyResponse, error) {
	domain, err := httptls.ParseDomain(input.URL)
	if err != nil {
		e := ErrorResponse{Message: "Could not understand given URL."}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       string(b),
		}, nil
	}

	var result httptls.TLSResult

	host, port, err := httptls.ParseHostPort(domain)
	if err != nil {
		e := ErrorResponse{Message: "Could not understand given domain/port."}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       string(b),
		}, nil
	}

	result, err = httptls.GetSupportedTLSVersions(host, port, httptls.Options{
		Logger:         logger,
		TimeoutSeconds: 3,
	})
	if err != nil {
		e := ErrorResponse{Message: fmt.Sprintf("Error when testing the endpoint: %s", err.Error())}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       string(b),
		}, nil
	}

	b, err := json.Marshal(result)
	if err != nil {
		e := ErrorResponse{Message: fmt.Sprintf("Error when preparing results as JSON: %s", err.Error())}
		b, _ := json.Marshal(e)

		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       string(b),
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(b),
	}, nil
}

// client, cacheManager, err := GetValkeyCacheClient()
// if err != nil {
// }

// 			h := sha256.New()
// 			h.Write([]byte(domain))
// 			hash := hex.EncodeToString(h.Sum(nil))
// 			key := "http-" + hash

// 			data, err := cacheManager.Get(ctx, key)
// 			if err != nil {

// 				e = cacheManager.Set(ctx, key, string(b), store.WithExpiration(60*time.Minute))
// 				if e != nil {
// 					logger.Error(e)
// 					os.Exit(1)
// 				}

// 				return
// 			}

// c := *client
// c.Close()
