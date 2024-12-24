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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/charmbracelet/log"
	"github.com/eko/gocache/lib/v4/store"

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

	// Log the input
	inputJSON, _ := json.Marshal(input)
	logger.Debug("Input:", "input", string(inputJSON))

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
	var (
		e    error
		err1 error
	)

	domain, err := httptls.ParseDomain(input.URL)
	if err != nil {
		e := ErrorResponse{Message: "Could not understand given URL."}
		b, _ := json.Marshal(e)

		logger.Error(err)

		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       string(b),
		}, nil
	}

	var result httptls.HTTPResult

	client, cacheManager, err := GetValkeyCacheClient()
	if err != nil {
		e := ErrorResponse{Message: "Unable to communicate with cache."}
		b, _ := json.Marshal(e)

		logger.Error(err)

		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       string(b),
		}, nil
	}

	c := *client
	defer c.Close()

	key := "http-" + hash(domain)

	data, err := cacheManager.Get(ctx, key)
	if err != nil {
		result, err1 = httptls.GetSupportedHTTPVersions(domain, httptls.Options{
			Logger:         logger,
			TimeoutSeconds: 3,
		})
		if err1 != nil {
			e := ErrorResponse{Message: fmt.Sprintf("Error when testing the endpoint: %s", err.Error())}
			b, _ := json.Marshal(e)

			logger.Error(err1)

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

		b, err1 := json.Marshal(result)
		if err1 != nil {
			e := ErrorResponse{Message: fmt.Sprintf("Error when preparing results as JSON: %s", err1.Error())}
			b, _ := json.Marshal(e)

			logger.Error(err1)

			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       string(b),
			}, nil
		}

		e = cacheManager.Set(ctx, key, string(b), store.WithExpiration(60*time.Minute)) // @TODO
		if e != nil {
			logger.Error(e)
		}

		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       string(b),
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(data),
	}, nil
}

func handleLambdaTLS(input InputRequest) (events.APIGatewayProxyResponse, error) {
	var err1 error

	domain, err := httptls.ParseDomain(input.URL)
	if err != nil {
		e := ErrorResponse{Message: "Could not understand given URL."}
		b, _ := json.Marshal(e)

		logger.Error(err)

		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       string(b),
		}, nil
	}

	var result httptls.TLSResult

	client, cacheManager, err := GetValkeyCacheClient()
	if err != nil {
		e := ErrorResponse{Message: "Unable to communicate with cache."}
		b, _ := json.Marshal(e)

		logger.Error(err)

		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       string(b),
		}, nil
	}

	c := *client
	defer c.Close()

	host, port, err := httptls.ParseHostPort(domain)
	if err != nil {
		e := ErrorResponse{Message: "Could not understand given domain/port."}
		b, _ := json.Marshal(e)

		logger.Error(err)

		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       string(b),
		}, nil
	}

	key := "tls-" + hash(host+":"+port)

	data, err := cacheManager.Get(ctx, key)
	if err != nil {
		result, err1 = httptls.GetSupportedTLSVersions(host, port, httptls.Options{
			Logger:         logger,
			TimeoutSeconds: 10,
		})
		if err1 != nil {
			e := ErrorResponse{Message: fmt.Sprintf("Error when testing the endpoint: %s", err1.Error())}
			b, _ := json.Marshal(e)

			logger.Error(err1)

			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       string(b),
			}, nil
		}

		b, err1 := json.Marshal(result)
		if err1 != nil {
			e := ErrorResponse{Message: fmt.Sprintf("Error when preparing results as JSON: %s", err1.Error())}
			b, _ := json.Marshal(e)

			logger.Error(err1)

			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       string(b),
			}, nil
		}

		e := cacheManager.Set(ctx, key, string(b), store.WithExpiration(60*time.Minute)) // @TODO
		if e != nil {
			logger.Error(e)
		}

		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       string(b),
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(data),
	}, nil
}

func hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}
