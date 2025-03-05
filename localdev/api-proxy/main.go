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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/northwood-labs/debug"
)

type (
	// QueryString represents the query string parameters that DevSec Tools
	// cares about.
	QueryString struct {
		URL string `json:"url" form:"url"`
	}

	// LambdaGetRequest represents the shape of the GET request that the local
	// Lambda environment understands.
	LambdaGetRequest struct {
		HTTPMethod  string            `json:"httpMethod"`
		Path        string            `json:"path"`
		QueryString map[string]string `json:"queryStringParameters"`
	}

	// LambdaPostRequest represents the shape of the POST request that the local
	// Lambda environment understands.
	LambdaPostRequest struct {
		HTTPMethod string `json:"httpMethod"`
		Path       string `json:"path"`
		Body       string `json:"body"`
	}

	// LambdaResponse represents the shape of the response from the local Lambda
	// environment.
	LambdaResponse struct {
		StatusCode int    `json:"statusCode,omitempty"`
		Body       string `json:"body,omitempty"`
	}
)

func main() {
	r := gin.Default()

	// r.SetTrustedProxies([]string{
	// 	"127.0.0.1",
	// })

	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "OPTIONS", "POST"},
		AllowHeaders:     []string{"Origin"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/domain", handleRequest)
	r.POST("/domain", handleRequest)

	r.GET("/http", handleRequest)
	r.POST("/http", handleRequest)

	r.GET("/tls", handleRequest)
	r.POST("/tls", handleRequest)

	r.Run()
}

func handleRequest(c *gin.Context) {
	var qs QueryString

	if c.Bind(&qs) == nil {
		var (
			result *LambdaResponse
			err    error
		)

		// Wrap the received request in a LambdaRequest so that we can forward
		// it to the Lambda environment.
		switch c.Request.Method {
		case "GET":
			requestBody := LambdaGetRequest{
				HTTPMethod: c.Request.Method,
				Path:       c.Request.URL.Path,
				QueryString: map[string]string{
					"url": qs.URL,
				},
			}

			b, _ := json.Marshal(requestBody)

			result, err = Send(string(b))
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": err.Error(),
				})
			}

			pp := debug.GetSpew()
			pp.Dump(result.Body)

			var body map[string]interface{}

			err = json.Unmarshal([]byte(result.Body), &body)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": err.Error(),
				})
			}

			c.JSON(result.StatusCode, body)

		case "POST":
			b, _ := json.Marshal(&qs)

			requestBody := LambdaPostRequest{
				HTTPMethod: c.Request.Method,
				Path:       c.Request.URL.Path,
				Body:       string(b),
			}

			b, _ = json.Marshal(requestBody)

			result, err = Send(string(b))
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": err.Error(),
				})
			}

			var body map[string]interface{}

			err = json.Unmarshal([]byte(result.Body), &body)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": err.Error(),
				})
			}

			c.JSON(result.StatusCode, body)

		default:
			c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{
				"error": "Only GET and POST methods are supported.",
			})
		}
	}
}

func Send(body string) (*LambdaResponse, error) {
	var result LambdaResponse

	client := &http.Client{
		Timeout: time.Duration(90) * time.Second,
	}

	req, err := http.NewRequest(
		"GET",
		"http://traefik:80/2015-03-31/functions/function/invocations",
		strings.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Need to explicitly set the `Host` header because we're calling Traefik
	// from container to container.
	req.Host = "lambda.devsec.local"

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed to send: %w", err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	err = json.Unmarshal(b, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return &result, nil
}
