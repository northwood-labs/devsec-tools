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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cache"
	"github.com/gin-contrib/cache/persistence"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"

	clihelpers "github.com/northwood-labs/cli-helpers"
	"github.com/northwood-labs/devsec-tools/pkg/httptls"
)

type QueryString struct {
	URL string `form:"url"`
}

// serveCmd represents the serve command
var (
	fServeDebug bool

	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Run a very simple local web server for development purposes only.",
		Long: clihelpers.LongHelpText(`
		Run a very simple local web server for development purposes only.

		Exposes a simple web server on http://localhost:8080 which matches the web
		interface provided by https://api.devsec.tools. This is not intended for
		any usage beyond local development.
		`),
		Run: func(cmd *cobra.Command, args []string) {
			r := gin.Default()

			// r.SetTrustedProxies([]string{
			// 	"127.0.0.1",
			// })

			if fServeDebug {
				pprof.Register(r)
			}

			r.Use(cors.New(cors.Config{
				AllowAllOrigins:  true,
				AllowMethods:     []string{"GET", "POST"},
				AllowHeaders:     []string{"Origin"},
				ExposeHeaders:    []string{"Content-Length"},
				AllowCredentials: true,
				MaxAge:           12 * time.Hour,
			}))

			r.Use(requestid.New(
				requestid.WithCustomHeaderStrKey("x-request-id"),
			))

			store := persistence.NewInMemoryStore(10 * time.Minute)

			r.GET("/http", cache.CachePage(store, time.Minute, handleHTTP))
			r.POST("/http", cache.CachePage(store, time.Minute, handleHTTP))

			r.GET("/tls", cache.CachePage(store, time.Minute, handleTLS))
			r.POST("/tls", cache.CachePage(store, time.Minute, handleTLS))

			r.Run()
		},
	}
)

func init() {
	serveCmd.Flags().BoolVarP(
		&fServeDebug, "serve-debug", "D", false, "Enable debug/profiling endpoints in the local web server.",
	)

	rootCmd.AddCommand(serveCmd)
}

func handleError(err error, c *gin.Context) {
	logger.Error(err)
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
		"error": err.Error(),
	})
}

func handleHTTP(c *gin.Context) {
	var qs QueryString

	if c.ShouldBind(&qs) == nil {
		domain, err := httptls.ParseDomain(qs.URL)
		if err != nil {
			handleError(err, c)

			return
		}

		result, err := httptls.GetSupportedHTTPVersions(domain, httptls.Options{
			Logger:         logger,
			TimeoutSeconds: fTimeout,
		})
		if err != nil {
			handleError(err, c)

			return
		}

		if !result.HTTP11 && !result.HTTP2 && !result.HTTP3 {
			err := errors.New(fmt.Sprintf(
				"The hostname `%s` does not support ANY versions of HTTP. It is probable that "+
					"the hostname is incorrect.",
				domain,
			))

			handleError(err, c)

			return
		}

		c.JSON(http.StatusOK, result)
	}
}

func handleTLS(c *gin.Context) {
	var qs QueryString

	if c.ShouldBind(&qs) == nil {
		domain, err := httptls.ParseDomain(qs.URL)
		if err != nil {
			handleError(err, c)

			return
		}

		host, port, err := httptls.ParseHostPort(domain)
		if err != nil {
			handleError(err, c)

			return
		}

		result, err := httptls.GetSupportedTLSVersions(host, port, httptls.Options{
			Logger:         logger,
			TimeoutSeconds: fTimeout,
		})
		if err != nil {
			handleError(err, c)

			return
		}

		c.JSON(http.StatusOK, result)
	}
}
