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
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/log"
)

func GetLogger(fVerbose int, fJSON bool) *log.Logger {
	styles := log.DefaultStyles()

	// ERROR
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("ERROR").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("160")).
		Foreground(lipgloss.Color("255"))
	styles.Keys["err"] = lipgloss.NewStyle().Foreground(lipgloss.Color("160"))
	styles.Values["err"] = lipgloss.NewStyle().Bold(true)

	// WARN
	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().
		SetString("WARN").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("220")).
		Foreground(lipgloss.Color("232"))
	styles.Keys["warn"] = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styles.Values["warn"] = lipgloss.NewStyle().Bold(true)

	// INFO
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().
		SetString("INFO").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("21")).
		Foreground(lipgloss.Color("255"))
	styles.Keys["info"] = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	styles.Values["info"] = lipgloss.NewStyle().Bold(true)

	// DEBUG
	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().
		SetString("DEBUG").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("99")).
		Foreground(lipgloss.Color("11"))
	styles.Keys["debug"] = lipgloss.NewStyle().Foreground(lipgloss.Color("99"))
	styles.Values["debug"] = lipgloss.NewStyle().Bold(true)

	// Logger
	logger := log.NewWithOptions(os.Stderr, log.Options{
		Level:           log.ErrorLevel,
		ReportCaller:    false,
		ReportTimestamp: true,
		TimeFormat:      time.RFC3339Nano,
	})

	logger.SetStyles(styles)

	if os.Getenv("DST_LOG_JSON") == "true" || fJSON {
		logger.SetFormatter(log.JSONFormatter)
	}

	if os.Getenv("DST_LOG_VERBOSE") == "2" || fVerbose > 1 {
		logger.SetReportCaller(true)
		logger.SetLevel(log.DebugLevel)
	} else if os.Getenv("DST_LOG_VERBOSE") == "1" || fVerbose > 0 {
		logger.SetLevel(log.InfoLevel)
	}

	return logger
}

func NewTable(headers ...string) *table.Table {
	EvenRowStyle := lipgloss.NewStyle().
		Padding(0, 1).
		Background(lipgloss.Color("#171e21"))

	OddRowStyle := lipgloss.NewStyle().
		Padding(0, 1).
		Background(lipgloss.Color("0"))

	return table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("99"))).
		BorderColumn(true).
		StyleFunc(func(row, col int) lipgloss.Style {
			switch {
			case row%2 == 0:
				return EvenRowStyle
			default:
				return OddRowStyle
			}
		}).
		Headers(headers...)
}

func displayBool(b, useEmoji bool) string {
	yes := "YES"
	no := "NO"

	if useEmoji {
		yes = "✅"
		no = "❌"
	}

	if b {
		return yes
	}

	return no
}

func parseFlagAsBool(env string) bool {
	if os.Getenv(env) == "true" {
		return true
	}

	return false
}
