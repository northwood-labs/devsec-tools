module github.com/northwood-labs/devsec-tools

go 1.23.0

toolchain go1.23.4

godebug (
	default=go1.21

	// In Go 1.23 3DES cipher suites were removed from the default list. This will re-enable them.
	// https://cs.opensource.google/go/go/+/refs/tags/go1.23.5:src/crypto/tls/cipher_suites.go;l=360-365
	tls3des=1

	// In Go 1.22 RSA key exchange based cipher suites were removed from the
	// default list. This will re-enable them.
	// https://cs.opensource.google/go/go/+/refs/tags/go1.23.5:src/crypto/tls/cipher_suites.go;l=348-358
	tlsrsakex=1
)

require (
	github.com/aws/aws-lambda-go v1.47.0
	github.com/charmbracelet/huh/spinner v0.0.0-20241216182847-438e4f741435
	github.com/charmbracelet/lipgloss v1.0.0
	github.com/charmbracelet/log v0.4.0
	github.com/eko/gocache/lib/v4 v4.1.6
	github.com/goware/urlx v0.3.2
	github.com/northwood-labs/cli-helpers v0.0.0-20241111201136-8e7d54066157
	github.com/northwood-labs/gocache-valkey/v4 v4.0.0-20241219051326-219069e441d4
	github.com/quic-go/quic-go v0.48.2
	github.com/spf13/cobra v1.8.1
	github.com/valkey-io/valkey-go v1.0.51
	github.com/valkey-io/valkey-go/valkeycompat v1.0.51
	golang.org/x/exp v0.0.0-20241217172543-b2144cdd0a67
	golang.org/x/net v0.33.0
)

require (
	github.com/PuerkitoBio/purell v1.2.1 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/bubbles v0.20.0 // indirect
	github.com/charmbracelet/bubbletea v1.2.5-0.20241205214244-9306010a31ee // indirect
	github.com/charmbracelet/x/ansi v0.6.0 // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/pprof v0.0.0-20241210010833-40e02aabc2ad // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lithammer/dedent v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.15.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/northwood-labs/archstring v0.0.0-20240514202917-e9357b4b91c8 // indirect
	github.com/onsi/ginkgo/v2 v2.22.0 // indirect
	github.com/onsi/gomega v1.35.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.20.5 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.61.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
	google.golang.org/protobuf v1.36.0 // indirect
)

replace github.com/Sirupsen/logrus => github.com/sirupsen/logrus v1.9.3
