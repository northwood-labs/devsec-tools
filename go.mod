module github.com/northwood-labs/devsec-tools

go 1.25.0

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
	github.com/aws/aws-lambda-go v1.52.0
	github.com/charmbracelet/huh/spinner v0.0.0-20251215014908-6f7d32faaff3
	github.com/charmbracelet/lipgloss v1.1.1-0.20250404203927-76690c660834
	github.com/charmbracelet/log v1.0.0
	github.com/eko/gocache/lib/v4 v4.2.3
	github.com/goware/urlx v0.3.2
	github.com/northwood-labs/cli-helpers v0.0.0-20251204230858-4e677c65594c
	github.com/northwood-labs/gocache-valkey/v4 v4.0.0-20241219051326-219069e441d4
	github.com/quic-go/quic-go v0.59.0
	github.com/spf13/cobra v1.10.2
	github.com/valkey-io/valkey-go v1.0.74
	github.com/valkey-io/valkey-go/valkeycompat v1.0.74
	github.com/zmap/zcrypto v0.0.0-20250129210703-03c45d0bae98
	golang.org/x/exp v0.0.0-20260112195511-716be5621a96
	golang.org/x/net v0.53.0
)

require (
	github.com/PuerkitoBio/purell v1.2.1 // indirect
	github.com/alecthomas/chroma/v2 v2.23.1 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/bubbles v0.21.0 // indirect
	github.com/charmbracelet/bubbletea v1.3.10 // indirect
	github.com/charmbracelet/colorprofile v0.4.1 // indirect
	github.com/charmbracelet/glamour v0.10.0 // indirect
	github.com/charmbracelet/x/ansi v0.11.4 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.14 // indirect
	github.com/charmbracelet/x/exp/slice v0.0.0-20260122224438-b01af16209d9 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.7.0 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.4.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/go-logfmt/logfmt v0.6.1 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lithammer/dedent v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/microcosm-cc/bluemonday v1.0.27 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/northwood-labs/archstring v0.0.0-20240514202917-e9357b4b91c8 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/weppos/publicsuffix-go v0.50.3-0.20260108123922-15eaa75052c0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/yuin/goldmark v1.7.16 // indirect
	github.com/yuin/goldmark-emoji v1.0.6 // indirect
	github.com/zmap/rc2 v0.0.0-20190804163417-abaa70531248 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/term v0.42.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/Sirupsen/logrus => github.com/sirupsen/logrus v1.9.3
