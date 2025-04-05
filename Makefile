include ./standard.mk

# go install golang.org/dl/go{VERSION}@latest
# go{VERSION} download
GO=$(shell which go)
HOMEBREW_PACKAGES=bash coreutils editorconfig-checker findutils git git-cliff git-lfs go grep jq k1LoW/tap/tbls nodejs pre-commit python@3.11 trivy trufflesecurity/trufflehog/trufflehog

#-------------------------------------------------------------------------------
# Environment

.PHONY: install-hooks
## install-hooks: [tools] Install/upgrade the Git hooks used for ensuring consistency.
install-hooks:
	@ $(HEADER) "=====> Installing Git hooks..."
	cp -vf .githooks/commit-msg.sh .git/hooks/commit-msg
	chmod +x .git/hooks/*
	pre-commit install

	@ $(BORDER) "Learn more about 'pre-commit' at:" "  https://pre-commit.com" " " "Learn more about 'gommit' at:" "  https://github.com/antham/gommit"

# goplicate-start:golang
#-------------------------------------------------------------------------------
# Go(lang)

.PHONY: tidy
## tidy: [go] Tidies go.mod and downloads dependencies.
tidy:
	@ $(HEADER) "=====> Tidy and download the Go dependencies..."
	$(GO) mod tidy -v

.PHONY: godeps
## godeps: [go] Attempts to perform a minor version upgrade of all Go dependencies.
godeps:
	@ $(HEADER) "=====> Upgrade the minor versions of Go dependencies..."
	find . -type f -name "go.mod" | xargs -I% dirname "%" | xargs -I@ bash -c 'cd "@" && $(GO) mod tidy -go=$(GO_VER) && $(GO) get -u -t -v ./...'

	@ $(HEADER) "=====> Keep zcrypto@03c45d0bae98..."
	$(GO) get github.com/zmap/zcrypto@03c45d0bae98

	@ echo ""
	@ $(YELLOW) "Run 'make tidy' to clean up the go.mod file."

.PHONY: clean-go
## clean-go: [clean] Clean Go's module cache.
clean-go:
	@ $(HEADER) "=====> Cleaning Go cache..."
	$(GO) clean -i -r -x -testcache -modcache -cache

.PHONY: clean-bench
## clean-bench: [clean] Cleans all benchmarking-related files.
clean-bench:
	@ $(HEADER) "=====> Cleaning artifacts from benchmarks..."
	- find . -type f -name "__*.out" | xargs -I% rm -fv "%"
	- find . -type f -name "*.test" | xargs -I% rm -fv "%"

.PHONY: docs
## docs: [docs]* Run all documentation tasks.
docs: docs-cli docs-serve

.PHONY: docs-cli
## docs-cli: [docs] Preview the Go library documentation on the CLI.
docs-cli:
	@ $(HEADER) "=====> Displaying Go CLI documentation..."
	$(GO) doc -C -all

.PHONY: docs-serve
## docs-serve: [docs] Preview the Go library documentation as displayed on pkg.go.dev.
docs-serve:
	@ $(HEADER) "=====> Displaying Go HTTP documentation..."
	open http://localhost:6060/pkg/github.com/northwood-labs/
	godoc -index -links

.PHONY: binsize
## binsize: [docs] Analyze the size of the binary by Go package.
binsize:
	@ $(HEADER) "=====> Displaying Go HTTP documentation..."
	$(GO) tool nm -size "$(GOBIN)/$(BINARY_NAME)" | go-binsize-treemap > binsize.svg
	rsvg-convert --width=2000 --format=png --output="binsize.png" "binsize.svg"

.PHONY: view-cov-cli
## view-cov-cli: [test] After running 'test' or 'unit', this will view the coverage report on the CLI.
view-cov-cli:
	gocovsh --profile=__coverage.out

.PHONY: view-cov-html
## view-cov-html: [test] After running 'test' or 'unit', this will launch a browser to view the coverage report.
view-cov-html:
	$(GO) tool cover -html=__coverage.out

.PHONY: view-cpupprof
## view-cpupprof: [test] After running 'bench', this will launch a browser to view the CPU profiler results.
view-cpupprof:
	$(GO) tool pprof -http :8080 __cpu.out

.PHONY: view-mempprof
## view-mempprof: [test] After running 'bench', this will launch a browser to view the memory profiler results.
view-mempprof:
	$(GO) tool pprof -http :8080 __mem.out

.PHONY: view-trace
## view-trace: [test] After running 'bench', this will launch a browser to view the trace results.
view-trace:
	$(GO) tool trace __trace.out

# goplicate-end:golang

# goplicate-start:linting
#-------------------------------------------------------------------------------
# Linting

.PHONY: pre-commit
## pre-commit: [lint]* Runs `pre-commit` against all files.
pre-commit:
	@ $(HEADER) "=====> Running pre-commit..."
	pre-commit run --all-files

.PHONY: license
## license: [lint]* Checks the licenses of all files and dependencies.
license:
	@ $(HEADER) "=====> Checking license usage..."
	@ - trivy fs --config trivy-license.yaml --format json . 2>/dev/null > .licenses.cache.json
	@ cat .licenses.cache.json | jq -Mr '[.Results[] | select(.Packages) | .Packages[] | select(.Licenses) | .Licenses[]] | to_entries | group_by(.value)[] | {Name: .[0].value, Count: length} | "\(.Name): \(.Count)"'

	@ $(HEADER) "=====> Checking license headers..."
	@ echo "Missing/outdated:"
	@ - licensei header

# goplicate-end:linting

# goplicate-start:git
#-------------------------------------------------------------------------------
# Git Tasks

.PHONY: changelog
## changelog: [release]* Generates the CHANGELOG for the release.
changelog:
	@ $(HEADER) "=====> Updating the CHANGELOG..."
	git cliff -o CHANGELOG.md

.PHONY: tag
## tag: [release]* Signs and tags the release.
tag:
	@ $(HEADER) "=====> Signing and tagging the release..."
	@ if [ $$(git status -s -uall | wc -l) != 1 ]; then $(ERROR) "Git workspace must be clean."; exit 1; fi;

	@ $(WHITE) "This release will be tagged as: $(NEXT_VERSION)"
	@ echo "---------------------------------------------------------------------"
	@ read -p "Press any key to continue, or press Control+C to cancel. " x;

	@ echo " "
	@ chag update $(NEXT_VERSION)
	@ echo " "

	@ $(HEADER) "These are the contents of the CHANGELOG for this release. Are these correct?"
	@ $(WHITE) "---------------------------------------------------------------------"
	@ chag contents
	@ $(WHITE) "---------------------------------------------------------------------"
	@ echo "Are these release notes correct? If not, cancel and update CHANGELOG.md."
	@ read -p "Press any key to continue, or press Control+C to cancel. " x;

	@ echo " "

	git add .
	git commit -a -m "relprep: Preparing the $(NEXT_VERSION) release." --no-verify
	chag tag --sign

# goplicate-end:git

#-------------------------------------------------------------------------------
# Specific to this project.

.PHONY: clean
## clean: [clean]* Run standard cleanup tasks.
clean: clean-ds clean-bench

.PHONY: lint
## lint: [lint]* Run linting tasks.
lint: license pre-commit

.PHONY: build
## build: [build]* Builds and installs the binary locally.
build: tidy
	@ $(HEADER) "=====> Building and installing locally..."
	CGO_ENABLED=0 $(GO) install -a -trimpath -ldflags="-s -w" .

.PHONY: build-serve
## build-serve: [build]* Builds the API proxy server for use with Docker Compose.
build-serve:
	@ $(HEADER) "=====> Building API proxy server..."
	cd localdev/api-proxy && \
		$(GO) mod tidy && \
		CGO_ENABLED=0 GOOS=linux $(GO) build -o serve .

.PHONY: build-provider-ir
## build-provider-ir: [build] Generates Terraform-OpenAPI IR.
build-provider-ir:
	@ $(HEADER) "=====> Generating Terraform-OpenAPI IR..."
	@ tfplugingen-openapi generate \
		--config internal/generator_config.yml \
		--output internal/framework_spec.json \
		openapi.json \
		;

.PHONY: build-provider-code
## build-provider-code: [build] Generates Terraform provider code.
build-provider-code:
	@ $(HEADER) "=====> Generating Terraform provider code..."
	@tfplugingen-framework generate all \
		--input internal/framework_spec.json \
		--output ./internal/provider \
		;

	@ tfplugingen-framework scaffold data-source \
		--name domain \
		--force \
		--output-dir ./internal/provider

	@ tfplugingen-framework scaffold data-source \
		--name http \
		--force \
		--output-dir ./internal/provider

	@ tfplugingen-framework scaffold data-source \
		--name tls \
		--force \
		--output-dir ./internal/provider

	@ cd internal/provider && \
		go mod init github.com/northwood-labs/devsec-tools/internal/provider && \
		go mod tidy

.PHONY: build-provider
## build-provider: [build] Builds a Terraform/OpenTofu provider from the OpenAPI spec.
build-provider: build-provider-ir build-provider-code

.PHONY: build-lambda
## build-lambda: [build]* Builds the Lambda function with current ARCH for local development.
build-lambda: tidy
	@ $(HEADER) "=====> Building Lambda function..."
	CGO_ENABLED=0 GOOS=linux $(GO) build -gcflags="all=-N -l" -tags lambda.norpc -o localdev/var-runtime/bootstrap .

.PHONY: build-lambda-prod
## build-lambda-prod: [build]* Builds the Lambda function for deployment.
build-lambda-prod: tidy
	@ $(HEADER) "=====> Building Lambda function..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -a -trimpath -ldflags="-s -w" -tags lambda.norpc -o bootstrap -v .

	@ $(HEADER) "=====> Zipping the Lambda function..."
	@ zip bootstrap.zip bootstrap
	@ output="$(shell realpath bootstrap.zip 2>&1)" && $(WHITE) "$$output"
	@ rm -f bootstrap

# https://github.com/golang/go/wiki/TableDrivenTests
# https://go.dev/doc/tutorial/fuzz
# https://pkg.go.dev/testing
# https://pkg.go.dev/golang.org/x/perf/cmd/benchstat

.PHONY: test
## test: [test]* Runs ALL tests.
test: unit examples mutate

.PHONY: list-tests
## list-tests: [test] Lists all of the tests that are available to run.
list-tests:
	@ $(HEADER) "=====> Unit tests..."
	@ echo "make unit"
	@ cat **/*_test.go | ggrep "func Test" | gsed 's/func\s//g' | gsed -r 's/\(.*//g' | gsed -r 's/Test/make unit NAME=/g'

	@ $(HEADER) "=====> Example tests..."
	@ echo "make examples"
	@ cat **/*_test.go | ggrep "func Example" | gsed 's/func\s//g' | gsed -r 's/\(.*//g' | gsed -r 's/Example/make examples NAME=/g'

	@ $(HEADER) "=====> Fuzzing tests..."
	@ $(ECHO) "make fuzz"

.PHONY: unit
## unit: [test] Runs unit tests. Set NAME= (without 'Test') to run a specific test by name.
unit:
	@ $(HEADER) "=====> Running unit tests..."
	gotestsum --format testname -- -run=Test$(NAME) -count=1 -parallel=$(shell nproc) -timeout 30s -coverpkg=./... -coverprofile=__coverage.out -v ./...
	@ go-cover-treemap -coverprofile __coverage.out > unit-coverage.svg
	@ rsvg-convert --width=2000 --format=png --output="unit-coverage.png" "unit-coverage.svg"

.PHONY: examples
## examples: [test] Runs tests for examples. Set NAME= (without 'Example') to run a specific test by name.
examples:
	@ $(HEADER) "=====> Running tests for examples..."
	gotestsum --format testname -- -run=Example$(NAME) -count=1 -parallel=$(shell nproc) -timeout 30s -coverpkg=./... -coverprofile=__coverage.out -v ./...

.PHONY: mutate
## mutate: [test] Runs mutation tests.
mutate:
	@ $(HEADER) "=====> Running mutation tests..."
	$(GO) test -tags=mutation -count=1 -parallel=$(shell nproc) -timeout 30s -ooze.v=true | ggrep -v "^[[:lower:]]" | ggrep -v "^)"

.PHONY: fuzz
## fuzz: [test]* Runs the fuzzer for 1 minute per test.
fuzz:
	@ $(HEADER) "=====> Running the fuzzer (https://go.dev/doc/tutorial/fuzz)..."
	$(GO) test -list=Fuzz ./... | grep ^Fuzz | xargs -I% $(GO) test -run='^$$' -fuzz=% -fuzztime 1m -v ./...

.PHONY: quickbench
## quickbench: [test]* Runs the benchmarks with minimal data for a quick check.
quickbench:
	@ $(HEADER) "=====> Running "quick" benchmark..."
	$(GO) test -bench=. -timeout 5m ./...

.PHONY: bench
## bench: [test]* Runs the benchmarks with enough data for analysis with benchstat.
bench:
	@ $(HEADER) "=====> Running "full" benchmark..."
	$(GO) test -bench=. -count=6 -timeout 60m -benchmem -cpuprofile=__cpu.out -memprofile=__mem.out -trace=__trace.out ./... | tee __bench-$(shell date --utc "+%Y%m%dT%H%M%SZ").out

#-------------------------------------------------------------------------------
# Installation

.PHONY: install-tools-go
## install-tools-go: [tools]* Install/upgrade the required Go packages.
install-tools-go:
	@ $(HEADER) "=====> Installing Go packages..."
	$(GO) install github.com/antham/gommit@latest
	$(GO) install github.com/google/osv-scanner/cmd/osv-scanner@v1
	$(GO) install github.com/google/yamlfmt/cmd/yamlfmt@latest
	$(GO) install github.com/goph/licensei/cmd/licensei@latest
	$(GO) install github.com/mdempsky/unconvert@latest
	$(GO) install github.com/nikolaydubina/go-binsize-treemap@latest
	$(GO) install github.com/nikolaydubina/go-cover-treemap@latest
	$(GO) install github.com/nikolaydubina/smrcptr@latest
	$(GO) install github.com/orlangure/gocovsh@latest
	$(GO) install github.com/pelletier/go-toml/v2/cmd/tomljson@latest
	$(GO) install github.com/quasilyte/go-consistent@latest
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	$(GO) install github.com/spf13/cobra-cli@latest
	$(GO) install golang.org/x/perf/cmd/benchstat@latest
	$(GO) install golang.org/x/tools/cmd/godoc@latest
	$(GO) install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GO) install gotest.tools/gotestsum@latest

.PHONY: install-tools-mac
## install-tools-mac: [tools]* Install/upgrade the required tools for macOS, including Go packages.
install-tools-mac: install-tools-go
	@ $(HEADER) "=====> Installing required packages for macOS (Homebrew)..."
	brew update && brew install $(HOMEBREW_PACKAGES) && brew upgrade $(HOMEBREW_PACKAGES)
	curl -sSLf https://raw.githubusercontent.com/mtdowling/chag/master/install.sh | sudo bash

	@ $(BORDER) "To update to the latest versions, run:" "    brew update && brew upgrade"
