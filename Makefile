#-------------------------------------------------------------------------------
# Running `make` will show the list of subcommands that will run.

SHELL:=bash
BINARY_NAME=devsec-tools
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(dir $(mkfile_path))

#-------------------------------------------------------------------------------
# Global stuff.

GO=$(shell which go)
HOMEBREW_PACKAGES=bash coreutils editorconfig-checker findutils git git-cliff git-lfs go grep jq nodejs pre-commit python@3.11 trivy trufflesecurity/trufflehog/trufflehog
NEXT_VERSION ?= $(shell git cliff --bump --unreleased --context | jq -r .[0].version)

# Determine the operating system and CPU arch.
OS=$(shell uname -o | tr '[:upper:]' '[:lower:]')

# Determine which version of `echo` to use. Use version from coreutils if available.
ECHOCHECK_HOMEBREW_AMD64 := $(shell command -v /usr/local/opt/coreutils/libexec/gnubin/echo 2> /dev/null)
ECHOCHECK_HOMEBREW_ARM64 := $(shell command -v /opt/homebrew/opt/coreutils/libexec/gnubin/echo 2> /dev/null)

ifdef ECHOCHECK_HOMEBREW_AMD64
	ECHO=/usr/local/opt/coreutils/libexec/gnubin/echo -e
else ifdef ECHOCHECK_HOMEBREW_ARM64
	ECHO=/opt/homebrew/opt/coreutils/libexec/gnubin/echo -e
else ifeq ($(findstring linux,$(OS)), linux)
	ECHO=echo -e
else
	ECHO=echo
endif

#-------------------------------------------------------------------------------
# Running `make` will show the list of subcommands that will run.

all: help

.PHONY: help
## help: [help]* Prints this help message.
help:
	@ $(ECHO) "Usage:"
	@ $(ECHO) ""
	@ sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /' | \
		while IFS= read -r line; do \
			if [[ "$$line" == *"]*"* ]]; then \
				$(ECHO) "\033[1;33m$$line\033[0m"; \
			else \
				$(ECHO) "$$line"; \
			fi; \
		done

#-------------------------------------------------------------------------------
# Installation

.PHONY: install-tools-go
## install-tools-go: [tools]* Install/upgrade the required Go packages.
install-tools-go:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Installing Go packages...\033[0m"
	$(GO) install github.com/antham/gommit@latest
	$(GO) install github.com/google/osv-scanner/cmd/osv-scanner@v1
	$(GO) install github.com/goph/licensei/cmd/licensei@latest
	$(GO) install github.com/mdempsky/unconvert@latest
	$(GO) install github.com/nikolaydubina/go-binsize-treemap@latest
	$(GO) install github.com/nikolaydubina/go-cover-treemap@latest
	$(GO) install github.com/nikolaydubina/smrcptr@latest
	$(GO) install github.com/orlangure/gocovsh@latest
	$(GO) install github.com/pelletier/go-toml/v2/cmd/tomljson@latest
	$(GO) install github.com/quasilyte/go-consistent@latest
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	$(GO) install golang.org/x/perf/cmd/benchstat@latest
	$(GO) install golang.org/x/tools/cmd/godoc@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GO) install gotest.tools/gotestsum@latest
	$(GO) install github.com/spf13/cobra-cli@latest

.PHONY: install-tools-mac
## install-tools-mac: [tools]* Install/upgrade the required tools for macOS, including Go packages.
install-tools-mac: install-tools-go
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Installing required packages for macOS (Homebrew)...\033[0m"
	brew update && brew install $(HOMEBREW_PACKAGES) && brew upgrade $(HOMEBREW_PACKAGES)
	curl -sSLf https://raw.githubusercontent.com/mtdowling/chag/master/install.sh | sudo bash

	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33mTo update to the latest versions, run:\033[0m"
	@ $(ECHO) "\033[1;33m    brew update && brew upgrade\033[0m"
	@ $(ECHO) " "

.PHONY: install-hooks
## install-hooks: [tools]* Install/upgrade the Git hooks used for ensuring consistency.
install-hooks:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Installing Git hooks...\033[0m"
	cp -vf .githooks/commit-msg.sh .git/hooks/commit-msg
	chmod +x .git/hooks/*
	pre-commit install

	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33mLearn more about `pre-commit` at:\033[0m"
	@ $(ECHO) "\033[1;33m    https://pre-commit.com\033[0m"
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33mLearn more about `gommit` at:\033[0m"
	@ $(ECHO) "\033[1;33m    https://github.com/antham/gommit\033[0m"
	@ $(ECHO) " "

#-------------------------------------------------------------------------------
# Compile

.PHONY: tidy
## tidy: [build] Updates go.mod and downloads dependencies.
tidy:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Tidy and download the Go dependencies...\033[0m"
	$(GO) mod tidy -go=1.21.7 -v

.PHONY: godeps
## godeps: [build] Updates go.mod and downloads dependencies.
godeps:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Upgrade the minor versions of Go dependencies...\033[0m"
	$(GO) get -d -u -t -v ./...

.PHONY: build
## build: [build]* Builds and installs the binary locally.
build: tidy
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Building and installing locally...\033[0m"
	$(GO) install -a -ldflags="-s -w" .

#-------------------------------------------------------------------------------
# Clean

.PHONY: clean-go
## clean-go: [clean] Clean Go's module cache.
clean-go:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Cleaning Go cache...\033[0m"
	$(GO) clean -i -r -x -testcache -modcache -cache

.PHONY: clean-bench
## clean-bench: [clean] Cleans all benchmarking-related files.
clean-bench:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Cleaning artifacts from benchmarks...\033[0m"
	- find . -type f -name "__*.out" | xargs rm -Rf
	- find . -type f -name "*.test" | xargs rm -Rf

.PHONY: clean
## clean: [clean]* Runs ALL cleaning tasks (except the Go cache).
clean: clean-bench

#-------------------------------------------------------------------------------
# Documentation

.PHONY: docs
## docs: [docs]* Runs primary documentation tasks.
docs: docs-cli

.PHONY: docs-cli
## docs-cli: [docs] Preview the Go library documentation on the CLI.
docs-cli:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Displaying Go CLI documentation...\033[0m"
	@ find ./pkg/* -type d -exec $(GO) doc -all {} \;

.PHONY: docs-serve
## docs-serve: [docs] Preview the Go library documentation as displayed on pkg.go.dev.
docs-serve:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Displaying Go HTTP documentation...\033[0m"
	open http://localhost:6060/pkg/github.com/northwood-labs/devsec-tools/pkg/
	godoc -index -links

#-------------------------------------------------------------------------------
# Linting

.PHONY: pre-commit
## pre-commit: [lint]* Runs `pre-commit` against all files.
pre-commit:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Running pre-commit...\033[0m"
	pre-commit run --all-files

.PHONY: license
## license: [lint]* Checks the licenses of all files and dependencies.
license:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Checking license usage...\033[0m"
	@ - trivy fs --config trivy-license.yaml --format json . 2>/dev/null > .licenses.cache.json
	@ cat .licenses.cache.json | jq -Mr '[.Results[] | select(.Class == "license") | select(.Licenses) | .Licenses[]] | [group_by(.Name) | .[] | {Name: .[0].Name, Count: length} | "\(.Name): \(.Count)"] | .[]'

	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Checking license headers...\033[0m"
	@ $(ECHO) "Missing/outdated:"
	@ - licensei header

.PHONY: lint
## lint: [lint]* Runs ALL linting/validation tasks.
lint: license pre-commit

#-------------------------------------------------------------------------------
# Testing
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
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Unit tests...\033[0m"
	@ $(ECHO) "make unit"
	@ cat **/*_test.go | ggrep "func Test" | gsed 's/func\s//g' | gsed -r 's/\(.*//g' | gsed -r 's/Test/make unit NAME=/g'

	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Example tests...\033[0m"
	@ $(ECHO) "make examples"
	@ cat **/*_test.go | ggrep "func Example" | gsed 's/func\s//g' | gsed -r 's/\(.*//g' | gsed -r 's/Example/make examples NAME=/g'

	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Fuzzing tests...\033[0m"
	@ $(ECHO) "make fuzz"

.PHONY: unit
## unit: [test] Runs unit tests. Set NAME= (without 'Test') to run a specific test by name.
unit:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Running unit tests...\033[0m"
	gotestsum --format testname -- -run=Test$(NAME) -count=1 -parallel=$(shell nproc) -timeout 30s -coverpkg=./... -coverprofile=__coverage.out -v ./...
	@ go-cover-treemap -coverprofile __coverage.out > unit-coverage.svg
	@ rsvg-convert --width=2000 --format=png --output="unit-coverage.png" "unit-coverage.svg"

.PHONY: mutate
## mutate: [test] Runs mutation tests.
mutate:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Running mutation tests...\033[0m"
	$(GO) test -tags=mutation -count=1 -parallel=$(shell nproc) -timeout 30s -ooze.v=true | ggrep -v "^[[:lower:]]" | ggrep -v "^)"

.PHONY: examples
## examples: [test] Runs tests for examples. Set NAME= (without 'Example') to run a specific test by name.
examples:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Running tests for examples...\033[0m"
	gotestsum --format testname -- -run=Example$(NAME) -count=1 -parallel=$(shell nproc) -timeout 30s -coverpkg=./... -coverprofile=__coverage.out -v ./...

.PHONY: fuzz
## fuzz: [test]* Runs the fuzzer for 1 minute per test.
fuzz:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Running the fuzzer (https://go.dev/doc/tutorial/fuzz)...\033[0m"
	$(GO) test -list=Fuzz ./... | grep ^Fuzz | xargs -I% $(GO) test -run='^$$' -fuzz=% -fuzztime 1m -v ./...

.PHONY: quickbench
## quickbench: [test]* Runs the benchmarks with minimal data for a quick check.
quickbench:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Running "quick" benchmark...\033[0m"
	$(GO) test -bench=. -timeout 5m ./...

.PHONY: bench
## bench: [test]* Runs the benchmarks with enough data for analysis with benchstat.
bench:
	@ $(ECHO) " "
	@ $(ECHO) "\033[1;33m=====> Running "full" benchmark...\033[0m"
	$(GO) test -bench=. -count=6 -timeout 60m -benchmem -cpuprofile=__cpu.out -memprofile=__mem.out -trace=__trace.out ./... | tee __bench-$(shell date --utc "+%Y%m%dT%H%M%SZ").out

.PHONY: view-cov-cli
## view-cov-cli: [test] After running test or unittest, this will view the coverage report on the CLI.
view-cov-cli:
	gocovsh --profile=__coverage.out

.PHONY: view-cov-html
## view-cov-html: [test] After running test or unittest, this will launch a browser to view the coverage report.
view-cov-html:
	$(GO) tool cover -html=__coverage.out

.PHONY: view-cpupprof
## view-cpupprof: [test] After running bench, this will launch a browser to view the CPU profiler results.
view-cpupprof:
	$(GO) tool pprof -http :8080 __cpu.out

.PHONY: view-mempprof
## view-mempprof: [test] After running bench, this will launch a browser to view the memory profiler results.
view-mempprof:
	$(GO) tool pprof -http :8080 __mem.out

.PHONY: view-trace
## view-trace: [test] After running bench, this will launch a browser to view the trace results.
view-trace:
	$(GO) tool trace __trace.out

#-------------------------------------------------------------------------------
# Git Tasks

.PHONY: changelog
## changelog: [release]* Generates the CHANGELOG for the release.
changelog:
	git cliff -o CHANGELOG.md
	pre-commit run --all-files markdownlint

.PHONY: tag
## tag: [release]* Tags (and GPG-signs) the release.
tag:
	@ if [ $$(git status -s -uall | wc -l) != 1 ]; then echo 'ERROR: Git workspace must be clean.'; exit 1; fi;

	@ $(ECHO) "This release will be tagged as: v$(NEXT_VERSION)"
	@ $(ECHO) "---------------------------------------------------------------------"
	@ read -p "Press any key to continue, or press Control+C to cancel. " x;

	@ $(ECHO) " "
	@ chag update v$(NEXT_VERSION)
	@ $(ECHO) " "

	@ $(ECHO) "These are the contents of the CHANGELOG for this release. Are these correct?"
	@ $(ECHO) "---------------------------------------------------------------------"
	@ chag contents
	@ $(ECHO) "---------------------------------------------------------------------"
	@ $(ECHO) "Are these release notes correct? If not, cancel and update CHANGELOG.md."
	@ read -p "Press any key to continue, or press Control+C to cancel. " x;

	@ $(ECHO) " "

	git add .
	git commit -a -m "relprep: Preparing the v$(NEXT_VERSION) release." --no-verify
	chag tag --sign
