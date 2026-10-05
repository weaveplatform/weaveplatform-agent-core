SHELL := /bin/bash
.DEFAULT_GOAL := help

# Built outside any parent go.work: local runs match CI.
export GOWORK := off

GO ?= go
GOLANGCI_LINT ?= golangci-lint
BUF ?= buf
MODULE := $(shell GOWORK=off $(GO) list -m)
COVER_DIR := cover
BIN_DIR := bin
TOOL_DIR := .bin
GOOSES := linux darwin windows
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# The protoc plugins buf.gen.yaml runs, at the versions stamped in the
# committed internal/gen headers. A newer plugin would fail gen-check on a
# plugin release rather than on a proto change.
PROTOC_GEN_GO_VERSION := v1.36.11
PROTOC_GEN_GO_GRPC_VERSION := v1.6.1

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | column -t -s ':'

## fmt: apply the formatters configured in .golangci.yml
fmt:
	$(GOLANGCI_LINT) fmt --config .golangci.yml ./...

## lint: golangci-lint as linux, darwin and windows (build tags decide which files exist)
lint:
	@set -e; for os in $(GOOSES); do echo "== GOOS=$$os"; \
		GOOS=$$os $(GOLANGCI_LINT) run --config .golangci.yml --new=false --fix=false ./...; done

## vet: go vet as linux, darwin and windows
vet:
	@set -e; for os in $(GOOSES); do echo "== GOOS=$$os"; GOOS=$$os $(GO) vet ./...; done

## test: unit tests (race, shuffle); coverage to cover/unit
test:
	@rm -rf $(COVER_DIR)/unit && mkdir -p $(COVER_DIR)/unit
	$(GO) test -race -shuffle=on -count=1 -cover -coverpkg=$(MODULE)/... ./... -args -test.gocoverdir=$(CURDIR)/$(COVER_DIR)/unit

## cover: merge every cover/* directory and enforce .testcoverage.yml (>=95% total, >=90% per package)
cover:
	@dirs=$$(find $(COVER_DIR) -mindepth 1 -maxdepth 1 -type d ! -name '.merged' | paste -sd, -); \
	if [ -z "$$dirs" ]; then echo "no coverage data; run make test first"; exit 1; fi; \
	rm -rf $(COVER_DIR)/.merged && mkdir -p $(COVER_DIR)/.merged && \
	$(GO) tool covdata merge -i=$$dirs -o=$(COVER_DIR)/.merged && \
	$(GO) tool covdata textfmt -i=$(COVER_DIR)/.merged -o=$(COVER_DIR)/coverage.out && \
	$(GO) tool covdata percent -i=$(COVER_DIR)/.merged
	$(GO) tool go-test-coverage --config=.testcoverage.yml

## vuln: govulncheck as linux, darwin and windows (the tool is built for this machine first)
vuln:
	@mkdir -p $(TOOL_DIR) && $(GO) build -o $(TOOL_DIR)/govulncheck golang.org/x/vuln/cmd/govulncheck
	@set -e; for os in $(GOOSES); do echo "== GOOS=$$os"; GOOS=$$os $(TOOL_DIR)/govulncheck ./...; done

## build: cross-compile every cmd/* binary for each release platform into bin/ (CGO disabled)
build:
	@mkdir -p $(BIN_DIR)
	@for d in $$(find cmd -mindepth 1 -maxdepth 1 -type d); do \
		name=$${d#cmd/}; \
		for p in $(PLATFORMS); do \
			os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
			echo "$$name $$os/$$arch"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
				-o $(BIN_DIR)/$$name-$$os-$$arch$$ext ./$$d || exit 1; \
		done; \
	done

## tidy-check: go mod tidy changes nothing
tidy-check:
	$(GO) mod tidy
	git diff --exit-code go.mod go.sum

## protoc-plugins: install the pinned protoc plugins buf.gen.yaml runs
protoc-plugins:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

## buf-lint: lint proto/
buf-lint:
	$(BUF) lint

## gen: regenerate internal/gen from proto/
gen:
	$(BUF) generate

## gen-check: regenerate and fail if internal/gen differs from what is committed
gen-check: gen
	@if [ -n "$$(git status --porcelain -- internal/gen)" ]; then \
		git status --porcelain -- internal/gen; \
		echo "internal/gen differs from proto/: run 'make gen' and commit"; exit 1; fi

## core-independent: fail on any dependency on weaveplatform-agent-modules
core-independent:
	@set -e; forbidden='^github\.com/weaveplatform/weaveplatform-agent-modules([/ ]|$$)'; fail=0; \
	for os in $(GOOSES); do \
		if GOOS=$$os $(GO) list -deps -test ./... | grep -E "$$forbidden"; then \
			echo "GOOS=$$os: core imports weaveplatform-agent-modules"; fail=1; fi; \
	done; \
	if $(GO) list -m all | grep -E "$$forbidden"; then echo "go.mod requires weaveplatform-agent-modules"; fail=1; fi; \
	[ $$fail -eq 0 ] && echo "core depends on nothing in weaveplatform-agent-modules"

## fuzz: fuzz the handshake and manifest parsers (FUZZTIME, default 30s each)
FUZZTIME ?= 30s
fuzz:
	$(GO) test ./internal/protocol/handshake/ -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/protocol/manifest/ -run '^$$' -fuzz '^FuzzManifest$$' -fuzztime $(FUZZTIME)

## snapshot: goreleaser snapshot build (binaries, archives and the deb; unsigned)
snapshot:
	goreleaser release --snapshot --clean --skip=sign,publish

## package-test: postinstall creates the service account idempotently (in Docker; not part of gate)
PACKAGE_TEST_IMAGE ?= ubuntu:24.04
package-test:
	docker run --rm -v "$(CURDIR)/packaging/linux:/pkg:ro" $(PACKAGE_TEST_IMAGE) sh /pkg/postinstall_test.sh

## pkg-darwin: build the macOS installer package (darwin/arm64) into dist/ (needs macOS: pkgbuild)
PKG_VERSION ?= $(patsubst v%,%,$(VERSION))
DARWIN_BIN := $(BIN_DIR)/darwin-arm64
pkg-darwin: darwin-bin
	sh packaging/darwin/build-pkg.sh $(PKG_VERSION) $(DARWIN_BIN) dist

darwin-bin:
	@mkdir -p $(DARWIN_BIN)
	@for c in weaveboot weave-agent weavectl weavemanifest; do \
		CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DARWIN_BIN)/$$c ./cmd/$$c || exit 1; \
	done

## package-test-darwin: the plist, a postinstall dry run, uninstall and the built package's payload (needs macOS; installs nothing)
package-test-darwin: darwin-bin
	sh packaging/darwin/package_test.sh $(DARWIN_BIN)

## package-test-windows: Authenticode signing (sign.sh) end to end with a throwaway certificate (needs osslsigncode, openssl; reaches a public TSA)
package-test-windows:
	sh packaging/windows/sign_test.sh

## shellcheck: the macOS and Windows packaging scripts
shellcheck:
	shellcheck -s sh packaging/darwin/*.sh packaging/darwin/scripts/preinstall packaging/darwin/scripts/postinstall packaging/windows/*.sh

## gate: everything CI runs, in order
gate: vet lint test cover vuln build tidy-check buf-lint gen-check core-independent

.PHONY: help fmt lint vet test cover vuln build tidy-check protoc-plugins buf-lint gen gen-check core-independent fuzz snapshot package-test pkg-darwin darwin-bin package-test-darwin package-test-windows shellcheck gate
