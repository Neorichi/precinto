# precinto — build entry points. Owner: G7 (docs/OWNERSHIP.md).
#
# go.mod pins `go 1.26.0` and `toolchain go1.26.11`; with GOTOOLCHAIN=auto any
# working go ≥ 1.21 downloads/uses that toolchain. Some dev machines have a
# broken /usr/local/go first on PATH, so GO picks the first go binary that
# actually runs. Override with `make GO=/path/to/go`.
GO ?= $(shell for g in $$(which -a go 2>/dev/null) /opt/homebrew/bin/go /usr/local/bin/go; do if "$$g" version >/dev/null 2>&1; then echo "$$g"; break; fi; done)

# gofmt of the selected toolchain (GOROOT resolves through GOTOOLCHAIN).
GOFMT ?= $(shell $(GO) env GOROOT)/bin/gofmt

CGO_ENABLED ?= 0
export CGO_ENABLED

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/precinto

.PHONY: all build build-testing build-linux test test-race test-crash test-e2e test-integration crossgroup vet vet-crossgroup lint fmt fmt-check arch api-doc api-check hygiene codex-plugin-check clean ci

all: build

## build: release-style binary (CGO disabled, trimpath)
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/precinto

## build-testing: binary honouring PRECINTO_HOME/PRECINTO_RUNTIME_DIR (D6), for integration tests
build-testing:
	$(GO) build -tags testing -o bin/precinto-testing ./cmd/precinto

## build-linux: cross-compile check
build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build ./...
	GOOS=linux GOARCH=arm64 $(GO) build ./...

## test: unit + integration tests (testing tag; no network, no real harness data)
test:
	$(GO) test -tags testing ./...

## test-race: unit + integration tests under the race detector
test-race:
	$(GO) test -race -tags testing ./...

## crossgroup: tests that need every group's real implementation (build tag
## crossgroup: test/integration flows, adapters over agenttest); they compile
## in every worktree and pass once the groups are integrated
crossgroup:
	$(GO) test -tags testing,crossgroup ./...

## test-integration: cross-package flows against the testing binary (crossgroup)
test-integration:
	$(GO) test -tags testing,crossgroup -count=1 ./test/integration/...

## test-crash: crash-injection matrix (docs/TESTPLAN.md §4)
test-crash:
	$(GO) test -tags testing,failpoints -count=1 ./internal/fsx/... ./internal/capsule/... ./internal/sweep/... ./internal/live/...

## test-e2e: opt-in E2E against real harnesses in throwaway homes (PRECINTO_E2E=1)
test-e2e:
	PRECINTO_E2E=1 $(GO) test -tags testing -count=1 -run 'E2E' ./...

## vet: go vet for {default, testing+failpoints} × {darwin, linux} (TESTPLAN §10)
vet:
	$(GO) vet ./...
	$(GO) vet -tags testing,failpoints ./...
	GOOS=linux $(GO) vet ./...
	GOOS=linux $(GO) vet -tags testing,failpoints ./...

## vet-crossgroup: the crossgroup tests compile on darwin and linux
vet-crossgroup:
	$(GO) vet -tags testing,crossgroup ./...
	GOOS=linux $(GO) vet -tags testing,crossgroup ./...

## lint: formatting, vet, architecture contract, API doc drift, optional linters
lint: fmt-check vet vet-crossgroup arch api-check
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "lint: staticcheck not installed, skipped"; fi
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "lint: govulncheck not installed, skipped"; fi
	@if command -v shellcheck >/dev/null 2>&1; then \
		for f in plugin/scripts/precinto-hook plugins/codex/scripts/precinto-hook; do [ -f "$$f" ] && shellcheck -s sh "$$f"; done; true; \
	else echo "lint: shellcheck not installed, skipped"; fi

## fmt: gofmt -w
fmt:
	$(GOFMT) -w .

fmt-check:
	@out="$$($(GOFMT) -l .)" || exit 1; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

## arch: package contract (owners, import allowlist, env access)
arch:
	$(GO) test -count=1 ./internal/archtest

## api-doc: regenerate the generated part of docs/API.md
api-doc:
	$(GO) run ./internal/archtest/apidoc -splice docs/API.md

api-check:
	$(GO) run ./internal/archtest/apidoc -check docs/API.md

## hygiene: no testdata/ file holds real paths, emails, tokens or non-fixture
## UUIDs (testkit.Hygiene, S13; TESTPLAN §10)
hygiene:
	$(GO) test -tags testing -count=1 -run 'TestTestdataHygiene' ./test/integration/

## codex-plugin-check: plugins/codex/ is byte-identical to its recorded
## SHA-256 list (D41; skipped until the list is recorded, D61)
codex-plugin-check:
	$(GO) test -tags testing -count=1 -run 'TestCodexPluginByteStable' ./test/integration/

clean:
	rm -rf bin

## ci: everything CI runs on every change (E2E never runs by default)
ci: lint build build-linux build-testing test hygiene codex-plugin-check
