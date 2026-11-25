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

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.2.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/precinto

.PHONY: all build build-testing build-linux build-windows test test-race test-crash test-e2e test-integration crossgroup crossgroup-crash vet vet-crossgroup vet-windows lint linters fmt fmt-check arch api-doc api-check hygiene codex-plugin-check clean ci

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

## build-windows: cross-compile check; the Windows binary refuses everything
## (on Windows, Precinto runs inside WSL2)
build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build ./...
	GOOS=windows GOARCH=arm64 $(GO) build ./...

## test: unit + integration tests (testing tag; no network, no real harness data)
test:
	$(GO) test -tags testing ./...

## test-race: unit + integration tests under the race detector
test-race:
	$(GO) test -race -tags testing ./...

## crossgroup: tests that need every group's real implementation (build tag
## crossgroup: test/integration flows, adapters over agenttest); they compile
## in every worktree and pass once the groups are integrated. Bounded at 8 min
## with every goroutine's stack on a hang (TESTPLAN §10).
crossgroup:
	GOTRACEBACK=all $(GO) test -tags testing,crossgroup -timeout 8m ./...

## crossgroup-crash: the crossgroup crash rows (failpoints over the real
## groups) of the crash-matrix packages; test-crash keeps its own list.
## Bounded and traced like crossgroup (TESTPLAN §10).
crossgroup-crash:
	GOTRACEBACK=all $(GO) test -tags testing,failpoints,crossgroup -count=1 -timeout 8m ./internal/fsx/... ./internal/capsule/... ./internal/sweep/... ./internal/live/...

## test-integration: cross-package flows against the testing binary (crossgroup)
test-integration:
	$(GO) test -tags testing,crossgroup -count=1 ./test/integration/...

## test-crash: crash-injection matrix (docs/TESTPLAN.md §4), CRASH_COUNT
## times in a row (crash.yml runs it 5 times to find rows that fail only now
## and then)
CRASH_COUNT ?= 1
test-crash:
	$(GO) test -tags testing,failpoints -count=$(CRASH_COUNT) -timeout 45m ./internal/fsx/... ./internal/capsule/... ./internal/sweep/... ./internal/live/...

## test-e2e: opt-in E2E against real harnesses in throwaway homes (PRECINTO_E2E=1);
## 30 min: SEC-14 alone needs about 7 and skips itself when less than 9 remain.
## PRECINTO_E2E_CLAUDE / PRECINTO_E2E_CODEX pick the harness binary (absolute paths);
## without ANTHROPIC_API_KEY the model-dependent checks are skipped (TESTPLAN §2)
test-e2e:
	PRECINTO_E2E=1 $(GO) test -tags testing -count=1 -timeout 30m -run 'E2E' ./...

## vet: go vet for {default, testing+failpoints} × {darwin, linux} (TESTPLAN §10);
## GOOS is explicit, so a Linux runner vets the darwin files too
vet:
	GOOS=darwin $(GO) vet ./...
	GOOS=darwin $(GO) vet -tags testing,failpoints ./...
	GOOS=linux $(GO) vet ./...
	GOOS=linux $(GO) vet -tags testing,failpoints ./...

## vet-crossgroup: the crossgroup tests compile on darwin and linux, with
## and without failpoints (crossgroup-crash builds testing+failpoints+crossgroup)
vet-crossgroup:
	GOOS=darwin $(GO) vet -tags testing,crossgroup ./...
	GOOS=darwin $(GO) vet -tags testing,failpoints,crossgroup ./...
	GOOS=linux $(GO) vet -tags testing,crossgroup ./...
	GOOS=linux $(GO) vet -tags testing,failpoints,crossgroup ./...

## vet-windows: go vet for GOOS=windows with the default, testing,
## testing+failpoints, testing+crossgroup and testing+failpoints+crossgroup tags
vet-windows:
	GOOS=windows $(GO) vet ./...
	GOOS=windows $(GO) vet -tags testing ./...
	GOOS=windows $(GO) vet -tags testing,failpoints ./...
	GOOS=windows $(GO) vet -tags testing,crossgroup ./...
	GOOS=windows $(GO) vet -tags testing,failpoints,crossgroup ./...

## lint: formatting, vet, architecture contract, API doc drift, linters;
## `make -k lint` runs every one of them even when an earlier one fails
lint: fmt-check vet vet-crossgroup arch api-check linters

# STATICCHECK_MATRIX: the builds staticcheck checks in one run, {darwin,
# linux, windows} × {default, testing+failpoints+crossgroup}: -matrix
# reports code as unused only when no build uses it (a helper of tagged
# tests, a darwin-only function in a shared file).
STATICCHECK_MATRIX := 'darwin: GOOS=darwin' 'darwintests: GOOS=darwin -tags=testing,failpoints,crossgroup' \
	'linux: GOOS=linux' 'linuxtests: GOOS=linux -tags=testing,failpoints,crossgroup' \
	'windows: GOOS=windows' 'windowstests: GOOS=windows -tags=testing,failpoints,crossgroup'

## linters: staticcheck (STATICCHECK_MATRIX), govulncheck and shellcheck of
## the hook shims; each runs even when another fails, and the target fails
## when any did. A missing staticcheck or govulncheck is skipped; a missing
## shellcheck fails in CI (TESTPLAN §10).
linters:
	@rc=0; \
	if command -v staticcheck >/dev/null 2>&1; then \
		printf '%s\n' $(STATICCHECK_MATRIX) | staticcheck -matrix ./... || rc=1; \
	else echo "lint: staticcheck not installed, skipped"; fi; \
	if command -v govulncheck >/dev/null 2>&1; then govulncheck ./... || rc=1; \
	else echo "lint: govulncheck not installed, skipped"; fi; \
	if command -v shellcheck >/dev/null 2>&1; then \
		for f in plugin/scripts/precinto-hook plugins/codex/scripts/precinto-hook; do \
			if [ -f "$$f" ]; then shellcheck -s sh "$$f" || rc=1; fi; \
		done; \
	elif [ -n "$$CI" ]; then echo "lint: shellcheck is required in CI (TESTPLAN §10)"; rc=1; \
	else echo "lint: shellcheck not installed, skipped"; fi; \
	exit $$rc

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
## SHA-256 list (D41, D78: a change updates the list in the same change)
codex-plugin-check:
	$(GO) test -tags testing -count=1 -run 'TestCodexPluginByteStable' ./test/integration/

clean:
	rm -rf bin

## ci: everything CI runs on every change (E2E never runs by default)
ci: lint build-windows vet-windows build build-linux build-testing test hygiene codex-plugin-check
