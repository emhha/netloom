.DEFAULT_GOAL := help

GO ?= go
PYTHON ?= python3

.PHONY: help fmt fmt-check test vet build race integration integration-local integration-compile docs-check scripts-test wordlists-check check

help:
	@printf '%s\n' \
	  'Netloom development commands:' \
	  '  make check                Format, repository/docs, scripts, resources, tests, vet, build' \
	  '  make fmt                  Format maintained Go files' \
	  '  make test | vet | build   Run Go checks individually' \
	  '  make race                 Run all Go tests with race detector' \
	  '  make integration-compile  Compile integration tests without running' \
	  '  make integration-local    Run local integration tests, excluding external Cookie services' \
	  '  make integration          Run integration tests (external prerequisites apply)' \
	  '  make docs-check           Check local links and module/package naming' \
	  '  make scripts-test         Run offline Python script tests' \
	  '  make wordlists-check      Verify the pinned wordlist snapshot'

fmt:
	$(GO) fmt ./...

fmt-check:
	@$(PYTHON) scripts/check-format.py "$(GO)"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build ./...

race:
	$(GO) test -race ./...

integration:
	$(GO) test -tags=integration ./...

integration-local:
	$(GO) test -tags=integration ./... -skip '^TestPythonCookieServerE2E$$'

integration-compile:
	$(GO) test -tags=integration ./... -run '^$$'

docs-check:
	$(PYTHON) scripts/check-repository.py

scripts-test:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s scripts -p 'test_*.py' -v

wordlists-check:
	$(PYTHON) scripts/update-dirsearch-wordlists.py --check

check: fmt-check docs-check scripts-test wordlists-check test vet build
