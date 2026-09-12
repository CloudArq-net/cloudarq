SHELL := bash
GO    ?= go
PKG   := ./...

.PHONY: all build test vet purity determinism cover css check clean

all: check

build:
	$(GO) build $(PKG)

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test $(PKG)

## purity: internal/eval and internal/parse must not reach IO. docs/ENGINEERING.md s1.
purity:
	$(GO) test ./test/arch/ -run TestPureLayersHaveNoIO -v

## determinism: identical input must produce byte-identical output. docs/ENGINEERING.md s2.
determinism:
	@for i in $$(seq 1 20); do \
	  $(GO) test ./internal/... -count=1 -run TestDeterminism >/dev/null || exit 1; \
	done; echo "determinism: 20/20 fresh processes agree"

## cover: 100% statement coverage is required on internal/eval and NOWHERE else.
## Passes vacuously while the package has no statements; bites the moment it does.
cover:
	@$(GO) test ./internal/eval/... -coverprofile=coverage.out -covermode=atomic >/dev/null 2>&1 || true
	@if [ ! -s coverage.out ] || [ $$(grep -vc '^mode:' coverage.out) -eq 0 ]; then \
	  echo "cover: internal/eval has no statements yet - gate armed, not yet binding"; \
	else \
	  pct=$$($(GO) tool cover -func=coverage.out | awk '/^total:/{gsub("%","",$$3);print $$3}'); \
	  echo "internal/eval coverage: $$pct%"; \
	  awk -v p="$$pct" 'BEGIN{exit !(p+0 < 100)}' && { echo "FAIL: internal/eval must be 100% (docs/ENGINEERING.md s7)"; exit 1; } || true; \
	fi

## css: taste under deadline is unreliable; a grep is not. docs/ENGINEERING.md s9.
css:
	@! grep -rniE 'gradient|blur-\[|backdrop-filter|cyber-|drop-shadow' web/ 2>/dev/null \
	  || { echo "FAIL: forbidden visual idiom in web/ (docs/ENGINEERING.md s9)"; exit 1; }
	@echo "css: clean"

check: build vet test purity determinism cover css
	@echo "all checks green"

clean:
	rm -f coverage.out
	rm -rf dist bin
