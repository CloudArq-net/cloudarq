SHELL := bash
GO    ?= go

# Packages held to 100% statement coverage. Adding one is deliberate.
PURE_PKGS = eval trust parse ring
PKG   := ./...

.PHONY: all build test vet purity determinism cover check preflight clean

all: check

build:
	$(GO) build $(PKG)

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test $(PKG)

## purity: the pure packages (eval, join, parse, registry, report, ring, trust)
## import no package that reaches the network, the filesystem, a subprocess,
## a system call or randomness, except through encoding/json, fmt,
## crypto/sha256 and time; test/arch/purity_test.go lists them.
# go test passes when -run matches no test, so the gate also requires the
# test's own PASS line: a renamed test fails here instead of passing unrun.
purity:
	@out=$$($(GO) test ./test/arch/ -count=1 -run '^TestPureLayersHaveNoIO$$' -v 2>&1); status=$$?; \
	echo "$$out"; \
	if [ $$status -ne 0 ]; then exit $$status; fi; \
	echo "$$out" | grep -q '^--- PASS: TestPureLayersHaveNoIO ' || \
	  { echo "FAIL: TestPureLayersHaveNoIO did not run, so no package was examined"; exit 1; }

## determinism: identical input must produce byte-identical output, in fresh processes.
# DETERMINISM_TESTS is the number of TestDeterminism* tests the tree holds. The gate
# counts what each fresh process ran and refuses any other number, so a renamed or
# unreachable test fails loudly instead of vanishing from a gate that says "agree".
DETERMINISM_TESTS = 10
determinism:
	@for i in $$(seq 1 20); do \
	  out=$$($(GO) test ./... -count=1 -run TestDeterminism -v 2>&1) || { echo "$$out"; exit 1; }; \
	  ran=$$(echo "$$out" | grep -cE '^=== RUN   TestDeterminism[^/]*$$'); \
	  if [ "$$ran" -ne $(DETERMINISM_TESTS) ]; then \
	    echo "determinism: process $$i ran $$ran TestDeterminism tests, expected $(DETERMINISM_TESTS) - a test was renamed, dropped or not reached"; exit 1; \
	  fi; \
	done; echo "determinism: 20/20 fresh processes agree, $(DETERMINISM_TESTS) tests each"

# Every package in PURE_PKGS must be at 100% statement coverage. A figure is
# read only from a run that built every package and passed every test: a
# package that does not compile writes no profile, and coverage read beside
# a failing test measures code that is wrong. Either fails the gate, with go
# test's own output, and so does a run that exits cleanly with no profile or
# with a profile of no statements, which would be 100% of nothing.
cover:
	@fail=0; for pkg in $(PURE_PKGS); do \
	  profile=cover.$$pkg.out; rm -f $$profile; \
	  if ! out=$$($(GO) test ./internal/$$pkg/... -count=1 -coverprofile=$$profile -covermode=atomic 2>&1); then \
	    echo "$$out"; echo "FAIL: internal/$$pkg did not build or a test failed, so its coverage was not measured"; fail=1; \
	  elif [ ! -s $$profile ]; then \
	    echo "FAIL: internal/$$pkg: go test passed and wrote no coverage profile"; fail=1; \
	  elif [ $$(grep -vc '^mode:' $$profile) -eq 0 ]; then \
	    echo "FAIL: internal/$$pkg has no statements, so its coverage measures nothing"; fail=1; \
	  elif ! pct=$$($(GO) tool cover -func=$$profile | awk '/^total:/{gsub("%","",$$3);print $$3}') || [ -z "$$pct" ]; then \
	    echo "FAIL: internal/$$pkg: the coverage profile could not be read"; fail=1; \
	  else \
	    echo "internal/$$pkg coverage: $$pct%"; \
	    awk -v p="$$pct" 'BEGIN{exit !(p+0 < 100)}' && { echo "FAIL: internal/$$pkg must be at 100% statement coverage"; fail=1; } || true; \
	  fi; \
	  rm -f $$profile; \
	done; exit $$fail

check: build vet test purity determinism cover
	@echo "all checks green"

## preflight: run before every push. A commit is recoverable; a pushed secret is not.
preflight: check
	@./scripts/preflight.sh

clean:
	rm -f cover.*.out
	rm -rf dist bin
