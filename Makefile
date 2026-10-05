SHELL := bash
GO    ?= go

# Packages held to 100% statement coverage. Adding one is deliberate.
PURE_PKGS = eval trust parse ring
PKG   := ./...

.PHONY: all build test vet purity determinism cover collect release check preflight clean

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

## collect: the collector is its own module, so ./... never reaches it; the
## AWS SDK stays out of the engine's build. Its modules are checked against
## go.sum before anything is built from them.
collect:
	cd internal/collect && $(GO) mod verify && $(GO) build ./... && $(GO) vet ./... && $(GO) test -count=1 ./...

## release: the files of a release, VERSION=v0.3.0, under dist/release/<VERSION>:
## the collector (cloudarq-collect_<os>_<arch>) and the command line
## (cloudarq_<os>_<arch>) for macOS and Linux on Intel and ARM, static, built
## without the build machine's paths and without a symbol table, and
## SHA256SUMS over the eight. The collector is stamped with VERSION; the
## command line says the version Go records for the module, which at a tag
## is the tag.
##
## It builds only a tree git status lists nothing for, since Go records a
## binary built from any other tree as modified, and it refuses any binary
## Go recorded as modified all the same. When VERSION names a tag, the tag
## must be on HEAD and the command line must record the module at that
## tag; a VERSION written as a release's (v1.2.3) must name a tag, so no
## file says a version it was not built from. In every case VERSION must be
## v and what scripts/version.sh prints for HEAD, the one rule that names
## the engine's version: at a release tag, the tag; anywhere else, the
## commit as the script describes it, which builds a rehearsal's files. A
## run that fails or is refused once it has started building leaves no
## files behind.
# GOWORK=off: a go.work file, which git ignores and git status does not
# list, would otherwise build the release from modules the commit does not
# hold. VERSION is read from the environment, where make puts a variable
# given on its command line, and checked before it names a directory.
RELEASE_TARGETS = darwin/arm64 darwin/amd64 linux/arm64 linux/amd64
MODULE          = github.com/CloudArq-net/cloudarq
release:
	@set -euo pipefail; export GOWORK=off; \
	version=$${VERSION:-}; \
	if [ -z "$$version" ]; then echo "release: refused: set VERSION, as VERSION=v0.3.0"; exit 2; fi; \
	if ! [[ $$version =~ ^v[0-9A-Za-z][0-9A-Za-z.+_-]*$$ ]]; then \
	  echo "release: refused: VERSION $$version is not v and a version, as v0.3.0"; exit 2; fi; \
	if ! dirty=$$(git status --porcelain --untracked-files=all); then \
	  echo "release: refused: git status failed, and a release is built only from a git work tree"; exit 2; fi; \
	if [ -n "$$dirty" ]; then \
	  echo "release: refused: the tree is not clean, so Go would record every binary as modified; git status lists:"; \
	  printf '%s\n' "$$dirty" | sed 's/^/  /'; exit 1; fi; \
	head=$$(git rev-parse HEAD); \
	if tagged=$$(git rev-parse -q --verify "refs/tags/$$version^{commit}"); then \
	  if [ "$$tagged" != "$$head" ]; then \
	    echo "release: refused: the tag $$version is on $$tagged, not on HEAD ($$head)"; exit 1; fi; \
	  ontag=1; \
	elif [[ $$version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$$ ]]; then \
	  echo "release: refused: VERSION $$version is a release's version, and no tag $$version is here to build it from"; exit 1; \
	else \
	  ontag=0; \
	fi; \
	described=v$$(scripts/version.sh); \
	if [ "$$described" != "$$version" ]; then \
	  echo "release: refused: VERSION is $$version, and scripts/version.sh describes HEAD as $$described, the version its files must carry"; exit 1; fi; \
	out=$$PWD/dist/release/$$version; rm -rf "$$out"; mkdir -p "$$out"; \
	finished=0; trap '[ $$finished = 1 ] || rm -rf "$$out"' EXIT; \
	for target in $(RELEASE_TARGETS); do \
	  os=$${target%/*}; arch=$${target#*/}; \
	  ( cd internal/collect && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -mod=readonly -buildvcs=true -trimpath \
	      -ldflags "-s -w -X main.version=$${version#v}" -o "$$out/cloudarq-collect_$${os}_$${arch}" ./cmd/cloudarq-collect ); \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -mod=readonly -buildvcs=true -trimpath \
	      -ldflags "-s -w" -o "$$out/cloudarq_$${os}_$${arch}" ./cmd/cloudarq; \
	done; \
	count=0; bad=0; \
	for f in "$$out"/cloudarq-collect_* "$$out"/cloudarq_*; do \
	  count=$$((count + 1)); name=$${f##*/}; \
	  modified=$$($(GO) version -m "$$f" | awk -F'\t' '$$2 == "build" && index($$3, "vcs.modified=") == 1 { print substr($$3, 14) }'); \
	  if [ "$$modified" != false ]; then \
	    echo "release: refused: Go recorded $$name as built with vcs.modified=$${modified:-(nothing)}"; bad=1; fi; \
	  if [ $$ontag = 1 ] && [[ $$name == cloudarq_* ]]; then \
	    recorded=$$($(GO) version -m "$$f" | awk -F'\t' '$$2 == "mod" && $$3 == "$(MODULE)" { print $$4 }'); \
	    if [ "$$recorded" != "$$version" ]; then \
	      echo "release: refused: Go recorded $(MODULE) in $$name at '$$recorded', not at the tag $$version"; bad=1; fi; \
	  fi; \
	done; \
	if [ $$count -ne 8 ]; then echo "release: refused: read Go's record of $$count binaries, not 8"; bad=1; fi; \
	if [ $$bad -ne 0 ]; then exit 1; fi; \
	( cd "$$out" && shasum -a 256 $$(ls | LC_ALL=C sort) > SHA256SUMS ); \
	cat "$$out/SHA256SUMS"; \
	if [ $$ontag = 1 ]; then kind="the tag $$version"; else kind="$$version, a rehearsal and not a tag"; fi; \
	finished=1; echo "release: $$count binaries, each recorded unmodified, and SHA256SUMS in $$out, built from $$kind"

check: build vet test purity determinism cover collect
	@echo "all checks green"

## preflight: run before every push. A commit is recoverable; a pushed secret is not.
preflight: check
	@./scripts/preflight.sh

clean:
	rm -f cover.*.out
	rm -rf dist bin
