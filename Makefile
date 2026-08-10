GO ?= go
BINARY := bin/incidentpilot
COVERAGE_FILE := coverage.out
COVERAGE_MIN := 80
GOVULNCHECK_VERSION := v1.6.0

.PHONY: run build test race vet fmt fmt-check coverage check audit clean docker-build

run:
	$(GO) run ./cmd/incidentpilot

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BINARY) ./cmd/incidentpilot

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './.git/*'))" || \
		{ echo "Go files need formatting. Run 'make fmt'."; exit 1; }

coverage:
	$(GO) test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	@total="$$( $(GO) tool cover -func=$(COVERAGE_FILE) | awk '/^total:/ { gsub(/%/, "", $$3); print $$3 }' )"; \
		echo "total coverage: $${total}%"; \
		awk -v total="$${total}" -v minimum="$(COVERAGE_MIN)" 'BEGIN { if (total + 0 < minimum + 0) exit 1 }' || \
		{ echo "coverage is below $(COVERAGE_MIN)%"; exit 1; }

check: fmt-check vet test race coverage build

audit:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

clean:
	rm -f $(BINARY) $(COVERAGE_FILE)

docker-build:
	docker build -t incidentpilot:local .
