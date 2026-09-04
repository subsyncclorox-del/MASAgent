# MASAgent build & test.
.PHONY: build test test-go test-py test-ts fmt clean

BIN := bin

build: $(BIN)/scopeguard $(BIN)/recon

$(BIN)/scopeguard:
	cd scopeguard && go build -o ../$(BIN)/scopeguard ./cmd/scopeguard

$(BIN)/recon:
	cd recon && go build -o ../$(BIN)/recon ./cmd/recon

test: test-go test-py test-ts

test-go:
	cd scopeguard && go test ./... && go vet ./...
	cd recon && go test ./... && go vet ./...

test-py:
	cd orchestrator && python -m pytest -q

test-ts:
	cd api && npm install --no-audit --no-fund && npx tsc -p tsconfig.json --noEmit

fmt:
	cd scopeguard && gofmt -w .
	cd recon && gofmt -w .

clean:
	rm -rf $(BIN) orchestrator/*.egg-info api/dist api/node_modules
