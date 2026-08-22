.PHONY: proto test build vet fmt tidy manifest

GO ?= go
PROTO_DIR ?= proto

proto: ## generate protobuf stubs (requires buf or protoc)
	@echo "proto: ponytail - no proto files yet, stub target"
	@mkdir -p $(PROTO_DIR)

test: ## run all tests
	$(GO) test ./... -v -count=1

build: ## compile check
	$(GO) build ./...

vet: ## go vet
	$(GO) vet ./...

fmt: ## format
	$(GO) fmt ./...

tidy: ## tidy modules
	$(GO) mod tidy

manifest: ## regenerate manifest.json from <category>/<connector>/manifest.yaml
	$(GO) run ./cmd/combine-manifest -root .

.DEFAULT_GOAL := test
