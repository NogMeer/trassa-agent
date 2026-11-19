# Сборка и проверки trassa-agent (E05-T2). Версии инструментов — docs/plan/decisions/E05-agent.md панели.
BUF_VERSION := 1.75.0
PROTOC_GEN_GO_VERSION := v1.36.12
STATICCHECK_VERSION := 2026.2.2
GOBIN ?= $(shell go env GOPATH)/bin

.PHONY: tools proto proto-check vet staticcheck test build release-check check

tools:
	GOBIN=$(GOBIN) go install github.com/bufbuild/buf/cmd/buf@v$(BUF_VERSION)
	GOBIN=$(GOBIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(GOBIN) go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

# Генерат gen/ коммитится; CI падает, если он разошёлся с proto/.
proto:
	PATH=$(GOBIN):$$PATH buf lint
	PATH=$(GOBIN):$$PATH buf generate

proto-check: proto
	git diff --exit-code -- gen || (echo 'Генерат устарел: make proto' && exit 1)

vet:
	go vet ./...
	go vet -tags testops ./...

staticcheck:
	$(GOBIN)/staticcheck ./...
	$(GOBIN)/staticcheck -tags testops ./...

# Тесты дважды: выпускная сборка и сборка с test.config_write (тег testops).
test:
	go test -race ./...
	go test -race -tags testops ./...

# Сборка как в выпуске (decisions п. 11). VERSION задаётся тегом выпуска.
VERSION ?= 0.0.0-dev
GOARCH ?= $(shell go env GOARCH)
LDFLAGS := -s -w -buildid= -X github.com/NogMeer/trassa-agent/internal/config.Version=$(VERSION)
build:
	mkdir -p dist
	for b in trassa-agent trassa-helper; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GOFLAGS=-mod=readonly \
	    go build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o dist/$$b-linux-$(GOARCH) ./cmd/$$b || exit 1; \
	done

# В выпускном бинарнике нет тестового типа и тега testops (E05, раздел 6).
release-check: build
	for b in trassa-agent trassa-helper; do \
	  f=dist/$$b-linux-$(GOARCH); \
	  if go version -m $$f | grep -q testops; then echo "$$f: собран с testops"; exit 1; fi; \
	  if grep -qF 'test.config_write' $$f; then echo "$$f: есть test.config_write"; exit 1; fi; \
	done

check: proto-check vet staticcheck test release-check
