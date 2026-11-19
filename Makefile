# Сборка и проверки trassa-agent (E05-T2). Версии инструментов — docs/plan/decisions/E05-agent.md панели.
BUF_VERSION := 1.75.0
PROTOC_GEN_GO_VERSION := v1.36.12
STATICCHECK_VERSION := 2026.2.2
GOBIN ?= $(shell go env GOPATH)/bin

.PHONY: tools proto proto-check vet staticcheck test check

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

staticcheck:
	$(GOBIN)/staticcheck ./...

test:
	go test -race ./...

check: proto-check vet staticcheck test
