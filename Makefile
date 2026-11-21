# Сборка и проверки trassa-agent (E05-T2). Версии инструментов — docs/plan/decisions/E05-agent.md панели.
BUF_VERSION := 1.75.0
PROTOC_GEN_GO_VERSION := v1.36.12
STATICCHECK_VERSION := 2026.2.2
GOBIN ?= $(shell go env GOPATH)/bin

.PHONY: tools proto proto-check vet staticcheck test build release-check release cli check

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

# Выпуск (E05-T29): обе архитектуры и SHA256SUMS. Только на toolchain из go.mod — другой компилятор даёт другой хэш.
# Время в бинарник Go не попадает, публикуются сами файлы без архивов, поэтому SOURCE_DATE_EPOCH закреплять нечего.
RELEASE_FILES := trassa-agent-linux-amd64 trassa-agent-linux-arm64 trassa-helper-linux-amd64 trassa-helper-linux-arm64
release:
	@want=$$(awk '/^toolchain /{ print $$2 }' go.mod); got=$$(go env GOVERSION); \
	  [ "$$got" = "$$want" ] || { echo "Выпуск собирается только на $$want, сейчас $$got (нужен GOTOOLCHAIN=auto)"; exit 1; }
	rm -f dist/trassa-*-linux-* dist/SHA256SUMS dist/SHA256SUMS.minisig
	$(MAKE) release-check GOARCH=amd64
	$(MAKE) release-check GOARCH=arm64
	cd dist && if command -v sha256sum >/dev/null; then sha256sum $(RELEASE_FILES); else shasum -a 256 $(RELEASE_FILES); fi >SHA256SUMS
	cat dist/SHA256SUMS

# CLI trassa (E16-T19, T20): macOS, Linux, Windows на amd64 и arm64, без cgo; vet — и под Windows.
CLI_TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64
CLI_LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
cli:
	mkdir -p dist
	GOOS=windows go vet ./internal/cli ./cmd/trassa
	for t in $(CLI_TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOFLAGS=-mod=readonly \
	    go build -trimpath -buildvcs=false -ldflags="$(CLI_LDFLAGS)" -o dist/trassa-$$os-$$arch$$ext ./cmd/trassa || exit 1; \
	done

check: proto-check vet staticcheck test release-check cli
