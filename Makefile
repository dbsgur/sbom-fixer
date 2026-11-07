WAILS ?= $(shell command -v wails 2>/dev/null || echo $(HOME)/go/bin/wails)

.PHONY: dev build test test-go test-ui cover

dev:            ## 개발 모드 실행 (핫 리로드)
	$(WAILS) dev

build:          ## macOS 앱 번들 빌드 → build/bin/sbomapp.app
	$(WAILS) build

test: test-go test-ui

test-go:
	go test -race ./internal/...

test-ui:
	cd frontend && npm test

cover:
	go test -cover ./internal/...
	cd frontend && npm run coverage
