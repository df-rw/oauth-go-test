.PHONY: dev

dev:
	go run dfauth/cmd/web

lint:
	golangci-lint run ./...
