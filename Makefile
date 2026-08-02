.PHONY: run test build fmt docker
run:
	go run ./cmd/observer -source-root .
test:
	go test ./...
build:
	mkdir -p bin && go build -o bin/pqm-observer ./cmd/observer
fmt:
	gofmt -w $$(find . -name '*.go')
docker:
	docker compose up --build
