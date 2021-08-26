all: lint test
PHONY: test coverage lint golint clean vendor
GOOS=linux

test: | lint
	@echo Running unit tests...
	@go test -cover -short -tags testtools ./...

coverage: | docker-up test-database
	@echo Generating coverage report...
	@go test ./... -race -coverprofile=coverage.out -covermode=atomic -tags testtools -p 1
	@go tool cover -func=coverage.out
	@go tool cover -html=coverage.out

lint: golint

golint: | vendor
	@echo Linting Go files...
	@golangci-lint run

clean: docker-clean
	@echo Cleaning...
	@rm -rf coverage.out
	@go clean -testcache

vendor:
	@go mod download
	@go mod tidy
