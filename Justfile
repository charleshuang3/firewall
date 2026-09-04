# List available recipes
default:
    @just --list

# Build all packages
build:
    go build -v ./...

# Run linters using golangci-lint
lint:
    golangci-lint run ./...

# Alias for lint to support lint-backend
lint-backend: lint

# Run go mod tidy
tidy:
    go mod tidy

# Update go mod dependencies
update-go-deps:
    go get -u -t ./...
    @just tidy

# Update dependencies
update-deps: update-go-deps

# Run tests
test:
    go test -v ./...

# Alias for test to support test-backend
test-backend: test

# Format code using goimports
fmt:
    goimports -w -local "github.com/charleshuang3/firewall" .

# Alias for fmt to support fmt-backend
fmt-backend: fmt

# Check formatting without modifying files
fmt-check:
    @test -z "$($(go env GOPATH)/bin/goimports -local github.com/charleshuang3/firewall -l . 2>/dev/null || goimports -local github.com/charleshuang3/firewall -l .)" || (echo "Unformatted Go files found:" && goimports -local github.com/charleshuang3/firewall -l . && exit 1)

# Alias for fmt-check to support fmt-check-backend
fmt-check-backend: fmt-check
