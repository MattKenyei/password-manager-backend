.PHONY: test test-short test-race test-cover

# Full suite (requires Docker)
test:
	go test ./... -count=1 -v

# Only unit tests — skips testcontainers
test-short:
	go test ./... -short -count=1 -v

# Full suite with race detector (slow, catches concurrency bugs)
test-race:
	go test ./... -race -count=1 -v

# Coverage report
test-cover:
	go test ./... -count=1 -race -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html in a browser"