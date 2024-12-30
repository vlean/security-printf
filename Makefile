all: securityprintf.so securityprintf
.PHONY: lint test

clean:
	rm -f securityprintf.so securityprintf

test:
	go test ./...

lint:
	golangci-lint run ./...

securityprintf:
	go build ./cmd/securityprintf

securityprintf.so:
	go build -buildmode=plugin ./plugin/securityprintf.go
