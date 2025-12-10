build:
	go build -o jamf-enc-helper cmd/main.go

test:
	go test ./...

lint:
	go vet ./...
	go fmt ./...

clean:
	rm -f jamf-enc-helper
