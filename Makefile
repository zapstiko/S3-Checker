.PHONY: build test vet fmt wordlists check clean

build:
	go build -trimpath -o s3-checker .

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w *.go

wordlists:
	./scripts/build-wordlists.sh

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	./scripts/build-wordlists.sh --check

clean:
	rm -f s3-checker
