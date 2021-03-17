default: test

proto:
	protoc --go_out . --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./pkg/proto/*.proto

.PHONY: certs
certs:
	cd certs; make certs

all-certs:
	cd certs; make all

.PHONY: test
test: all-certs
	go test ./...

race: all-certs
	go test -race ./...

build: proto
	go build ./cmd/exec-server
	go build ./cmd/exec-client

clean:
	rm -f exec-server exec-client
	go clean -testcache
	cd certs; make clean

sandbox: certs build
