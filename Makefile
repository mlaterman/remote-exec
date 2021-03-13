default: test

.PHONY: proto
proto:
	protoc --go_out . --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./pkg/proto/*.proto

.PHONY: test
test:
	go test ./...
