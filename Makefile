.PHONY: build build-windows-agent test install-relay uninstall-relay
build:
	mkdir -p bin
	go build -o bin/porthub-core ./apps/core
	go build -o bin/porthub-edge ./apps/edge
	go build -o bin/porthub-agent ./apps/agent
	go build -o bin/porthub-netd ./apps/netd
	go build -o bin/porthub-relay ./apps/relay
	go build -o bin/porthub-update-helper ./apps/update-helper

install-relay:
	scripts/install-relay.sh

uninstall-relay:
	scripts/uninstall-relay.sh

build-windows-agent:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/porthub-agent-windows-amd64.exe ./apps/agent

test:
	go test ./...
