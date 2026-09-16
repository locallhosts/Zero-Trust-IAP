.PHONY: build test vet fmt certs ui dev-up clean

build:
	go build -o bin/proxy ./cmd/proxy
	go build -o bin/posture-agent ./cmd/posture-agent
	go build -o bin/mint-jwt ./cmd/mint-jwt
	go build -o bin/demo-app ./cmd/demo-app

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

certs:
	./certs/generate-certs.sh iap.local certs/out

ui:
	cd admin-ui && npm install && npm run build

dev-up:
	./scripts/dev-up.sh

clean:
	rm -rf bin logs/*.log certs/out admin-ui/dist admin-ui/node_modules
