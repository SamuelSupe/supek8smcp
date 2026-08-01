SHELL := /bin/sh

IMG ?= ghcr.io/samuelsupe/supek8smcp:0.1.0
VERSION ?= 0.1.0
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0
KUSTOMIZE ?= kubectl kustomize --load-restrictor LoadRestrictionsNone

.PHONY: generate manifests fmt vet test build release docker-build install uninstall deploy undeploy

generate:
	$(CONTROLLER_GEN) object:headerFile="" paths="./api/..."

manifests:
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd/bases

fmt:
	gofmt -w api cmd internal

vet:
	go vet ./...

test:
	go test ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/supek8smcp ./cmd/supek8smcp

release:
	VERSION=$(VERSION) ./hack/package-release.sh

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMG) .

install:
	kubectl apply -f config/crd/bases

uninstall:
	kubectl delete --ignore-not-found=true -f config/crd/bases

deploy:
	$(KUSTOMIZE) config/default | sed 's|ghcr.io/samuelsupe/supek8smcp:0.1.0|$(IMG)|g' | kubectl apply -f -

undeploy:
	$(KUSTOMIZE) config/default | kubectl delete --ignore-not-found=true -f -
