SHELL := /bin/sh

IMG ?= ghcr.io/samuelsupe/supek8smcp:0.3.0
VERSION ?= 0.3.0
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0
KUSTOMIZE ?= kubectl kustomize --load-restrictor LoadRestrictionsNone
HELM ?= helm

.PHONY: generate manifests fmt vet test build release docker-build helm-lint helm-template helm-package install uninstall deploy undeploy

generate:
	$(CONTROLLER_GEN) object:headerFile="" paths="./api/..."

manifests:
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd/bases
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=charts/supek8smcp/crds

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
	VERSION=$(VERSION) HELM=$(HELM) ./hack/package-release.sh

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMG) .

helm-lint:
	$(HELM) lint --strict charts/supek8smcp

helm-template:
	$(HELM) template supek8smcp charts/supek8smcp --namespace supek8smcp-system --include-crds >/dev/null

helm-package:
	mkdir -p dist
	$(HELM) package charts/supek8smcp --version $(VERSION) --app-version $(VERSION) --destination dist

install:
	kubectl apply -f config/crd/bases

uninstall:
	kubectl delete --ignore-not-found=true -f config/crd/bases

deploy:
	$(KUSTOMIZE) config/default | sed 's|ghcr.io/samuelsupe/supek8smcp:0.3.0|$(IMG)|g' | kubectl apply -f -

undeploy:
	$(KUSTOMIZE) config/default | kubectl delete --ignore-not-found=true -f -
