ARG BUILDPLATFORM=linux/amd64
FROM --platform=${BUILDPLATFORM} golang:1.25 AS builder

ARG VERSION=0.1.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/supek8smcp ./cmd/supek8smcp

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="SupeK8sMCP" \
      org.opencontainers.image.description="Kubernetes-native MCP server operator with delegated RBAC" \
      org.opencontainers.image.source="https://github.com/SamuelSupe/supek8smcp" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder /out/supek8smcp /usr/local/bin/supek8smcp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/supek8smcp"]
