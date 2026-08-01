FROM golang:1.25 AS builder

ARG VERSION=0.1.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/supek8smcp ./cmd/supek8smcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/supek8smcp /usr/local/bin/supek8smcp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/supek8smcp"]
