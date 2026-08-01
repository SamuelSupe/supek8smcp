package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrepareMCPRequestBodyRejectsWhitespacePrefixedBatch(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(" \n\t[{}]"))
	writer := httptest.NewRecorder()
	if prepareMCPRequestBody(writer, request) {
		t.Fatal("prepareMCPRequestBody() accepted a JSON-RPC batch")
	}
	if writer.Code != http.StatusBadRequest {
		t.Fatalf("prepareMCPRequestBody() status = %d, want %d", writer.Code, http.StatusBadRequest)
	}
}

func TestPrepareMCPRequestBodyPreservesSingleObject(t *testing.T) {
	t.Parallel()

	const body = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	writer := httptest.NewRecorder()
	if !prepareMCPRequestBody(writer, request) {
		t.Fatalf("prepareMCPRequestBody() rejected a single JSON-RPC object: %s", writer.Body.String())
	}
	got, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read prepared request body: %v", err)
	}
	if string(got) != body {
		t.Fatalf("prepared request body = %q, want %q", got, body)
	}
}

func TestPrepareMCPRequestBodyMapsMaxBytesErrorTo413(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("   {\"jsonrpc\":\"2.0\"}"))
	writer := httptest.NewRecorder()
	request.Body = http.MaxBytesReader(writer, request.Body, 2)
	if prepareMCPRequestBody(writer, request) {
		t.Fatal("prepareMCPRequestBody() accepted an over-limit request while scanning whitespace")
	}
	if writer.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("prepareMCPRequestBody() status = %d, want %d", writer.Code, http.StatusRequestEntityTooLarge)
	}
}
