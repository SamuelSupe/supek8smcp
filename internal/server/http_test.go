package server

import (
	"encoding/json"
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
	if got := writer.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("prepareMCPRequestBody() content type = %q, want application/json", got)
	}
	var payload struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal(writer.Body.Bytes(), &payload); err != nil {
		t.Fatalf("prepareMCPRequestBody() error body = %q, want structured JSON: %v", writer.Body.String(), err)
	}
	if payload.Code != "invalid_request" || payload.Message != "JSON-RPC batches are not supported" || payload.Retryable {
		t.Fatalf("prepareMCPRequestBody() error payload = %#v, want invalid_request/message/retryable=false", payload)
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
	var payload struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal(writer.Body.Bytes(), &payload); err != nil {
		t.Fatalf("prepareMCPRequestBody() oversized error body = %q, want structured JSON: %v", writer.Body.String(), err)
	}
	if payload.Code != "request_too_large" || payload.Message == "" || payload.Retryable {
		t.Fatalf("prepareMCPRequestBody() oversized error payload = %#v, want request_too_large/message/retryable=false", payload)
	}
}

func TestServeStatelessSessionCloseReturnsNoContent(t *testing.T) {
	t.Parallel()

	for _, sessionID := range []string{"", "stateless-session"} {
		request := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
		if sessionID != "" {
			request.Header.Set("Mcp-Session-Id", sessionID)
		}
		writer := httptest.NewRecorder()
		if !serveStatelessSessionClose(writer, request) {
			t.Fatalf("serveStatelessSessionClose() did not handle DELETE (sessionID=%q)", sessionID)
		}
		if writer.Code != http.StatusNoContent {
			t.Fatalf("serveStatelessSessionClose() status = %d, want %d (sessionID=%q)", writer.Code, http.StatusNoContent, sessionID)
		}
		if writer.Body.Len() != 0 {
			t.Fatalf("serveStatelessSessionClose() body = %q, want empty (sessionID=%q)", writer.Body.String(), sessionID)
		}
	}

	post := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	if serveStatelessSessionClose(httptest.NewRecorder(), post) {
		t.Fatal("serveStatelessSessionClose() handled non-DELETE request")
	}
}
