package server

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

type requestBody struct {
	io.Reader
	io.Closer
}

func prepareMCPRequestBody(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodPost || request.Body == nil {
		return true
	}
	original := request.Body
	data, err := io.ReadAll(original)
	if err != nil {
		_ = original.Close()
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeStructuredHTTPError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "MCP request body exceeds maxInputBytes", false)
			return false
		}
		writeStructuredHTTPError(writer, http.StatusBadRequest, "invalid_request", "cannot read MCP request body", false)
		return false
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		_ = original.Close()
		writeStructuredHTTPError(writer, http.StatusBadRequest, "invalid_request", "JSON-RPC batches are not supported", false)
		return false
	}
	request.Body = &requestBody{Reader: bytes.NewReader(data), Closer: original}
	request.ContentLength = int64(len(data))
	return true
}

func serveStatelessSessionClose(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodDelete {
		return false
	}
	writer.WriteHeader(http.StatusNoContent)
	return true
}
