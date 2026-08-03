package server

import (
	"bufio"
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
	buffered := bufio.NewReader(original)
	discarded := int64(0)
	for {
		first, err := buffered.ReadByte()
		if err != nil {
			request.Body = &requestBody{Reader: buffered, Closer: original}
			if request.ContentLength >= 0 {
				request.ContentLength = max(0, request.ContentLength-discarded)
			}
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeStructuredHTTPError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "MCP request body exceeds maxInputBytes", false)
				return false
			}
			if !errors.Is(err, io.EOF) {
				writeStructuredHTTPError(writer, http.StatusBadRequest, "invalid_request", "cannot read MCP request body", false)
				return false
			}
			return true
		}
		if first == ' ' || first == '\t' || first == '\r' || first == '\n' {
			discarded++
			continue
		}
		request.Body = &requestBody{Reader: io.MultiReader(bytes.NewReader([]byte{first}), buffered), Closer: original}
		if request.ContentLength >= 0 {
			request.ContentLength = max(0, request.ContentLength-discarded)
		}
		if first == '[' {
			writeStructuredHTTPError(writer, http.StatusBadRequest, "invalid_request", "JSON-RPC batches are not supported", false)
			return false
		}
		return true
	}
}

func serveStatelessSessionClose(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodDelete {
		return false
	}
	writer.WriteHeader(http.StatusNoContent)
	return true
}
