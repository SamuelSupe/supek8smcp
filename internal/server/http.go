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
				http.Error(writer, "MCP request body exceeds maxInputBytes", http.StatusRequestEntityTooLarge)
				return false
			}
			if !errors.Is(err, io.EOF) {
				http.Error(writer, "cannot read MCP request body", http.StatusBadRequest)
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
			http.Error(writer, "JSON-RPC batches are not supported", http.StatusBadRequest)
			return false
		}
		return true
	}
}
