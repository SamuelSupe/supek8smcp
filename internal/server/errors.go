package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type toolError struct {
	Reason  string `json:"code"`
	Message string `json:"message"`
}

func (e *toolError) Error() string { return e.Reason + ": " + e.Message }

func policyError(reason, message string) error {
	return &toolError{Reason: reason, Message: message}
}

type toolErrorOutput struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func structuredToolErrorMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
		result, err := next(ctx, method, request)
		if err != nil {
			return result, err
		}
		toolResult, ok := result.(*mcp.CallToolResult)
		if !ok || !toolResult.IsError {
			return result, nil
		}
		output := normalizeToolError(toolResult.GetError())
		data, marshalErr := json.Marshal(output)
		if marshalErr != nil {
			return nil, marshalErr
		}
		toolResult.Content = []mcp.Content{&mcp.TextContent{Text: string(data)}}
		toolResult.StructuredContent = output
		return toolResult, nil
	}
}

func normalizeToolError(err error) toolErrorOutput {
	if err == nil {
		return toolErrorOutput{Code: "tool_error", Message: "tool call failed", Retryable: false}
	}
	var typed *toolError
	if errors.As(err, &typed) {
		return toolErrorOutput{Code: typed.Reason, Message: typed.Message, Retryable: retryableErrorCode(typed.Reason)}
	}
	message := err.Error()
	if strings.HasPrefix(message, `validating "arguments":`) || strings.HasPrefix(message, "json: cannot unmarshal") {
		return toolErrorOutput{Code: "invalid_input", Message: message, Retryable: false}
	}
	_, code := auditOutcome(err)
	return toolErrorOutput{Code: code, Message: message, Retryable: retryableErrorCode(code)}
}

func retryableErrorCode(code string) bool {
	switch code {
	case "kubernetes_conflict", "kubernetes_throttled", "kubernetes_timeout", "kubernetes_unavailable", "deadline_exceeded":
		return true
	default:
		return false
	}
}

func writeStructuredHTTPError(writer http.ResponseWriter, status int, code, message string, retryable bool) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(toolErrorOutput{Code: code, Message: message, Retryable: retryable})
}
