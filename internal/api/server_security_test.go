package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuthProtectsAPI(t *testing.T) {
	token := strings.Repeat("a", 32)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := bearerAuth(token, next)

	tests := []struct {
		name   string
		path   string
		header string
		want   int
	}{
		{name: "health remains available", path: "/api/v1/health", want: http.StatusNoContent},
		{name: "missing token", path: "/api/v1/scans", want: http.StatusUnauthorized},
		{name: "wrong scheme", path: "/api/v1/scans", header: "Basic " + token, want: http.StatusUnauthorized},
		{name: "wrong token", path: "/api/v1/scans", header: "Bearer " + strings.Repeat("b", 32), want: http.StatusUnauthorized},
		{name: "valid token", path: "/api/v1/scans", header: "Bearer " + token, want: http.StatusNoContent},
		{name: "static assets remain available", path: "/", want: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tt.want {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tt.want, recorder.Body.String())
			}
		})
	}
}

func TestDecodeRejectsMultipleJSONValues(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/scans",
		strings.NewReader("{\"kind\":\"tls\"}{\"kind\":\"ssh\"}"),
	)
	recorder := httptest.NewRecorder()
	var value map[string]any
	if decode(recorder, req, &value) {
		t.Fatal("decode accepted multiple JSON values")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d", recorder.Code, http.StatusBadRequest)
	}
}

func TestDecodeRejectsOversizedBody(t *testing.T) {
	body := "{\"value\":\"" + strings.Repeat("x", int(maxRequestBodyBytes)) + "\"}"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	var value map[string]any
	if decode(recorder, req, &value) {
		t.Fatal("decode accepted an oversized request")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d", recorder.Code, http.StatusBadRequest)
	}
}
