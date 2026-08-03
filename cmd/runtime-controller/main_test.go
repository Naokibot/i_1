package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMiddlewareRequiresBearerToken(t *testing.T) {
	s := &server{token: "correct-token"}
	handler := s.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, authorization := range []string{"", "Bearer wrong-token", "Basic correct-token"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/deployments", nil)
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("authorization %q returned %d", authorization, response.Code)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/deployments", nil)
	request.Header.Set("Authorization", "Bearer correct-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid bearer token returned %d", response.Code)
	}
}

func TestMiddlewareKeepsHealthEndpointPublic(t *testing.T) {
	s := &server{token: "correct-token"}
	handler := s.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("health endpoint returned %d", response.Code)
	}
}

func TestSecurePathRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.pem"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}

	for _, candidate := range []string{
		filepath.Join("..", filepath.Base(outside), "secret.pem"),
		filepath.Join(root, "escape", "secret.pem"),
		filepath.Join(root, "escape", "new-output.pqm"),
	} {
		if resolved, err := securePath(root, candidate); err == nil {
			t.Fatalf("unsafe path %q resolved to %q", candidate, resolved)
		} else if !strings.Contains(err.Error(), "outside the configured root") {
			t.Fatalf("unsafe path %q returned unexpected error: %v", candidate, err)
		}
	}
}

func TestSecurePathAllowsNonexistentDestinationInsideRoot(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join("nested", "archive.pqm")
	resolved, err := securePath(root, candidate)
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(root, candidate)
	if resolved != expected {
		t.Fatalf("resolved %q, expected %q", resolved, expected)
	}
}
