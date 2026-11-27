package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	xray "github.com/amiinnoriizade-lang/amin-vpn-ui/node-agent/internal/xray"
	"strings"
	"testing"
)

func TestAuthRejectsMissingAndWrongToken(t *testing.T) {
	h := auth("01234567890123456789012345678901", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, header := range []string{"", "Bearer wrong"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
		req.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized { t.Fatalf("header %q: got %d", header, rec.Code) }
	}
}

func TestAuthAcceptsCorrectBearerToken(t *testing.T) {
	token := "01234567890123456789012345678901"
	h := auth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent { t.Fatalf("got %d", rec.Code) }
}

func TestInboundAPIUnavailableWithoutXray(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/inbounds", nil)
	rec := httptest.NewRecorder()
	inboundAPI(nil)(rec, req)
	if rec.Code != http.StatusServiceUnavailable { t.Fatalf("got %d: %s", rec.Code, rec.Body.String()) }
}

func TestDecodeBodyRejectsUnknownFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"tag":"x","unexpected":true}`))
	rec := httptest.NewRecorder()
	var dst struct { Tag string `json:"tag"` }
	if err := decodeBody(rec, req, &dst); err == nil { t.Fatal("expected unknown field rejection") }
}

func TestInboundAPIExposesAuthenticatedUserTrafficStats(t *testing.T) {
 dir := t.TempDir()
 configPath := filepath.Join(dir, "config.json")
 config := `{"api":{"tag":"api","services":["StatsService"]},"inbounds":[{"tag":"api","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door"}]}`
 if err := os.WriteFile(configPath, []byte(config), 0600); err != nil { t.Fatal(err) }
 binary := filepath.Join(dir, "xray")
 script := `#!/bin/sh
printf '%s\n' '{"stat":[{"name":"user>>>alice@example.com>>>traffic>>>uplink","value":"321"}]}'
`
 if err := os.WriteFile(binary, []byte(script), 0700); err != nil { t.Fatal(err) }
 manager := &xray.ConfigManager{Path:configPath,XrayBinary:binary}

 const token = "test-node-token-with-sufficient-length"
 handler := auth(token, protectedAPI(manager))
 req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
 req.Header.Set("Authorization", "Bearer "+token)
 rec := httptest.NewRecorder()
 handler.ServeHTTP(rec, req)
 if rec.Code != http.StatusOK { t.Fatalf("GET /api/v1/stats got %d: %s", rec.Code, rec.Body.String()) }
 if !strings.Contains(rec.Body.String(), `"email":"alice@example.com"`) || !strings.Contains(rec.Body.String(), `"up":321`) {
  t.Fatalf("unexpected stats response: %s", rec.Body.String())
 }
}
