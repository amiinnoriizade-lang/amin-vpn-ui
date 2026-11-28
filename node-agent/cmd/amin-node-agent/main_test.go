package main

import (
	"net/http"
	"net/http/httptest"
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
	inboundAPI(nil, nil)(rec, req)
	if rec.Code != http.StatusServiceUnavailable { t.Fatalf("got %d: %s", rec.Code, rec.Body.String()) }
}

func TestDecodeBodyRejectsUnknownFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"tag":"x","unexpected":true}`))
	rec := httptest.NewRecorder()
	var dst struct { Tag string `json:"tag"` }
	if err := decodeBody(rec, req, &dst); err == nil { t.Fatal("expected unknown field rejection") }
}
