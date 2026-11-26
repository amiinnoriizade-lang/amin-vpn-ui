package job

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestNativeInboundIDIsStableAndPositive(t *testing.T) {
	a := nativeInboundID("amin-test-vless-10085")
	b := nativeInboundID("amin-test-vless-10085")
	c := nativeInboundID("amin-test-vless-10086")
	if a <= 0 {
		t.Fatalf("expected positive id, got %d", a)
	}
	if a != b {
		t.Fatalf("same tag produced different ids: %d != %d", a, b)
	}
	if a == c {
		t.Fatalf("different tags collided: %d", a)
	}
}

func TestNativeAgentRequestsUseBearerAndExpectedRoutes(t *testing.T) {
	const token = "test-node-token-with-sufficient-length"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q, want bearer token", got)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/inbounds":
			_, _ = w.Write([]byte(`{"success":true,"obj":[{"tag":"test-inbound","port":10085,"protocol":"vless","settings":{"clients":[]}}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/inbounds/test-inbound/clients":
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			if !strings.Contains(string(body), `"email":"test-user"`) {
				t.Errorf("client request body = %s", body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"success":true,"msg":"client created"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/inbounds/test-inbound/clients" && r.URL.Query().Get("email") == "test-user":
			_, _ = w.Write([]byte(`{"success":true,"msg":"client deleted"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	node := model.Node{
		Address: host, Port: port, Scheme: "http", ApiToken: token,
		AgentMode: true, AllowPrivateAddress: true,
	}

	inbounds, err := NativeAgentListInbounds(context.Background(), node)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].Tag != "test-inbound" {
		t.Fatalf("unexpected inbound response: %#v", inbounds)
	}
	if err := NativeAgentCreateClient(context.Background(), node, "test-inbound", map[string]any{"email": "test-user", "id": "00000000-0000-4000-8000-000000000001"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := NativeAgentDeleteClient(context.Background(), node, "test-inbound", "test-user"); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	if requests != 3 {
		t.Fatalf("received %d requests, want 3", requests)
	}
}

func TestNativeAgentRejectsUnsuccessfulEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"msg":"invalid node token"}`))
	}))
	defer server.Close()

	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	node := model.Node{
		Address: host, Port: port, Scheme: "http", ApiToken: "test-node-token",
		AgentMode: true, AllowPrivateAddress: true,
	}
	_, err = NativeAgentListInbounds(context.Background(), node)
	if err == nil || !strings.Contains(err.Error(), "invalid node token") {
		t.Fatalf("expected Agent envelope error, got %v", err)
	}
}
