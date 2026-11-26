package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

type envelope struct {
	Success bool        `json:"success"`
	Msg     string      `json:"msg"`
	Obj     interface{} `json:"obj,omitempty"`
}

var started = time.Now()
var requests uint64

func writeJSON(w http.ResponseWriter, status int, v envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func auth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if token == "" || len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, envelope{Success: false, Msg: "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func method(method string, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, http.StatusMethodNotAllowed, envelope{Success: false, Msg: "method not allowed"})
			return
		}
		atomic.AddUint64(&requests, 1)
		fn(w, r)
	}
}

func main() {
	token := strings.TrimSpace(os.Getenv("AMIN_NODE_TOKEN"))
	if len(token) < 32 {
		log.Fatal("AMIN_NODE_TOKEN must contain at least 32 characters")
	}
	addr := strings.TrimSpace(os.Getenv("AMIN_NODE_LISTEN"))
	if addr == "" {
		addr = "127.0.0.1:8787"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("invalid AMIN_NODE_LISTEN: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsLoopback() && os.Getenv("AMIN_NODE_ALLOW_PUBLIC") != "yes") {
		log.Fatal("public listen requires AMIN_NODE_ALLOW_PUBLIC=yes; prefer a private network or TLS reverse proxy")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", method(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, envelope{Success: true, Obj: map[string]interface{}{
			"service": "amin-node-agent", "version": "0.1.0", "uptimeSeconds": int64(time.Since(started).Seconds()),
		}})
	}))
	protected := http.NewServeMux()
	protected.HandleFunc("/api/v1/capabilities", method(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, envelope{Success: true, Obj: map[string]interface{}{
			"agentVersion": "0.1.0", "xrayManagement": false, "features": []string{"health", "system", "capabilities"},
			"protocolsPlanned": []string{"vless", "vmess", "trojan", "shadowsocks"},
		}})
	}))
	protected.HandleFunc("/api/v1/system", method(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		writeJSON(w, http.StatusOK, envelope{Success: true, Obj: map[string]interface{}{
			"goVersion": runtime.Version(), "goroutines": runtime.NumGoroutine(),
			"heapAllocBytes": m.HeapAlloc, "uptimeSeconds": int64(time.Since(started).Seconds()),
			"requests": atomic.LoadUint64(&requests), "os": runtime.GOOS, "arch": runtime.GOARCH,
		}})
	}))
	mux.Handle("/api/v1/", auth(token, protected))
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	log.Printf("AMIN Node Agent 0.1.0 listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}
