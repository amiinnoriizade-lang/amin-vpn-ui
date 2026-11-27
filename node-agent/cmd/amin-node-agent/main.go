package main

import (
	"crypto/subtle"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	xray "github.com/amiinnoriizade-lang/amin-vpn-ui/node-agent/internal/xray"
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

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
	} else if strings.Contains(err.Error(), "Xray rejected config") || strings.Contains(err.Error(), "Xray restart failed") {
		status = http.StatusBadGateway
	} else if os.IsPermission(err) {
		status = http.StatusForbidden
	}
	writeJSON(w, status, envelope{Success: false, Msg: err.Error()})
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func auth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			writeJSON(w, http.StatusUnauthorized, envelope{Success: false, Msg: "unauthorized"})
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		if token == "" || len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, envelope{Success: false, Msg: "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func method(want string, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != want {
			w.Header().Set("Allow", want)
			writeJSON(w, http.StatusMethodNotAllowed, envelope{Success: false, Msg: "method not allowed"})
			return
		}
		atomic.AddUint64(&requests, 1)
		fn(w, r)
	}
}

func inboundAPI(manager *xray.ConfigManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			writeJSON(w, http.StatusServiceUnavailable, envelope{Success: false, Msg: "Xray manager is unavailable; check Xray paths and service"})
			return
		}
		switch {
		case r.URL.Path == "/api/v1/inbounds" && r.Method == http.MethodGet:
			items, err := manager.ListInbounds()
			if err != nil { writeError(w, err); return }
			writeJSON(w, http.StatusOK, envelope{Success: true, Obj: items})
		case r.URL.Path == "/api/v1/inbounds" && r.Method == http.MethodPost:
			var in xray.Inbound
			if err := decodeBody(w, r, &in); err != nil { writeError(w, err); return }
			if err := manager.AddInbound(in); err != nil { writeError(w, err); return }
			writeJSON(w, http.StatusCreated, envelope{Success: true, Msg: "inbound created"})
		case r.URL.Path == "/api/v1/stats" && r.Method == http.MethodGet:
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			stats, err := manager.QueryUserTraffic(ctx)
			if err != nil { writeError(w, err); return }
			writeJSON(w, http.StatusOK, envelope{Success: true, Obj: stats})
		default:
			rest := strings.TrimPrefix(r.URL.Path, "/api/v1/inbounds/")
			parts := strings.Split(rest, "/")
			if len(parts) == 1 && parts[0] != "" && r.Method == http.MethodDelete {
				if err := manager.DeleteInbound(parts[0]); err != nil { writeError(w, err); return }
				writeJSON(w, http.StatusOK, envelope{Success: true, Msg: "inbound deleted"})
				return
			}
			if len(parts) == 2 && parts[0] != "" && parts[1] == "clients" {
				switch r.Method {
				case http.MethodPost:
					var client map[string]interface{}
					if err := decodeBody(w, r, &client); err != nil { writeError(w, err); return }
					if err := manager.AddClient(parts[0], client); err != nil { writeError(w, err); return }
					writeJSON(w, http.StatusCreated, envelope{Success: true, Msg: "client created"})
				case http.MethodDelete:
					email := r.URL.Query().Get("email")
					if err := manager.DeleteClient(parts[0], email); err != nil { writeError(w, err); return }
					writeJSON(w, http.StatusOK, envelope{Success: true, Msg: "client deleted"})
				case http.MethodPut:
					email := r.URL.Query().Get("email")
					var patch map[string]interface{}
					if err := decodeBody(w, r, &patch); err != nil { writeError(w, err); return }
					if err := manager.UpdateClient(parts[0], email, patch); err != nil { writeError(w, err); return }
					writeJSON(w, http.StatusOK, envelope{Success: true, Msg: "client updated"})
				default:
					w.Header().Set("Allow", "POST, PUT, DELETE")
					writeJSON(w, http.StatusMethodNotAllowed, envelope{Success: false, Msg: "method not allowed"})
				}
				return
			}
			writeJSON(w, http.StatusNotFound, envelope{Success: false, Msg: "route not found"})
		}
	}
}

func main() {
	token := strings.TrimSpace(os.Getenv("AMIN_NODE_TOKEN"))
	if len(token) < 32 {
		log.Fatal("AMIN_NODE_TOKEN must contain at least 32 characters")
	}
	addr := strings.TrimSpace(os.Getenv("AMIN_NODE_LISTEN"))
	if addr == "" { addr = "127.0.0.1:8787" }
	host, _, err := net.SplitHostPort(addr)
	if err != nil { log.Fatalf("invalid AMIN_NODE_LISTEN: %v", err) }
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsLoopback() && os.Getenv("AMIN_NODE_ALLOW_PUBLIC") != "yes") {
		log.Fatal("public listen requires AMIN_NODE_ALLOW_PUBLIC=yes; prefer a private network or TLS reverse proxy")
	}

	manager, managerErr := xray.NewConfigManager()
	if managerErr != nil {
		log.Printf("Xray manager disabled: %v", managerErr)
		manager = nil
	} else if _, err := os.Stat(manager.Path); err != nil {
		log.Printf("Xray manager disabled: config unavailable: %v", err)
		manager = nil
	} else if info, err := os.Stat(manager.XrayBinary); err != nil || info.IsDir() {
		log.Printf("Xray manager disabled: binary unavailable")
		manager = nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", method(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, envelope{Success: true, Obj: map[string]interface{}{
			"service": "amin-node-agent", "version": "0.3.0", "uptimeSeconds": int64(time.Since(started).Seconds()),
		}})
	}))
	protected := http.NewServeMux()
	protected.HandleFunc("/api/v1/capabilities", method(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		features := []string{"health", "system", "capabilities"}
		if manager != nil {
			features = append(features, "inbounds.list", "inbounds.create", "inbounds.delete", "clients.create", "clients.update", "clients.delete")
			if _, err := manager.StatsAPIAddress(); err == nil { features = append(features, "clients.stats") }
		}
		writeJSON(w, http.StatusOK, envelope{Success: true, Obj: map[string]interface{}{
			"agentVersion": "0.3.0", "xrayManagement": manager != nil, "features": features,
			"protocols": []string{"vless", "vmess", "trojan", "shadowsocks"},
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
	protected.HandleFunc("/api/v1/inbounds", inboundAPI(manager))
	protected.HandleFunc("/api/v1/inbounds/", inboundAPI(manager))
	mux.Handle("/api/v1/", auth(token, protected))
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	log.Printf("AMIN Node Agent 0.3.0 listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}
