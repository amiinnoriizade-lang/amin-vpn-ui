package job

import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "crypto/tls"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "strings"
 "sync"
 "time"

 "github.com/mhsanaei/3x-ui/v2/database"
 "github.com/mhsanaei/3x-ui/v2/database/model"
 "github.com/mhsanaei/3x-ui/v2/util/nodetoken"
 "github.com/mhsanaei/3x-ui/v2/logger"
 "github.com/mhsanaei/3x-ui/v2/web/websocket"
 "gorm.io/gorm"
)

const (
 nodeTrafficPollIntervalMs int64 = 5000
 nodeTrafficRequestTimeout = 4 * time.Second
 nodeTrafficResponseLimit = 16 << 20
)

type NodeTrafficSyncJob struct {
 running sync.Mutex
 previous map[int]map[string]nodeCounterSample
}
type nodeCounterSample struct { up, down, at int64 }

type nodeAPIEnvelope struct {
 Success bool `json:"success"`
 Msg string `json:"msg"`
 Obj json.RawMessage `json:"obj"`
}
type remoteInboundSnapshot struct {
 ID int `json:"id"`
 Tag string `json:"tag"`
 Remark string `json:"remark"`
 Protocol string `json:"protocol"`
 Listen string `json:"listen"`
 Port int `json:"port"`
 Enable bool `json:"enable"`
 Up int64 `json:"up"`
 Down int64 `json:"down"`
 Total int64 `json:"total"`
 ExpiryTime int64 `json:"expiryTime"`
 Settings json.RawMessage `json:"settings"`
 ClientStats []remoteClientSnapshot `json:"clientStats"`
}
type remoteClientSnapshot struct {
 Email string `json:"email"`
 Up int64 `json:"up"`
 Down int64 `json:"down"`
 Total int64 `json:"total"`
 ExpiryTime int64 `json:"expiryTime"`
 Enable bool `json:"enable"`
 LastOnline int64 `json:"lastOnline"`
}
type remoteSettings struct { Clients []struct {
 Email string `json:"email"`
 Enable bool `json:"enable"`
 ExpiryTime int64 `json:"expiryTime"`
 } `json:"clients"` }
type nodeClientAggregate struct {
 Up int64
 Down int64
 Total int64
 ExpiryTime int64
 Enable bool
 LastOnline int64
 Online bool
}
type nodeClientDelta struct {
 Email string `json:"email"`
 Up int64 `json:"up"`
 Down int64 `json:"down"`
}

func NewNodeTrafficSyncJob() *NodeTrafficSyncJob {
 return &NodeTrafficSyncJob{previous: make(map[int]map[string]nodeCounterSample)}
}

func nodeAddressAllowed(ip net.IP) bool {
 return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() &&
  !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
  !ip.IsUnspecified() && !ip.IsMulticast()
}

func nodeRequest(ctx context.Context, n model.Node, method, endpoint string) (json.RawMessage, error) {
 return nodeRequestBody(ctx, n, method, endpoint, nil)
}

// nodeRequestBody sends an authenticated request through the same DNS, SSRF, TLS,
// timeout, redirect, and response-size protections used by node synchronization.
func nodeRequestBody(ctx context.Context, n model.Node, method, endpoint string, body []byte) (json.RawMessage, error) {
 if n.ApiToken == "" { return nil, fmt.Errorf("node API token is missing") }
 token, tokenErr := nodetoken.Decrypt(n.ApiToken)
 if tokenErr != nil { return nil, fmt.Errorf("load node API token: %w", tokenErr) }
 if n.Port < 1 || n.Port > 65535 { return nil, fmt.Errorf("invalid node port") }
 scheme := n.Scheme
 if scheme != "http" && scheme != "https" { return nil, fmt.Errorf("unsupported node scheme") }
 host := strings.TrimSpace(strings.Trim(n.Address, "[]"))
 if host == "" || strings.ContainsAny(host, "/@?#") { return nil, fmt.Errorf("invalid node address") }
 ips, err := net.LookupIP(host)
 if err != nil || len(ips) == 0 { return nil, fmt.Errorf("resolve node address: %w", err) }
 for _, ip := range ips {
  if n.AgentMode && scheme == "http" && !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
   return nil, fmt.Errorf("AMIN Agent HTTP is allowed only over a private management tunnel; use HTTPS for public addresses")
  }
  if !n.AllowPrivateAddress && !nodeAddressAllowed(ip) {
   return nil, fmt.Errorf("private or reserved node address blocked")
  }
 }
 targetIP := ips[0].String()
 basePath := strings.TrimRight(n.BasePath, "/")
 endpointURL, err := url.Parse(endpoint)
 if err != nil || endpointURL.IsAbs() || endpointURL.Host != "" || strings.HasPrefix(endpointURL.Path, "//") {
  return nil, fmt.Errorf("invalid remote API endpoint")
 }
 u := url.URL{
  Scheme: scheme,
  Host: net.JoinHostPort(host, strconv.Itoa(n.Port)),
  Path: basePath + "/" + strings.TrimLeft(endpointURL.Path, "/"),
  RawQuery: endpointURL.RawQuery,
 }
 requestTimeout := nodeTrafficRequestTimeout
 if body != nil { requestTimeout = 12 * time.Second }
 reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
 defer cancel()
 var requestBody io.Reader
 if body != nil { requestBody = bytes.NewReader(body) }
 req, err := http.NewRequestWithContext(reqCtx, method, u.String(), requestBody)
 if err != nil { return nil, err }
 req.Header.Set("Accept", "application/json")
 if body != nil { req.Header.Set("Content-Type", "application/json") }
 req.Header.Set("Authorization", "Bearer " + token)
 transport := &http.Transport{
  TLSClientConfig: &tls.Config{
   MinVersion: tls.VersionTLS12,
   InsecureSkipVerify: n.TlsVerifyMode == "insecure" || n.TlsVerifyMode == "pinned",
   VerifyConnection: func(state tls.ConnectionState) error {
    if n.TlsVerifyMode != "pinned" { return nil }
    if len(state.PeerCertificates) == 0 { return fmt.Errorf("remote panel sent no TLS certificate") }
    sum := sha256.Sum256(state.PeerCertificates[0].Raw)
    expected, e := hex.DecodeString(strings.TrimSpace(n.PinnedCertSha256))
    if e != nil || len(expected) != sha256.Size { return fmt.Errorf("invalid pinned certificate SHA-256") }
    if subtle.ConstantTimeCompare(sum[:], expected) != 1 { return fmt.Errorf("node TLS certificate fingerprint mismatch") }
    return nil
   },
  },
  DialContext: func(c context.Context, network, address string) (net.Conn, error) {
   return (&net.Dialer{Timeout: requestTimeout}).DialContext(c, "tcp", net.JoinHostPort(targetIP, strconv.Itoa(n.Port)))
  },
 }
 client := &http.Client{Transport: transport, Timeout: requestTimeout,
  CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
 defer transport.CloseIdleConnections()
 resp, err := client.Do(req)
 if err != nil { return nil, err }
 defer resp.Body.Close()
 if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices { return nil, fmt.Errorf("remote API returned HTTP %d", resp.StatusCode) }
 raw, err := io.ReadAll(io.LimitReader(resp.Body, nodeTrafficResponseLimit+1))
 if err != nil { return nil, err }
 if len(raw) > nodeTrafficResponseLimit { return nil, fmt.Errorf("remote response exceeds %d bytes", nodeTrafficResponseLimit) }
 var env nodeAPIEnvelope
 if err := json.Unmarshal(raw, &env); err != nil { return nil, fmt.Errorf("decode remote response: %w", err) }
 if !env.Success { return nil, fmt.Errorf("remote API: %s", env.Msg) }
 return env.Obj, nil
}

// CreateNodeClient provisions one account on a remote Sanaei/3x-ui node.
// The caller must validate the selected inbound against the synchronized snapshot.
func CreateNodeClient(ctx context.Context, n model.Node, payload []byte) (json.RawMessage, error) {
 return nodeRequestBody(ctx, n, http.MethodPost, "panel/api/clients/add", payload)
}

func decodeRemoteOnline(raw json.RawMessage) map[string]bool {
 out := make(map[string]bool)
 var emails []string
 if json.Unmarshal(raw, &emails) == nil {
  for _, email := range emails { email = strings.ToLower(strings.TrimSpace(email)); if email != "" { out[email] = true } }
 }
 return out
}

func mergeRemoteClient(dst map[string]*nodeClientAggregate, c remoteClientSnapshot) {
 email := strings.ToLower(strings.TrimSpace(c.Email))
 if email == "" { return }
 v := dst[email]
 if v == nil { v = &nodeClientAggregate{Enable: c.Enable}; dst[email] = v }
 // The same account may be present on several inbounds; use the maximum
 // cumulative counter, never sum duplicate account-wide snapshots.
 if c.Up > v.Up { v.Up = c.Up }
 if c.Down > v.Down { v.Down = c.Down }
 if c.Total > v.Total { v.Total = c.Total }
 if c.ExpiryTime > v.ExpiryTime { v.ExpiryTime = c.ExpiryTime }
 if c.LastOnline > v.LastOnline { v.LastOnline = c.LastOnline }
 v.Enable = v.Enable || c.Enable
}

func decodeSettingsClients(raw json.RawMessage) []struct {
 Email string `json:"email"`
 Enable bool `json:"enable"`
 ExpiryTime int64 `json:"expiryTime"`
} {
 var settings remoteSettings
 // Legacy panel stores settings as a JSON string; tolerate object form too.
 var encoded string
 if json.Unmarshal(raw, &encoded) == nil { raw = json.RawMessage(encoded) }
 if len(raw) > 0 { _ = json.Unmarshal(raw, &settings) }
 return settings.Clients
}

func nodeSpeedDelta(previous map[string]nodeCounterSample, current map[string]*nodeClientAggregate, now int64) (map[string]nodeCounterSample, []nodeClientDelta) {
 next := make(map[string]nodeCounterSample, len(current))
 deltas := make([]nodeClientDelta, 0, len(current))
 for email, c := range current {
  old, exists := previous[email]
  sample := nodeCounterSample{up:c.Up, down:c.Down, at:now}
  if exists {
   up, down := c.Up-old.up, c.Down-old.down
   if up < 0 || down < 0 { up, down = 0, 0
   } else if up > 0 || down > 0 {
    elapsed := now-old.at
    if elapsed < nodeTrafficPollIntervalMs { elapsed = nodeTrafficPollIntervalMs }
    up = up*nodeTrafficPollIntervalMs/elapsed
    down = down*nodeTrafficPollIntervalMs/elapsed
   } else { sample.at = old.at }
   if up > 0 || down > 0 { deltas = append(deltas, nodeClientDelta{Email:email,Up:up,Down:down}) }
  }
  next[email] = sample
 }
 return next, deltas
}

func (j *NodeTrafficSyncJob) syncNode(n model.Node, now int64) ([]nodeClientDelta, []string, map[string]int64, error) {
 if n.AgentMode {
  previous := j.previous[n.Id]
  if previous == nil { previous = make(map[string]nodeCounterSample) }
  deltas, online, last, err := syncNativeAgentNode(n, now, previous)
  if err == nil { j.previous[n.Id] = previous }
  return deltas, online, last, err
 }
 raw, err := nodeRequest(context.Background(), n, http.MethodGet, "panel/api/inbounds/list")
 if err != nil { return nil, nil, nil, fmt.Errorf("fetch inbounds: %w", err) }
 var inbounds []remoteInboundSnapshot
 if err = json.Unmarshal(raw, &inbounds); err != nil { return nil,nil,nil,fmt.Errorf("decode inbound list: %w",err) }
 onlineRaw, onlineErr := nodeRequest(context.Background(), n, http.MethodPost, "panel/api/clients/onlines")
 online := map[string]bool{}
 if onlineErr == nil { online = decodeRemoteOnline(onlineRaw) }
 lastRaw, lastErr := nodeRequest(context.Background(), n, http.MethodPost, "panel/api/clients/lastOnline")
 lastOnline := map[string]int64{}
 if lastErr == nil { _ = json.Unmarshal(lastRaw, &lastOnline) }

 clients := make(map[string]*nodeClientAggregate)
 inboundRows := make([]model.NodeInboundSnapshot, 0, len(inbounds))
 for _, ib := range inbounds {
  inboundRows = append(inboundRows, model.NodeInboundSnapshot{
   NodeID:n.Id, RemoteID:ib.ID, Tag:ib.Tag, Remark:ib.Remark, Protocol:ib.Protocol,
   Listen:ib.Listen, Port:ib.Port, Enable:ib.Enable, Up:ib.Up, Down:ib.Down,
   Total:ib.Total, ExpiryTime:ib.ExpiryTime, ClientCount:len(ib.ClientStats), LastSyncAt:now,
  })
  for _, c := range ib.ClientStats { mergeRemoteClient(clients,c) }
  for _, c := range decodeSettingsClients(ib.Settings) {
   email := strings.ToLower(strings.TrimSpace(c.Email))
   if email == "" { continue }
   if clients[email] == nil { clients[email] = &nodeClientAggregate{Enable:c.Enable,ExpiryTime:c.ExpiryTime} }
   clients[email].Enable = clients[email].Enable || c.Enable
   if c.ExpiryTime > clients[email].ExpiryTime { clients[email].ExpiryTime = c.ExpiryTime }
  }
 }
 onlineEmails := make([]string,0,len(online))
 for email := range online { onlineEmails=append(onlineEmails,email) }
 for email, c := range clients {
  c.Online = online[email]
  if lastOnline[email] > c.LastOnline { c.LastOnline = lastOnline[email] }
 }
 next,deltas:=nodeSpeedDelta(j.previous[n.Id],clients,now)
 j.previous[n.Id]=next
 rates:=make(map[string]nodeClientDelta,len(deltas))
 for _,rate:=range deltas { rates[rate.Email]=rate }
 clientRows := make([]model.NodeClientSnapshot,0,len(clients))
 for email,c := range clients {
  row:=model.NodeClientSnapshot{
   NodeID:n.Id,Email:email,Up:c.Up,Down:c.Down,Total:c.Total,ExpiryTime:c.ExpiryTime,
   Enable:c.Enable,Online:c.Online,LastOnline:c.LastOnline,LastSyncAt:now,
  }
  if rate,ok:=rates[email];ok {
   row.UpSpeed=rate.Up*1000/nodeTrafficPollIntervalMs
   row.DownSpeed=rate.Down*1000/nodeTrafficPollIntervalMs
  }
  clientRows=append(clientRows,row)
 }
 db:=database.GetDB()
 err=db.Transaction(func(tx *gorm.DB) error {
  if e:=tx.Where("node_id = ?",n.Id).Delete(&model.NodeInboundSnapshot{}).Error;e!=nil{return e}
  if e:=tx.Where("node_id = ?",n.Id).Delete(&model.NodeClientSnapshot{}).Error;e!=nil{return e}
  if len(inboundRows)>0 { if e:=tx.CreateInBatches(&inboundRows,100).Error;e!=nil{return e} }
  if len(clientRows)>0 { if e:=tx.CreateInBatches(&clientRows,200).Error;e!=nil{return e} }
  return tx.Model(&model.Node{}).Where("id = ?",n.Id).Updates(map[string]any{
   "inbound_count":len(inboundRows),"client_count":len(clientRows),"last_sync_at":now,"last_sync_error":"",
  }).Error
 })
 if err!=nil { return nil,nil,nil,err }
 last := make(map[string]int64,len(clients))
 for email,c:=range clients { if c.LastOnline>0 { last[email]=c.LastOnline } }
 return deltas,onlineEmails,last,nil
}

func (j *NodeTrafficSyncJob) Run() {
 if !j.running.TryLock() { return }
 defer j.running.Unlock()
 var nodes []model.Node
 if err:=database.GetDB().Where("enable = ? AND status = ?",true,"online").Order("id asc").Find(&nodes).Error;err!=nil {
  logger.Warning("node traffic sync: load nodes: ",err);return
 }
 now:=time.Now().UnixMilli()
 combined:=make(map[string]nodeClientDelta)
 onlineSet:=make(map[string]bool)
 lastOnline:=make(map[string]int64)
 for _,n:=range nodes {
  deltas,online,last,err:=j.syncNode(n,now)
  if err!=nil {
   logger.Warningf("node traffic sync: %s: %v",n.Name,err)
   _=database.GetDB().Model(&model.Node{}).Where("id = ?",n.Id).Update("last_sync_error",err.Error()).Error
   continue
  }
  for _,d:=range deltas { v:=combined[d.Email];v.Email=d.Email;v.Up+=d.Up;v.Down+=d.Down;combined[d.Email]=v }
  for _,email:=range online { onlineSet[email]=true }
  for email,stamp:=range last { if stamp>lastOnline[email] {lastOnline[email]=stamp} }
 }
 // Remove baselines only for nodes that no longer exist; offline nodes retain
 // their counters so a recovery is averaged across the actual gap.
 var allIDs []int
 if err:=database.GetDB().Model(&model.Node{}).Pluck("id",&allIDs).Error;err==nil {
  alive:=make(map[int]bool,len(allIDs));for _,id:=range allIDs{alive[id]=true}
  for id:=range j.previous{if !alive[id]{delete(j.previous,id)}}
 }
 if !websocket.HasClients(){return}
 traffic:=make([]nodeClientDelta,0,len(combined))
 for _,d:=range combined{traffic=append(traffic,d)}
 online:=make([]string,0,len(onlineSet));for email:=range onlineSet{online=append(online,email)}
 websocket.BroadcastTraffic(map[string]any{
  "clientTraffics":traffic,"clientTrafficSource":"node",
  "clientTrafficIntervalMs":nodeTrafficPollIntervalMs,
  "onlineClients":online,"lastOnlineMap":lastOnline,
 })
}


// ManageNodeClient executes an authenticated client-management request on a node.
// Endpoint paths are selected by the controller from the documented Sanaei API.
func ManageNodeClient(ctx context.Context, n model.Node, method, endpoint string, payload []byte) (json.RawMessage, error) {
 return nodeRequestBody(ctx, n, method, endpoint, payload)
}
