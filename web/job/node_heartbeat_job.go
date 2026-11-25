package job

import (
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/hex"
 "crypto/tls"
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
 "github.com/mhsanaei/3x-ui/v2/logger"
 "github.com/mhsanaei/3x-ui/v2/web/websocket"
)

const nodeHeartbeatTimeout = 4 * time.Second

type NodeHeartbeatJob struct { running sync.Mutex }
func NewNodeHeartbeatJob() *NodeHeartbeatJob { return &NodeHeartbeatJob{} }

type nodeStatusEnvelope struct {
 Success bool `json:"success"`
 Msg string `json:"msg"`
 Obj *struct {
  CPU float64 `json:"cpu"`
  Mem struct { Current uint64 `json:"current"`; Total uint64 `json:"total"` } `json:"mem"`
  PanelVersion string `json:"panelVersion"`
  Uptime uint64 `json:"uptime"`
  Xray struct { Version string `json:"version"`; State string `json:"state"` } `json:"xray"`
 } `json:"obj"`
}

func isPublicNodeIP(ip net.IP) bool {
 return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func probeNode(n model.Node) map[string]any {
 patch := map[string]any{"last_heartbeat":time.Now().Unix(),"status":"offline","latency_ms":0,"last_error":"","cpu_pct":0,"mem_pct":0,"uptime_secs":uint64(0),"panel_version":"","xray_version":"","xray_state":""}
 fail := func(err error) map[string]any { patch["last_error"]=err.Error(); return patch }
 if n.Port<1 || n.Port>65535 { return fail(fmt.Errorf("invalid node port")) }
 scheme:=n.Scheme
 if scheme!="http" && scheme!="https" { return fail(fmt.Errorf("unsupported node scheme")) }
 host:=strings.TrimSpace(strings.Trim(n.Address,"[]"))
 if host=="" || strings.ContainsAny(host,"/@?#") { return fail(fmt.Errorf("invalid node address")) }
 ips,err:=net.LookupIP(host)
 if err!=nil || len(ips)==0 { return fail(fmt.Errorf("resolve node address: %v",err)) }
 for _,ip:=range ips { if !n.AllowPrivateAddress && !isPublicNodeIP(ip) { return fail(fmt.Errorf("private or reserved node address blocked; enable allowPrivateAddress only for trusted networks")) } }
 targetIP:=ips[0].String()
 path:=strings.TrimRight(n.BasePath,"/")+"/panel/api/server/status"
 u:=url.URL{Scheme:scheme,Host:net.JoinHostPort(host,strconv.Itoa(n.Port)),Path:path}
 ctx,cancel:=context.WithTimeout(context.Background(),nodeHeartbeatTimeout); defer cancel()
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,u.String(),nil); if err!=nil{return fail(err)}
 req.Header.Set("Accept","application/json")
 if n.ApiToken!="" { req.Header.Set("Authorization","Bearer "+n.ApiToken) }
 if n.TlsVerifyMode=="pinned" { return fail(fmt.Errorf("pinned certificate verification is not implemented yet; use system verification")) }
 transport:=&http.Transport{
  TLSClientConfig:&tls.Config{
   MinVersion:tls.VersionTLS12,
   InsecureSkipVerify:n.TlsVerifyMode=="insecure" || n.TlsVerifyMode=="pinned",
   VerifyConnection:func(state tls.ConnectionState) error {
    if n.TlsVerifyMode!="pinned" { return nil }
    if len(state.PeerCertificates)==0 { return fmt.Errorf("node did not present a TLS certificate") }
    sum:=sha256.Sum256(state.PeerCertificates[0].Raw)
    expected,err:=hex.DecodeString(strings.TrimSpace(n.PinnedCertSha256))
    if err!=nil || len(expected)!=sha256.Size { return fmt.Errorf("invalid pinned certificate SHA-256 fingerprint") }
    if subtle.ConstantTimeCompare(sum[:],expected)!=1 { return fmt.Errorf("node TLS certificate fingerprint mismatch") }
    return nil
   },
  },
  DialContext:func(ctx context.Context,network,address string)(net.Conn,error){ return (&net.Dialer{Timeout:nodeHeartbeatTimeout}).DialContext(ctx,"tcp",net.JoinHostPort(targetIP,strconv.Itoa(n.Port))) },
 }
 client:=&http.Client{Transport:transport,Timeout:nodeHeartbeatTimeout,CheckRedirect:func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}; defer transport.CloseIdleConnections()
 started:=time.Now()
 resp,err:=client.Do(req); if err!=nil{return fail(err)}; defer resp.Body.Close()
 patch["latency_ms"]=int(time.Since(started).Milliseconds())
 if resp.StatusCode!=http.StatusOK { return fail(fmt.Errorf("remote panel returned HTTP %d",resp.StatusCode)) }
 var envelope nodeStatusEnvelope
 if err=json.NewDecoder(io.LimitReader(resp.Body,1<<20)).Decode(&envelope); err!=nil{return fail(fmt.Errorf("decode status response: %w",err))}
 if !envelope.Success || envelope.Obj==nil { return fail(fmt.Errorf("remote panel status unavailable: %s",envelope.Msg)) }
 patch["status"]="online"; patch["cpu_pct"]=envelope.Obj.CPU
 if envelope.Obj.Mem.Total>0 { patch["mem_pct"]=float64(envelope.Obj.Mem.Current)*100/float64(envelope.Obj.Mem.Total) }
 patch["uptime_secs"]=envelope.Obj.Uptime; patch["panel_version"]=envelope.Obj.PanelVersion
 patch["xray_version"]=envelope.Obj.Xray.Version; patch["xray_state"]=envelope.Obj.Xray.State
 return patch
}

func ProbeNode(n model.Node) map[string]any { return probeNode(n) }

func (j *NodeHeartbeatJob) Run() {
 if !j.running.TryLock(){return}; defer j.running.Unlock()
 var nodes []model.Node
 if err:=database.GetDB().Where("enable = ?",true).Find(&nodes).Error; err!=nil { logger.Warning("node heartbeat: load nodes: ",err); return }
 sem:=make(chan struct{},16); var wg sync.WaitGroup
 for _,node:=range nodes { n:=node; wg.Add(1); sem<-struct{}{}
  go func(){defer wg.Done();defer func(){<-sem}()
   patch:=probeNode(n)
   if err:=database.GetDB().Model(&model.Node{}).Where("id = ?",n.Id).Updates(patch).Error;err!=nil {logger.Warning("node heartbeat: update node ",n.Id,": ",err)}
  }()
 }
 wg.Wait()
 if websocket.HasClients() {
  var updated []model.Node
  if err:=database.GetDB().Order("id asc").Find(&updated).Error; err==nil {
   websocket.BroadcastNodes(updated)
  }
 }
}
