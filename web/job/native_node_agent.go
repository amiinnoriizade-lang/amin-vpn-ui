package job

import (
 "context"
 "encoding/json"
 "fmt"
 "hash/fnv"
 "net/http"
 "net/url"
 "strings"
 "time"

 "github.com/mhsanaei/3x-ui/v2/database"
 "github.com/mhsanaei/3x-ui/v2/database/model"
 "gorm.io/gorm"
)

// NativeAgentInbound is the read-only Xray inbound shape returned by AMIN Node Agent.
type NativeAgentInbound struct {
 Tag string `json:"tag"`
 Port int `json:"port"`
 Listen string `json:"listen"`
 Protocol string `json:"protocol"`
 Settings json.RawMessage `json:"settings"`
 StreamSettings json.RawMessage `json:"streamSettings"`
}

type nativeAgentClient struct {
 Email string `json:"email"`
 Enable *bool `json:"enable"`
 ExpiryTime int64 `json:"expiryTime"`
}

type nativeAgentSettings struct {
 Clients []nativeAgentClient `json:"clients"`
}

func NativeAgentListInbounds(ctx context.Context, n model.Node) ([]NativeAgentInbound, error) {
 raw, err := nodeRequestBody(ctx, n, http.MethodGet, "api/v1/inbounds", nil)
 if err != nil { return nil, err }
 var inbounds []NativeAgentInbound
 if err := json.Unmarshal(raw, &inbounds); err != nil { return nil, fmt.Errorf("decode AMIN Agent inbound list: %w", err) }
 return inbounds, nil
}

func NativeAgentCreateClient(ctx context.Context, n model.Node, tag string, client map[string]any) error {
 if strings.TrimSpace(tag)=="" { return fmt.Errorf("native inbound tag is missing") }
 body, err := json.Marshal(client)
 if err != nil { return err }
 endpoint := "api/v1/inbounds/" + url.PathEscape(tag) + "/clients"
 _, err = nodeRequestBody(ctx, n, http.MethodPost, endpoint, body)
 return err
}

func NativeAgentDeleteClient(ctx context.Context, n model.Node, tag, email string) error {
 if strings.TrimSpace(tag)=="" || strings.TrimSpace(email)=="" { return fmt.Errorf("inbound tag and client email are required") }
 endpoint := "api/v1/inbounds/" + url.PathEscape(tag) + "/clients?email=" + url.QueryEscape(email)
 _, err := nodeRequestBody(ctx, n, http.MethodDelete, endpoint, nil)
 return err
}

func nativeInboundID(tag string) int {
 h:=fnv.New32a()
 _,_ = h.Write([]byte(tag))
 id:=int(h.Sum32() & 0x7fffffff)
 if id==0 { return 1 }
 return id
}

func nativeClientEnabled(enabled *bool) bool {
	// Xray client objects commonly omit the enable field; omission means enabled.
	return enabled == nil || *enabled
}

func syncNativeAgentNode(n model.Node, now int64) ([]nodeClientDelta, []string, map[string]int64, error) {
 ctx,cancel:=context.WithTimeout(context.Background(),nodeTrafficRequestTimeout)
 defer cancel()
 inbounds,err:=NativeAgentListInbounds(ctx,n)
 if err!=nil { return nil,nil,nil,fmt.Errorf("fetch AMIN Agent inbounds: %w",err) }
 rows:=make([]model.NodeInboundSnapshot,0,len(inbounds))
 clients:=make(map[string]*model.NodeClientSnapshot)
 ids:=make(map[int]string,len(inbounds))
 for _,ib:=range inbounds {
  tag:=strings.TrimSpace(ib.Tag)
  if tag=="" { return nil,nil,nil,fmt.Errorf("AMIN Agent returned an inbound without a tag") }
  remoteID:=nativeInboundID(tag)
  if old,exists:=ids[remoteID]; exists && old!=tag { return nil,nil,nil,fmt.Errorf("inbound tag hash collision between %q and %q",old,tag) }
  ids[remoteID]=tag
  var settings nativeAgentSettings
  if len(ib.Settings)>0 { if err:=json.Unmarshal(ib.Settings,&settings); err!=nil { return nil,nil,nil,fmt.Errorf("decode clients for inbound %s: %w",tag,err) } }
  rows=append(rows,model.NodeInboundSnapshot{
   NodeID:n.Id,RemoteID:remoteID,Tag:tag,RemoteTag:tag,Remark:tag,Protocol:strings.ToLower(ib.Protocol),
   Listen:ib.Listen,Port:ib.Port,Enable:true,ClientCount:len(settings.Clients),LastSyncAt:now,
  })
  for _,client:=range settings.Clients {
   email:=strings.ToLower(strings.TrimSpace(client.Email))
   if email=="" { continue }
   enabled:=nativeClientEnabled(client.Enable)
   item:=clients[email]
   if item==nil {
    item=&model.NodeClientSnapshot{NodeID:n.Id,Email:email,Enable:enabled,LastSyncAt:now}
    clients[email]=item
   } else {
    // A username may be present on several inbounds; it is enabled if any
    // corresponding Xray client is enabled. Missing enable fields default to true.
    item.Enable=item.Enable || enabled
   }
   if client.ExpiryTime>item.ExpiryTime { item.ExpiryTime=client.ExpiryTime }
  }
 }
 clientRows:=make([]model.NodeClientSnapshot,0,len(clients))
 for _,client:=range clients { clientRows=append(clientRows,*client) }
 db:=database.GetDB()
 err=db.Transaction(func(tx *gorm.DB) error {
  if e:=tx.Where("node_id = ?",n.Id).Delete(&model.NodeInboundSnapshot{}).Error;e!=nil{return e}
  if e:=tx.Where("node_id = ?",n.Id).Delete(&model.NodeClientSnapshot{}).Error;e!=nil{return e}
  if len(rows)>0 { if e:=tx.CreateInBatches(&rows,100).Error;e!=nil{return e} }
  if len(clientRows)>0 { if e:=tx.CreateInBatches(&clientRows,200).Error;e!=nil{return e} }
  return tx.Model(&model.Node{}).Where("id = ?",n.Id).Updates(map[string]any{
   "inbound_count":len(rows),"client_count":len(clientRows),"last_sync_at":now,"last_sync_error":"",
  }).Error
 })
 if err!=nil { return nil,nil,nil,err }
 return []nodeClientDelta{},[]string{},map[string]int64{},nil
}

func probeNativeAgentNode(n model.Node) map[string]any {
 patch:=map[string]any{
  "last_heartbeat":time.Now().Unix(),"status":"offline","latency_ms":0,"last_error":"",
  "cpu_pct":0,"mem_pct":0,"uptime_secs":uint64(0),"panel_version":"",
  "agent_version":"","xray_version":"","xray_state":"","net_up":uint64(0),"net_down":uint64(0),
 }
 fail:=func(err error) map[string]any { patch["last_error"]=err.Error(); return patch }
 ctx,cancel:=context.WithTimeout(context.Background(),nodeHeartbeatTimeout)
 defer cancel()
 healthStarted:=time.Now()
 health,err:=nodeRequestBody(ctx,n,http.MethodGet,"health",nil)
 if err!=nil { return fail(fmt.Errorf("AMIN Agent health: %w",err)) }
 // Ping is the round-trip time of the lightweight health endpoint only.
 // Capability and system metadata are deliberately excluded: they are separate
 // management calls and must not inflate the network-latency figure.
 patch["latency_ms"]=int(time.Since(healthStarted).Milliseconds())
 var h struct { Version string `json:"version"`; UptimeSeconds uint64 `json:"uptimeSeconds"` }
 if err=json.Unmarshal(health,&h);err!=nil { return fail(fmt.Errorf("decode AMIN Agent health: %w",err)) }
 capabilities,err:=nodeRequestBody(ctx,n,http.MethodGet,"api/v1/capabilities",nil)
 if err!=nil { return fail(fmt.Errorf("AMIN Agent capabilities: %w",err)) }
 var caps struct { XrayManagement bool `json:"xrayManagement"` }
 if err=json.Unmarshal(capabilities,&caps);err!=nil { return fail(fmt.Errorf("decode AMIN Agent capabilities: %w",err)) }
 system,err:=nodeRequestBody(ctx,n,http.MethodGet,"api/v1/system",nil)
 if err!=nil { return fail(fmt.Errorf("AMIN Agent system: %w",err)) }
 var sys struct { UptimeSeconds uint64 `json:"uptimeSeconds"` }
 if err=json.Unmarshal(system,&sys);err!=nil { return fail(fmt.Errorf("decode AMIN Agent system: %w",err)) }
 patch["status"]="online"
 patch["agent_version"]=h.Version
 patch["uptime_secs"]=sys.UptimeSeconds
 if patch["uptime_secs"].(uint64)==0 { patch["uptime_secs"]=h.UptimeSeconds }
 if caps.XrayManagement { patch["xray_state"]="managed" } else { patch["xray_state"]="unavailable" }
 return patch
}
