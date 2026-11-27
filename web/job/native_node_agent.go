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

// decodeNativeAgentObject accepts both the Agent's standard {success,obj} envelope
// and direct JSON payloads used by older Agent builds.
func decodeNativeAgentObject(raw []byte, target any) error {
	var envelope struct {
		Success *bool           `json:"success"`
		Obj     json.RawMessage `json:"obj"`
		Msg     string          `json:"msg"`
		Error   string          `json:"error"`
	}
	if len(raw) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return fmt.Errorf("decode AMIN Agent response: %w", err)
		}
		if envelope.Success != nil {
			if !*envelope.Success {
				message := strings.TrimSpace(envelope.Msg)
				if message == "" { message = strings.TrimSpace(envelope.Error) }
				if message == "" { message = "Agent returned success=false" }
				return fmt.Errorf("AMIN Agent API: %s", message)
			}
			if len(envelope.Obj) == 0 || string(envelope.Obj) == "null" {
				return fmt.Errorf("AMIN Agent response has no obj payload")
			}
			raw = envelope.Obj
		}
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode AMIN Agent payload: %w", err)
	}
	return nil
}

type NativeAgentUserTraffic struct {
	Email string `json:"email"`
	Up int64 `json:"up"`
	Down int64 `json:"down"`
}

// NativeAgentQueryUserTraffic fetches cumulative Xray StatsService counters.
// It does not reset counters; rate calculation remains panel-side and per node.
func NativeAgentQueryUserTraffic(ctx context.Context, n model.Node) ([]NativeAgentUserTraffic, error) {
	raw, err := nodeRequestBody(ctx, n, http.MethodGet, "api/v1/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("query AMIN Agent traffic stats: %w", err)
	}
	var traffic []NativeAgentUserTraffic
	if err := decodeNativeAgentObject(raw, &traffic); err != nil {
		return nil, fmt.Errorf("decode AMIN Agent traffic stats: %w", err)
	}
	return traffic, nil
}

func NativeAgentListInbounds(ctx context.Context, n model.Node) ([]NativeAgentInbound, error) {
 raw, err := nodeRequestBody(ctx, n, http.MethodGet, "api/v1/inbounds", nil)
 if err != nil {
  return nil, err
 }

 var inbounds []NativeAgentInbound
 if err := decodeNativeAgentObject(raw, &inbounds); err != nil {
  return nil, fmt.Errorf("decode AMIN Agent inbound list: %w", err)
 }
 if inbounds == nil {
  inbounds = []NativeAgentInbound{}
 }
 return inbounds, nil
}

// NativeAgentCreateInbound creates a new Xray listener through the authenticated Agent API.
// The caller must validate port conflicts and verify the resulting live inbound.
func NativeAgentCreateInbound(ctx context.Context, n model.Node, inbound map[string]any) error {
 tag, _ := inbound["tag"].(string)
 if strings.TrimSpace(tag) == "" {
  return fmt.Errorf("native inbound tag is required")
 }
 port, ok := inbound["port"].(int)
 if !ok || port < 1 || port > 65535 {
  return fmt.Errorf("native inbound port must be between 1 and 65535")
 }
 body, err := json.Marshal(inbound)
 if err != nil {
  return fmt.Errorf("encode native inbound: %w", err)
 }
 _, err = nodeRequestBody(ctx, n, http.MethodPost, "api/v1/inbounds", body)
 if err != nil {
  return fmt.Errorf("AMIN Agent could not create inbound on port %d: %w", port, err)
 }
 return nil
}

func NativeAgentCreateClient(ctx context.Context, n model.Node, tag string, client map[string]any) error {
 if strings.TrimSpace(tag)=="" { return fmt.Errorf("native inbound tag is missing") }
 body, err := json.Marshal(client)
 if err != nil { return err }
 endpoint := "api/v1/inbounds/" + url.PathEscape(tag) + "/clients"
 _, err = nodeRequestBody(ctx, n, http.MethodPost, endpoint, body)
 return err
}

// NativeAgentInboundHasClient confirms that a client is present in the live Xray
// configuration, rather than trusting only the mutation endpoint's HTTP response.
func NativeAgentInboundHasClient(ctx context.Context, n model.Node, tag, email string) (bool, error) {
 tag = strings.TrimSpace(tag)
 email = strings.ToLower(strings.TrimSpace(email))
 if tag == "" || email == "" {
  return false, fmt.Errorf("inbound tag and client email are required")
 }
 inbounds, err := NativeAgentListInbounds(ctx, n)
 if err != nil {
  return false, fmt.Errorf("verify AMIN Agent client: %w", err)
 }
 for _, inbound := range inbounds {
  if inbound.Tag != tag {
   continue
  }
  var settings nativeAgentSettings
  if len(inbound.Settings) > 0 {
   if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
    return false, fmt.Errorf("decode clients for inbound %s: %w", tag, err)
   }
  }
  for _, client := range settings.Clients {
   if strings.EqualFold(strings.TrimSpace(client.Email), email) {
    return true, nil
   }
  }
  return false, nil
 }
 return false, fmt.Errorf("inbound %q is no longer present on AMIN Agent", tag)
}

// NativeAgentUpdateClient applies a validated, protocol-specific patch to one
// client without replacing its other credentials or Xray settings.
func NativeAgentUpdateClient(ctx context.Context, n model.Node, tag, email string, patch map[string]any) error {
	tag = strings.TrimSpace(tag)
	email = strings.TrimSpace(email)
	if tag == "" || email == "" || len(patch) == 0 {
		return fmt.Errorf("inbound tag, client email and at least one update field are required")
	}
	body, err := json.Marshal(patch)
	if err != nil { return fmt.Errorf("encode AMIN Agent client update: %w", err) }
	endpoint := "api/v1/inbounds/" + url.PathEscape(tag) + "/clients?email=" + url.QueryEscape(email)
	_, err = nodeRequestBody(ctx, n, http.MethodPut, endpoint, body)
	if err != nil { return fmt.Errorf("AMIN Agent client update failed: %w", err) }
	return nil
}

func NativeAgentDeleteClient(ctx context.Context, n model.Node, tag, email string) error {
 if strings.TrimSpace(tag)=="" || strings.TrimSpace(email)=="" { return fmt.Errorf("inbound tag and client email are required") }
 endpoint := "api/v1/inbounds/" + url.PathEscape(tag) + "/clients?email=" + url.QueryEscape(email)
 _, err := nodeRequestBody(ctx, n, http.MethodDelete, endpoint, nil)
 return err
}

func NativeAgentInboundID(tag string) int {
 h:=fnv.New32a()
 _,_ = h.Write([]byte(tag))
 id:=int(h.Sum32() & 0x7fffffff)
 if id==0 { return 1 }
 return id
}

func nativeInboundID(tag string) int { return NativeAgentInboundID(tag) }

func nativeClientEnabled(enabled *bool) bool {
	// Xray client objects commonly omit the enable field; omission means enabled.
	return enabled == nil || *enabled
}

func syncNativeAgentNode(n model.Node, now int64, previous map[string]nodeCounterSample) ([]nodeClientDelta, []string, map[string]int64, error) {
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
 // Read cumulative per-user Xray counters. StatsService is optional; if it is
 // not configured, retain a useful inbound/client snapshot and record the
 // reason rather than fabricating zero-speed samples.
 stats, statsErr := NativeAgentQueryUserTraffic(ctx, n)
 if statsErr == nil {
  for _, sample := range stats {
   email := strings.ToLower(strings.TrimSpace(sample.Email))
   if client := clients[email]; client != nil {
    if sample.Up >= 0 { client.Up = sample.Up }
    if sample.Down >= 0 { client.Down = sample.Down }
   }
  }
 }
 aggregates := make(map[string]*nodeClientAggregate, len(clients))
 for email, client := range clients {
  aggregates[email] = &nodeClientAggregate{
   Up:client.Up, Down:client.Down, Total:client.Total,
   ExpiryTime:client.ExpiryTime, Enable:client.Enable,
   LastOnline:client.LastOnline, Online:client.Online,
  }
 }
 var deltas []nodeClientDelta
 if statsErr == nil {
  next, calculated := nodeSpeedDelta(previous, aggregates, now)
  deltas = calculated
  // The caller supplies a per-node map. Replace its contents after a valid
  // stats sample so an unavailable StatsService cannot create a false spike.
  for email := range previous { delete(previous, email) }
  for email, sample := range next { previous[email] = sample }
 }
 clientRows:=make([]model.NodeClientSnapshot,0,len(clients))
 for _,client:=range clients { clientRows=append(clientRows,*client) }
 db:=database.GetDB()
 err=db.Transaction(func(tx *gorm.DB) error {
  if e:=tx.Where("node_id = ?",n.Id).Delete(&model.NodeInboundSnapshot{}).Error;e!=nil{return e}
  if e:=tx.Where("node_id = ?",n.Id).Delete(&model.NodeClientSnapshot{}).Error;e!=nil{return e}
  if len(rows)>0 { if e:=tx.CreateInBatches(&rows,100).Error;e!=nil{return e} }
  if len(clientRows)>0 { if e:=tx.CreateInBatches(&clientRows,200).Error;e!=nil{return e} }
  lastErr := ""
  if statsErr != nil { lastErr = "traffic stats unavailable: " + statsErr.Error() }
  return tx.Model(&model.Node{}).Where("id = ?",n.Id).Updates(map[string]any{
   "inbound_count":len(rows),"client_count":len(clientRows),"last_sync_at":now,"last_sync_error":lastErr,
  }).Error
 })
 if err!=nil { return nil,nil,nil,err }
 return deltas,[]string{},map[string]int64{},nil
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
 if err=decodeNativeAgentObject(health,&h);err!=nil { return fail(fmt.Errorf("decode AMIN Agent health: %w",err)) }
 capabilities,err:=nodeRequestBody(ctx,n,http.MethodGet,"api/v1/capabilities",nil)
 if err!=nil { return fail(fmt.Errorf("AMIN Agent capabilities: %w",err)) }
 var caps struct { XrayManagement bool `json:"xrayManagement"` }
 if err=decodeNativeAgentObject(capabilities,&caps);err!=nil { return fail(fmt.Errorf("decode AMIN Agent capabilities: %w",err)) }
 system,err:=nodeRequestBody(ctx,n,http.MethodGet,"api/v1/system",nil)
 if err!=nil { return fail(fmt.Errorf("AMIN Agent system: %w",err)) }
 var sys struct { UptimeSeconds uint64 `json:"uptimeSeconds"` }
 if err=decodeNativeAgentObject(system,&sys);err!=nil { return fail(fmt.Errorf("decode AMIN Agent system: %w",err)) }
 patch["status"]="online"
 patch["agent_version"]=h.Version
 patch["uptime_secs"]=sys.UptimeSeconds
 if patch["uptime_secs"].(uint64)==0 { patch["uptime_secs"]=h.UptimeSeconds }
 if caps.XrayManagement { patch["xray_state"]="managed" } else { patch["xray_state"]="unavailable" }
 return patch
}
