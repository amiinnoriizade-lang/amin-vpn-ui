package controller

import (
 "net"
 "net/http"
 "net/url"
 "time"
 "encoding/json"
 "encoding/base64"
 "fmt"
 "context"
 "crypto/ecdh"


 "github.com/google/uuid"
 "github.com/skip2/go-qrcode"
 "github.com/mhsanaei/3x-ui/v2/web/job"
 "github.com/mhsanaei/3x-ui/v2/web/websocket"
 "strconv"
 "strings"

 "github.com/gin-gonic/gin"
 "github.com/mhsanaei/3x-ui/v2/database"
 "github.com/mhsanaei/3x-ui/v2/database/model"
 "github.com/mhsanaei/3x-ui/v2/util/nodetoken"
 "gorm.io/gorm"
)

// NodeController exposes authenticated CRUD for configured remote nodes.
// Remote probing and synchronization are intentionally separate follow-up work.
type NodeController struct { BaseController }

type nodeMutation struct {
 Name string `form:"name" json:"name"`
 Remark string `form:"remark" json:"remark"`
 Scheme string `form:"scheme" json:"scheme"`
 Address string `form:"address" json:"address"`
 PublicAddress string `form:"publicAddress" json:"publicAddress"`
 Port int `form:"port" json:"port"`
 BasePath string `form:"basePath" json:"basePath"`
 ApiToken string `form:"apiToken" json:"apiToken"`
 AgentMode bool `form:"agentMode" json:"agentMode"`
 Enable *bool `form:"enable" json:"enable"`
 AllowPrivateAddress bool `form:"allowPrivateAddress" json:"allowPrivateAddress"`
 TlsVerifyMode string `form:"tlsVerifyMode" json:"tlsVerifyMode"`
 PinnedCertSha256 string `form:"pinnedCertSha256" json:"pinnedCertSha256"`
 InboundSyncMode string `form:"inboundSyncMode" json:"inboundSyncMode"`
 InboundTags string `form:"inboundTags" json:"inboundTags"`
 OutboundTag string `form:"outboundTag" json:"outboundTag"`
 Guid string `form:"guid" json:"guid"`
 ParentGuid string `form:"parentGuid" json:"parentGuid"`
 Transitive bool `form:"transitive" json:"transitive"`
}

func NewNodeController(g *gin.RouterGroup) *NodeController {
 c := &NodeController{}
 g.GET("/list", c.list)
 g.GET("/get/:id", c.get)
 g.POST("/add", c.add)
 g.POST("/update/:id", c.update)
 g.POST("/del/:id", c.delete)
 g.POST("/setEnable/:id", c.setEnable)
 g.POST("/probe/:id", c.probe)
 g.GET("/snapshot/:id", c.snapshot)
 g.POST("/createClient/:id", c.createClient)
 g.GET("/clients", c.listNodeClients)
 g.POST("/clients/update/:id/:email", c.updateNodeClient)
 g.POST("/clients/delete/:id/:email", c.deleteNodeClient)
 g.GET("/clients/config/:id/:email", c.nodeClientConfig)
 return c
}

func nodeDB() *gorm.DB { return database.GetDB() }

func validNodeHost(host string) bool {
 host=strings.TrimSpace(host)
 if host=="" || strings.ContainsAny(host,"/?#@") { return false }
 if strings.HasPrefix(host,"[") && strings.HasSuffix(host,"]") { host=host[1:len(host)-1] }
 if net.ParseIP(host)!=nil { return true }
 // Public endpoint is a host only; the listener port comes from the inbound.
 if strings.Contains(host,":") { return false }
 u,err:=url.Parse("https://"+host)
 return err==nil && u.Hostname()!="" && u.User==nil && u.Path==""
}

func validNodeMutation(v nodeMutation, creating bool) string {
 if strings.TrimSpace(v.Name)=="" { return "name is required" }
 if strings.TrimSpace(v.Address)=="" { return "address is required" }
 if v.PublicAddress!="" && !validNodeHost(v.PublicAddress) { return "publicAddress must be a hostname or IP without a URL path" }
 if v.Scheme=="" { v.Scheme="https" }
 if v.Scheme!="http" && v.Scheme!="https" { return "scheme must be http or https" }
 if v.Port<1 || v.Port>65535 { return "port must be between 1 and 65535" }
 if strings.ContainsAny(v.Address, "/?#@") { return "address must be a hostname or IP without a URL path" }
 if net.ParseIP(v.Address)==nil {
  u,err:=url.Parse("https://"+v.Address)
  if err!=nil || u.Hostname()=="" || u.User!=nil || u.Path!="" { return "invalid address" }
 }
 if creating && strings.TrimSpace(v.ApiToken)=="" { return "apiToken is required" }
 if v.AgentMode && v.Scheme=="http" && !v.AllowPrivateAddress { return "AMIN Agent over HTTP requires an explicitly trusted private management tunnel; otherwise use HTTPS" }
 if v.TlsVerifyMode!="" && v.TlsVerifyMode!="system" && v.TlsVerifyMode!="insecure" && v.TlsVerifyMode!="pinned" { return "invalid tlsVerifyMode" }
 if v.TlsVerifyMode=="pinned" && len(strings.TrimSpace(v.PinnedCertSha256))!=64 { return "pinned TLS mode requires a SHA-256 certificate fingerprint" }
 return ""
}

func (a *NodeController) list(c *gin.Context) {
 var nodes []model.Node
 if err:=nodeDB().Order("id asc").Find(&nodes).Error; err!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":err.Error()}); return }
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":nodes})
}
func (a *NodeController) get(c *gin.Context) {
 id,err:=strconv.Atoi(c.Param("id")); if err!=nil || id<1 { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid node id"}); return }
 var n model.Node
 if err=nodeDB().First(&n,id).Error; err!=nil { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"}); return }
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":n})
}
func nodeFromMutation(v nodeMutation, old model.Node) model.Node {
 old.Name=strings.TrimSpace(v.Name); old.Remark=v.Remark; old.AgentMode=v.AgentMode; old.Scheme=v.Scheme; if old.Scheme=="" {old.Scheme="https"}
 old.Address=strings.TrimSpace(v.Address); old.PublicAddress=strings.TrimSpace(v.PublicAddress); old.Port=v.Port; old.BasePath=strings.TrimSpace(v.BasePath)
 if v.ApiToken!="" {old.ApiToken=v.ApiToken}
 if v.Enable!=nil {old.Enable=*v.Enable} else if old.Id==0 {old.Enable=true}
 old.AllowPrivateAddress=v.AllowPrivateAddress; old.TlsVerifyMode=v.TlsVerifyMode; if old.TlsVerifyMode=="" {old.TlsVerifyMode="system"}
 old.PinnedCertSha256=strings.TrimSpace(v.PinnedCertSha256); old.InboundSyncMode=v.InboundSyncMode; if old.InboundSyncMode=="" {old.InboundSyncMode="all"}
 old.InboundTags=v.InboundTags; old.OutboundTag=v.OutboundTag; old.Guid=v.Guid; old.ParentGuid=v.ParentGuid; old.Transitive=v.Transitive
 return old
}
func (a *NodeController) add(c *gin.Context) {
 var v nodeMutation
 if err:=c.ShouldBind(&v); err!=nil {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid JSON"});return}
 if msg:=validNodeMutation(v,true); msg!="" {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":msg});return}
 n:=nodeFromMutation(v,model.Node{})
 encryptedToken, tokenErr := nodetoken.Encrypt(n.ApiToken)
 if tokenErr != nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":"could not protect node API token: "+tokenErr.Error()}); return }
 n.ApiToken = encryptedToken
 if err:=nodeDB().Create(&n).Error; err!=nil {c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":err.Error()});return}
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":n})
}
func (a *NodeController) update(c *gin.Context) {
 id,err:=strconv.Atoi(c.Param("id")); if err!=nil || id<1 {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid node id"});return}
 var v nodeMutation
 if err=c.ShouldBind(&v); err!=nil {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid JSON"});return}
 if msg:=validNodeMutation(v,false); msg!="" {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":msg});return}
 var n model.Node
 if err=nodeDB().First(&n,id).Error; err!=nil {c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"});return}
 n=nodeFromMutation(v,n)
 encryptedToken, tokenErr := nodetoken.Encrypt(n.ApiToken)
 if tokenErr != nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":"could not protect node API token: "+tokenErr.Error()}); return }
 n.ApiToken = encryptedToken
 if err=nodeDB().Save(&n).Error; err!=nil {c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":err.Error()});return}
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":n})
}
func (a *NodeController) delete(c *gin.Context) {
 id,err:=strconv.Atoi(c.Param("id")); if err!=nil || id<1 {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid node id"});return}
 result:=nodeDB().Delete(&model.Node{},id)
 if result.Error!=nil {c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":result.Error.Error()});return}
 if result.RowsAffected==0 {c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"});return}
 c.JSON(http.StatusOK,gin.H{"success":true})
}
func (a *NodeController) setEnable(c *gin.Context) {
 id,err:=strconv.Atoi(c.Param("id")); if err!=nil || id<1 {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid node id"});return}
 var req struct { Enable bool `form:"enable" json:"enable"` }
 if err=c.ShouldBind(&req); err!=nil {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid JSON"});return}
 result:=nodeDB().Model(&model.Node{}).Where("id = ?",id).Update("enable",req.Enable)
 if result.Error!=nil {c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":result.Error.Error()});return}
 if result.RowsAffected==0 {c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"});return}
 c.JSON(http.StatusOK,gin.H{"success":true})
}

func (a *NodeController) probe(c *gin.Context) {
 id,err:=strconv.Atoi(c.Param("id"))
 if err!=nil || id<1 { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid node id"}); return }
 var n model.Node
 if err=nodeDB().First(&n,id).Error; err!=nil { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"}); return }
 if !n.Enable { c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"node is disabled"}); return }
 result:=make(chan map[string]any,1)
 go func(){result<-job.ProbeNode(n)}()
 var patch map[string]any
 select {
 case patch=<-result:
 case <-c.Request.Context().Done(): return
 case <-time.After(5*time.Second):
  c.JSON(http.StatusGatewayTimeout,gin.H{"success":false,"msg":"node probe timed out"}); return
 }
 if err=nodeDB().Model(&model.Node{}).Where("id = ?",id).Updates(patch).Error; err!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":err.Error()}); return }
 var updated model.Node
 _=nodeDB().First(&updated,id).Error
 websocket.BroadcastNodes([]model.Node{updated})
 ok:=patch["status"]=="online"
 c.JSON(http.StatusOK,gin.H{"success":ok,"obj":updated,"msg":patch["last_error"]})
}

 
// Accepts both JSON and form-encoded payloads from the shared HttpUtil client.
type nodeCreateClientRequest struct {
 InboundID int `form:"inboundId" json:"inboundId"`
 CreateInbound bool `form:"createInbound" json:"createInbound"`
 Port int `form:"port" json:"port"`
 Protocol string `form:"protocol" json:"protocol"`
 Email string `form:"email" json:"email"`
 TotalGB int64 `form:"totalGB" json:"totalGB"`
 Months int `form:"months" json:"months"`
 Days int `form:"days" json:"days"`
 Flow string `form:"flow" json:"flow"`
}

// createClient either provisions on an existing inbound or creates a new listener
// on the user-selected port before adding the client.
func (a *NodeController) createClient(c *gin.Context) {
 id, err := strconv.Atoi(c.Param("id"))
 if err != nil || id < 1 { c.JSON(http.StatusBadRequest, gin.H{"success":false,"msg":"invalid node id"}); return }
 var n model.Node
 if err = nodeDB().First(&n,id).Error; err != nil { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"}); return }
 if !n.Enable { c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"node is disabled"}); return }

 var req nodeCreateClientRequest
 if err = c.ShouldBind(&req); err != nil { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid request"}); return }
 req.Email = strings.ToLower(strings.TrimSpace(req.Email))
 if len(req.Email)<1 || len(req.Email)>64 { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"username must be 1 to 64 characters"}); return }
 for _,r:=range req.Email {
  if !(r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='.'||r=='_'||r=='-') {
   c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"username may contain only letters, numbers, dot, underscore and dash"}); return
  }
 }
 if req.TotalGB<0 || req.TotalGB>1000000 || req.Months<0 || req.Months>120 || req.Days<0 || req.Days>36500 {
  c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid volume or validity"}); return
 }

 var inbound model.NodeInboundSnapshot
 protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
 if req.CreateInbound {
  if !n.AgentMode { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"creating a new inbound with a custom port is currently supported on AMIN Agent nodes"}); return }
  if req.Port<1 || req.Port>65535 { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"port must be between 1 and 65535"}); return }
  if protocol=="" { protocol="vless" }
  if protocol!="vless" && protocol!="vmess" && protocol!="trojan" {
   c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"supported protocols are VLESS, VMess and Trojan"}); return
  }
 } else {
  if req.InboundID<1 { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"select an existing inbound or choose a new custom port"}); return }
  if err=nodeDB().Where("node_id = ? AND remote_id = ?",id,req.InboundID).First(&inbound).Error; err!=nil {
   c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"inbound not found in this node snapshot; refresh the inbound list"}); return
  }
  if !inbound.Enable { c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"selected inbound is disabled"}); return }
  protocol=strings.ToLower(strings.TrimSpace(inbound.Protocol))
 }
 if protocol!="vless" && protocol!="vmess" && protocol!="trojan" {
  c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"client creation currently supports VLESS, VMess and Trojan inbounds"}); return
 }
 if req.Flow!="" && protocol!="vless" { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"flow is only available for VLESS"}); return }

 if n.AgentMode {
  if req.TotalGB!=0 || req.Months!=0 || req.Days!=0 {
   c.JSON(http.StatusNotImplemented,gin.H{"success":false,"msg":"AMIN Node Agent currently does not enforce traffic quotas or expiry; use unlimited volume and no expiry"}); return
  }
  ctx,cancel:=context.WithTimeout(c.Request.Context(),25*time.Second); defer cancel()
  liveInbounds,liveErr:=job.NativeAgentListInbounds(ctx,n)
  if liveErr!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"could not read live Agent inbounds: "+liveErr.Error()}); return }

  if req.CreateInbound {
   for _,live:=range liveInbounds {
    if live.Port==req.Port {
     c.JSON(http.StatusConflict,gin.H{"success":false,"msg":fmt.Sprintf("port %d is already assigned to inbound %q (%s); choose another port or use that existing inbound",req.Port,live.Tag,live.Protocol)}); return
    }
   }
   tag:="amin-ui-"+protocol+"-"+strconv.Itoa(req.Port)+"-"+strings.ReplaceAll(uuid.NewString()[:8],"-","")
   settings:=map[string]any{"clients":[]any{}}
   if protocol=="vless" { settings["decryption"]="none" }
   payload:=map[string]any{
    "tag":tag,
    "port":req.Port,
    "listen":"0.0.0.0",
    "protocol":protocol,
    "settings":settings,
    "streamSettings":map[string]any{"network":"tcp","security":"none"},
   }
   if err=job.NativeAgentCreateInbound(ctx,n,payload); err!=nil {
    c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":err.Error()}); return
   }
   // Never proceed to user creation until the Agent reports the new listener
   // back with the exact tag, protocol and selected port.
   liveInbounds,liveErr=job.NativeAgentListInbounds(ctx,n)
   if liveErr!=nil {
    c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"inbound creation was accepted, but the new inbound could not be verified: "+liveErr.Error()}); return
   }
   found:=false
   for _,live:=range liveInbounds {
    if live.Tag==tag && live.Port==req.Port && strings.EqualFold(live.Protocol,protocol) {
     found=true
     inbound=model.NodeInboundSnapshot{NodeID:id,RemoteID:job.NativeAgentInboundID(tag),Tag:tag,RemoteTag:tag,Remark:tag,Protocol:protocol,Listen:live.Listen,Port:live.Port,Enable:true,ClientCount:0,LastSyncAt:time.Now().UnixMilli()}
     break
    }
   }
   if !found {
    c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":fmt.Sprintf("Agent accepted inbound creation, but port %d is not present in its live inbound list; no user was created",req.Port)}); return
   }
   if err=nodeDB().Create(&inbound).Error; err!=nil {
    c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":"inbound was created on the Agent but could not be saved in the panel snapshot; refresh the node before retrying: "+err.Error()}); return
   }
   req.InboundID=inbound.RemoteID
  } else {
   if inbound.RemoteTag=="" { c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"native inbound tag is missing; refresh the node snapshot"}); return }
   found:=false
   for _,live:=range liveInbounds {
    if live.Tag==inbound.RemoteTag {
     if live.Port!=inbound.Port || !strings.EqualFold(strings.TrimSpace(live.Protocol),protocol) {
      c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"selected inbound changed on AMIN Agent; refresh the inbound list"}); return
     }
     found=true
     break
    }
   }
   if !found { c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"selected inbound no longer exists on AMIN Agent; refresh the inbound list"}); return }
  }

  // Check duplicate usernames against the selected live inbound.
  var liveSelected *job.NativeAgentInbound
  for i:=range liveInbounds { if liveInbounds[i].Tag==inbound.RemoteTag { liveSelected=&liveInbounds[i]; break } }
  if liveSelected==nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"selected inbound disappeared before user creation"}); return }
  var liveSettings struct { Clients []struct { Email string `json:"email"` } `json:"clients"` }
  if len(liveSelected.Settings)>0 {
   if decodeErr:=json.Unmarshal(liveSelected.Settings,&liveSettings); decodeErr!=nil {
    c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"could not read selected inbound clients: "+decodeErr.Error()}); return
   }
  }
  for _,existing:=range liveSettings.Clients {
   if strings.EqualFold(strings.TrimSpace(existing.Email),req.Email) {
    c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"this username already exists on the selected inbound"}); return
   }
  }
  client:=map[string]any{"email":req.Email,"level":0}
  switch protocol { case "vless","vmess": client["id"]=uuid.NewString(); case "trojan","shadowsocks": client["password"]=uuid.NewString() }
  if req.Flow!="" { client["flow"]=req.Flow }
  if err=job.NativeAgentCreateClient(ctx,n,inbound.RemoteTag,client); err!=nil {
   msg:="AMIN Agent rejected client creation: "+err.Error()
   if req.CreateInbound { msg=fmt.Sprintf("Inbound on port %d was created, but user creation failed: %s. The inbound was kept; refresh the list and retry on that inbound.",req.Port,err.Error()) }
   obj:=any(nil)
   if req.CreateInbound { obj=gin.H{"inboundId":req.InboundID,"port":inbound.Port,"tag":inbound.RemoteTag} }
   c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":msg,"obj":obj}); return
  }
  verified:=false
  for attempt:=0;attempt<4;attempt++ {
   var verifyErr error
   verified,verifyErr=job.NativeAgentInboundHasClient(ctx,n,inbound.RemoteTag,req.Email)
   if verifyErr!=nil {
    obj:=any(nil)
    if req.CreateInbound { obj=gin.H{"inboundId":req.InboundID,"port":inbound.Port,"tag":inbound.RemoteTag} }
    c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"Agent accepted the user request, but live Xray verification failed: "+verifyErr.Error(),"obj":obj}); return
   }
   if verified { break }
   if attempt<3 {
    select { case <-ctx.Done():
     obj:=any(nil); if req.CreateInbound { obj=gin.H{"inboundId":req.InboundID,"port":inbound.Port,"tag":inbound.RemoteTag} }
     c.JSON(http.StatusGatewayTimeout,gin.H{"success":false,"msg":"Agent accepted the request, but the user did not appear in Xray before verification timed out","obj":obj}); return
    case <-time.After(200*time.Millisecond): }
   }
  }
  if !verified { obj:=any(nil)
   if req.CreateInbound { obj=gin.H{"inboundId":req.InboundID,"port":inbound.Port,"tag":inbound.RemoteTag} }
   c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"Agent accepted the request, but the username is not present in the selected inbound's live Xray configuration","obj":obj}); return }

  dbErr:=nodeDB().Transaction(func(tx *gorm.DB) error {
   if updateErr:=tx.Model(&model.NodeInboundSnapshot{}).Where("node_id = ? AND remote_id = ?",id,req.InboundID).Updates(map[string]any{"client_count":len(liveSettings.Clients)+1,"last_sync_at":time.Now().UnixMilli()}).Error; updateErr!=nil { return updateErr }
   var snapshot model.NodeClientSnapshot
   findErr:=tx.Where("node_id = ? AND email = ?",id,req.Email).First(&snapshot).Error
   if findErr==gorm.ErrRecordNotFound {
    snapshot=model.NodeClientSnapshot{NodeID:id,Email:req.Email,Enable:true,LastSyncAt:time.Now().UnixMilli()}
    if createErr:=tx.Create(&snapshot).Error; createErr!=nil { return createErr }
   } else if findErr!=nil { return findErr
   } else if updateErr:=tx.Model(&snapshot).Updates(map[string]any{"enable":true,"last_sync_at":time.Now().UnixMilli()}).Error; updateErr!=nil { return updateErr }
   var clientCount int64
   if countErr:=tx.Model(&model.NodeClientSnapshot{}).Where("node_id = ?",id).Count(&clientCount).Error; countErr!=nil { return countErr }
   return tx.Model(&model.Node{}).Where("id = ?",id).Update("client_count",clientCount).Error
  })
  if dbErr!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":"user was created and verified in Xray, but panel snapshot update failed; refresh the node: "+dbErr.Error()}); return }
  credential:=client["id"]; if credential==nil { credential=client["password"] }
  c.JSON(http.StatusOK,gin.H{"success":true,"obj":gin.H{"nodeId":id,"inboundId":req.InboundID,"inbound":inbound.Remark,"protocol":protocol,"port":inbound.Port,"email":req.Email,"id":client["id"],"password":client["password"],"credential":credential}})
  return
 }

 // Sanaei-compatible nodes continue to use their existing inbound and client API.
 if req.CreateInbound { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"custom inbound creation requires an AMIN Agent node"}); return }
 expiry:=int64(0)
 if req.Days>0 { expiry=time.Now().AddDate(0,0,req.Days).UnixMilli() } else if req.Months>0 { expiry=time.Now().AddDate(0,req.Months,0).UnixMilli() }
 payload:=map[string]any{"client":map[string]any{"email":req.Email,"totalGB":req.TotalGB*(1<<30),"expiryTime":expiry,"enable":true,"flow":req.Flow},"inboundIds":[]int{req.InboundID}}
 body,err:=json.Marshal(payload)
 if err!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":"could not encode client request"}); return }
 ctx,cancel:=context.WithTimeout(c.Request.Context(),12*time.Second); defer cancel()
 if _,err=job.CreateNodeClient(ctx,n,body); err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":err.Error()}); return }
 _=nodeDB().Where("node_id = ? AND email = ?",id,req.Email).Delete(&model.NodeClientSnapshot{}).Error
 _=nodeDB().Create(&model.NodeClientSnapshot{NodeID:id,Email:req.Email,Total:req.TotalGB*(1<<30),ExpiryTime:expiry,Enable:true,LastSyncAt:time.Now().UnixMilli()}).Error
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":gin.H{"nodeId":id,"inboundId":req.InboundID,"inbound":inbound.Remark,"protocol":protocol,"email":req.Email,"totalGB":req.TotalGB*(1<<30),"expiryTime":expiry}})
}

// snapshot returns the last successfully synchronized, credential-free view of a node.
func (a *NodeController) snapshot(c *gin.Context) {
 id, err := strconv.Atoi(c.Param("id"))
 if err != nil || id < 1 {
  c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid node id"})
  return
 }
 var node model.Node
 if err = nodeDB().First(&node, id).Error; err != nil {
  c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "node not found"})
  return
 }
 var inbounds []model.NodeInboundSnapshot
 if err = nodeDB().Where("node_id = ?", id).Order("remote_id asc").Find(&inbounds).Error; err != nil {
  c.JSON(http.StatusInternalServerError, gin.H{"success": false, "msg": err.Error()})
  return
 }
 var clients []model.NodeClientSnapshot
 if err = nodeDB().Where("node_id = ?", id).Order("email asc").Find(&clients).Error; err != nil {
  c.JSON(http.StatusInternalServerError, gin.H{"success": false, "msg": err.Error()})
  return
 }
 c.JSON(http.StatusOK, gin.H{"success": true, "obj": gin.H{
  "nodeId": id, "lastSyncAt": node.LastSyncAt, "lastSyncError": node.LastSyncError,
  "inbounds": inbounds, "clients": clients,
 }})
}


type nodeClientMutation struct {
 TotalBytes int64 `json:"totalBytes"`
 ExpiryTime int64 `json:"expiryTime"`
 Enable bool `json:"enable"`
 ID string `json:"id"`
 Password string `json:"password"`
 Flow *string `json:"flow"`
 Security string `json:"security"`
 Level *int `json:"level"`
 AlterID *int `json:"alterId"`
}

func (a *NodeController) listNodeClients(c *gin.Context) {
 type row struct {
  model.NodeClientSnapshot
  NodeName string `json:"nodeName"`
  NodeAddress string `json:"nodeAddress"`
  NodeStatus string `json:"nodeStatus"`
  AgentMode bool `json:"agentMode"`
 }
 var snapshots []model.NodeClientSnapshot
 if err := nodeDB().Order("node_id asc, email asc").Find(&snapshots).Error; err != nil {
  c.JSON(http.StatusInternalServerError, gin.H{"success":false,"msg":err.Error()}); return
 }
 nodes := map[int]model.Node{}
 var all []model.Node
 if err := nodeDB().Find(&all).Error; err != nil {
  c.JSON(http.StatusInternalServerError, gin.H{"success":false,"msg":err.Error()}); return
 }
 for _, n := range all { nodes[n.Id] = n }
 rows := make([]row,0,len(snapshots))
 for _, s := range snapshots {
  n, ok := nodes[s.NodeID]; if !ok { continue }
  displayAddress:=n.Address; if n.AgentMode && strings.TrimSpace(n.PublicAddress)!="" { displayAddress=n.PublicAddress }
  rows = append(rows,row{NodeClientSnapshot:s,NodeName:n.Name,NodeAddress:displayAddress,NodeStatus:n.Status,AgentMode:n.AgentMode})
 }
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":rows})
}

func (a *NodeController) loadManageableNode(c *gin.Context) (model.Node, bool) {
 id, err := strconv.Atoi(c.Param("id"))
 if err != nil || id < 1 { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid node id"}); return model.Node{},false }
 var n model.Node
 if err = nodeDB().First(&n,id).Error; err != nil { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"}); return model.Node{},false }
 if !n.Enable { c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"node is disabled"}); return model.Node{},false }
 return n,true
}

func validRemoteEmail(email string) bool {
 email = strings.TrimSpace(email)
 if len(email)<1 || len(email)>64 { return false }
 for _, r := range email {
  if !(r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='.'||r=='_'||r=='-') { return false }
 }
 return true
}

func (a *NodeController) updateNodeClient(c *gin.Context) {
 n,ok:=a.loadManageableNode(c); if !ok { return }
 if n.AgentMode {
  email:=strings.ToLower(strings.TrimSpace(c.Param("email")))
  if !validRemoteEmail(email) { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid username"}); return }
  var exists model.NodeClientSnapshot
  if err:=nodeDB().Where("node_id = ? AND email = ?",n.Id,email).First(&exists).Error; err!=nil { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"client not found in this node"}); return }
  var req nodeClientMutation
  if err:=c.ShouldBindJSON(&req); err!=nil { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid client update"}); return }
  if req.TotalBytes!=0 || req.ExpiryTime!=0 {
   c.JSON(http.StatusNotImplemented,gin.H{"success":false,"msg":"AMIN Node Agent does not yet enforce traffic quota or expiry; those fields were not changed"}); return
  }
  patch:=map[string]any{}
  if strings.TrimSpace(req.ID)!="" { patch["id"]=strings.TrimSpace(req.ID) }
  if strings.TrimSpace(req.Password)!="" { patch["password"]=strings.TrimSpace(req.Password) }
  if req.Flow!=nil { patch["flow"]=*req.Flow }
  if req.Security!="" { patch["security"]=req.Security }
  if req.Level!=nil { patch["level"]=*req.Level }
  if req.AlterID!=nil { patch["alterId"]=*req.AlterID }
  if len(patch)==0 {
   c.JSON(http.StatusNotImplemented,gin.H{"success":false,"msg":"For AMIN Agent clients, provide at least one supported field: id, password, flow, security, level or alterId. Quota, expiry and enable toggles are not supported."}); return
  }
  ctx,cancel:=context.WithTimeout(c.Request.Context(),20*time.Second); defer cancel()
  inbounds,err:=job.NativeAgentListInbounds(ctx,n)
  if err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":err.Error()}); return }
  matched:=false
  for _,ib:=range inbounds {
   var settings struct { Clients []struct { Email string `json:"email"` } `json:"clients"` }
   if len(ib.Settings)>0 { if e:=json.Unmarshal(ib.Settings,&settings); e!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"invalid client settings from native inbound "+ib.Tag}); return } }
   for _,cl:=range settings.Clients { if strings.EqualFold(strings.TrimSpace(cl.Email),email) {
    if err=job.NativeAgentUpdateClient(ctx,n,ib.Tag,email,patch); err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"client update failed on inbound "+ib.Tag+": "+err.Error()}); return }
    matched=true
   } }
  }
  if !matched { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"client not found on this native node"}); return }
  _=nodeDB().Model(&model.NodeClientSnapshot{}).Where("node_id = ? AND email = ?",n.Id,email).Update("last_sync_at",time.Now().UnixMilli()).Error
  c.JSON(http.StatusOK,gin.H{"success":true,"msg":"supported client fields updated on AMIN Agent"})
  return
 }
 email:=strings.ToLower(strings.TrimSpace(c.Param("email")))
 if !validRemoteEmail(email) { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid username"}); return }
 var exists model.NodeClientSnapshot
 if err:=nodeDB().Where("node_id = ? AND email = ?",n.Id,email).First(&exists).Error; err!=nil { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"client not found in this node"}); return }
 var req nodeClientMutation
 if err:=c.ShouldBindJSON(&req); err!=nil || req.TotalBytes<0 || req.TotalBytes>1000000*(1<<30) { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid quota, expiry or enable value"}); return }
 ctx,cancel:=context.WithTimeout(c.Request.Context(),12*time.Second); defer cancel()
 // The upstream update handler replaces the client record. Fetch the full record
 // first so fields not edited here (UUID/password, flow, limits, comments, etc.)
 // are preserved instead of silently reset by a partial payload.
 raw,err:=job.ManageNodeClient(ctx,n,http.MethodGet,"panel/api/clients/get/"+url.PathEscape(email),nil)
 if err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"could not read remote client before update: "+err.Error()}); return }
 var payloadMap map[string]any
 if err=json.Unmarshal(raw,&payloadMap); err!=nil || payloadMap==nil {
  c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"remote client details have an unexpected format"}); return
 }
 if nested,ok:=payloadMap["client"].(map[string]any); ok { payloadMap=nested }
 if strings.ToLower(strings.TrimSpace(fmt.Sprint(payloadMap["email"])))!=email {
  c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"remote client details did not match the requested username"}); return
 }
 payloadMap["totalGB"]=req.TotalBytes
 payloadMap["expiryTime"]=req.ExpiryTime
 payloadMap["enable"]=req.Enable
 payload,err:=json.Marshal(payloadMap)
 if err!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":"could not encode complete client update"}); return }
 if _,err=job.ManageNodeClient(ctx,n,http.MethodPost,"panel/api/clients/update/"+url.PathEscape(email),payload); err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":err.Error()}); return }
 if err=nodeDB().Model(&model.NodeClientSnapshot{}).Where("node_id = ? AND email = ?",n.Id,email).Updates(map[string]any{"total":req.TotalBytes,"expiry_time":req.ExpiryTime,"enable":req.Enable,"last_sync_at":time.Now().UnixMilli()}).Error; err!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":"remote client updated but local snapshot refresh failed: "+err.Error()}); return }
 c.JSON(http.StatusOK,gin.H{"success":true})
}

func (a *NodeController) deleteNodeClient(c *gin.Context) {
 n,ok:=a.loadManageableNode(c); if !ok { return }
 if n.AgentMode {
  email:=strings.ToLower(strings.TrimSpace(c.Param("email")))
  if !validRemoteEmail(email) { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid username"}); return }
  ctx,cancel:=context.WithTimeout(c.Request.Context(),20*time.Second); defer cancel()
  inbounds,err:=job.NativeAgentListInbounds(ctx,n)
  if err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":err.Error()}); return }
  tags:=make([]string,0)
  for _,ib:=range inbounds {
   var settings struct { Clients []struct { Email string `json:"email"` } `json:"clients"` }
   if len(ib.Settings)>0 { if e:=json.Unmarshal(ib.Settings,&settings); e!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"invalid client settings from native inbound "+ib.Tag}); return } }
   for _,cl:=range settings.Clients { if strings.EqualFold(strings.TrimSpace(cl.Email),email) { tags=append(tags,ib.Tag); break } }
  }
  if len(tags)==0 { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"client not found on this native node"}); return }
  for _,tag:=range tags {
   if err=job.NativeAgentDeleteClient(ctx,n,tag,email); err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"client deletion partially failed on inbound "+tag+": "+err.Error()}); return }
  }
  _=nodeDB().Where("node_id = ? AND email = ?",n.Id,email).Delete(&model.NodeClientSnapshot{}).Error
  c.JSON(http.StatusOK,gin.H{"success":true,"obj":gin.H{"deletedFrom":tags}})
  return
 }
 email:=strings.TrimSpace(c.Param("email"))
 if !validRemoteEmail(email) { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid username"}); return }
 var exists model.NodeClientSnapshot
 if err:=nodeDB().Where("node_id = ? AND email = ?",n.Id,email).First(&exists).Error; err!=nil { c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"client not found in this node"}); return }
 ctx,cancel:=context.WithTimeout(c.Request.Context(),12*time.Second); defer cancel()
 if _,err:=job.ManageNodeClient(ctx,n,http.MethodPost,"panel/api/clients/del/"+url.PathEscape(email)+"?keepTraffic=0",[]byte("{}")); err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":err.Error()}); return }
 _=nodeDB().Where("node_id = ? AND email = ?",n.Id,email).Delete(&model.NodeClientSnapshot{}).Error
 c.JSON(http.StatusOK,gin.H{"success":true})
}



// Sanaei versions differ in whether API data is returned directly or wrapped in
// the standard {success, msg, obj} envelope. Normalize both forms here.
func decodeNodeRemoteClient(raw []byte) (map[string]any, error) {
 var root map[string]any
 if err := json.Unmarshal(raw, &root); err != nil { return nil, err }
 if ok, exists := root["success"].(bool); exists && !ok {
  return nil, fmt.Errorf("%v", root["msg"])
 }
 for _, key := range []string{"obj", "client", "data"} {
  if nested, ok := root[key].(map[string]any); ok {
   if inner, ok := nested["client"].(map[string]any); ok { return inner, nil }
   return nested, nil
  }
 }
 return root, nil
}

func decodeNodeRemoteInbounds(raw []byte) ([]map[string]any, error) {
 var direct []map[string]any
 if err := json.Unmarshal(raw, &direct); err == nil && direct != nil { return direct, nil }
 var root map[string]any
 if err := json.Unmarshal(raw, &root); err != nil { return nil, err }
 if ok, exists := root["success"].(bool); exists && !ok {
  return nil, fmt.Errorf("%v", root["msg"])
 }
 for _, key := range []string{"obj", "inbounds", "data"} {
  value, exists := root[key]
  if !exists { continue }
  if nested, ok := value.(map[string]any); ok {
   for _, innerKey := range []string{"inbounds", "obj", "list"} {
    if arr, ok := nested[innerKey].([]any); ok { value = arr; break }
   }
  }
  if arr, ok := value.([]any); ok {
   out := make([]map[string]any, 0, len(arr))
   for _, item := range arr { if m, ok := item.(map[string]any); ok { out = append(out, m) } }
   return out, nil
  }
 }
 return nil, fmt.Errorf("inbound array not found in API response")
}


func nativeString(m map[string]any,key string) string {
 v:=strings.TrimSpace(fmt.Sprint(m[key]))
 if v=="<nil>" { return "" }
 return v
}

func nativeFirstString(value any) string {
 switch values:=value.(type) {
 case []any:
  for _,item:=range values {
   if candidate,ok:=item.(string);ok && strings.TrimSpace(candidate)!="" { return strings.TrimSpace(candidate) }
  }
 case []string:
  for _,candidate:=range values { if strings.TrimSpace(candidate)!="" { return strings.TrimSpace(candidate) } }
 }
 return ""
}

func nativeFirstStringIncludingEmpty(value any) (string,bool) {
 switch values:=value.(type) {
 case []any:
  if len(values)>0 { candidate,ok:=values[0].(string); return strings.TrimSpace(candidate),ok }
 case []string:
  if len(values)>0 { return strings.TrimSpace(values[0]),true }
 }
 return "",false
}

// realityPublicKey derives the client-facing X25519 public key from the
// privateKey stored in a normal Xray server-side Reality configuration.
// Xray encodes Reality keys using unpadded URL-safe base64.
func realityPublicKey(privateKey string) (string,error) {
 privateKey=strings.TrimSpace(privateKey)
 if privateKey=="" { return "",fmt.Errorf("Reality privateKey در تنظیمات زنده Xray وجود ندارد") }
 var keyBytes []byte
 var err error
 for _,encoding:=range []*base64.Encoding{base64.RawURLEncoding,base64.URLEncoding,base64.RawStdEncoding,base64.StdEncoding} {
  keyBytes,err=encoding.DecodeString(privateKey)
  if err==nil { break }
 }
 if err!=nil { return "",fmt.Errorf("Reality privateKey قالب Base64 معتبر ندارد: %w",err) }
 if len(keyBytes)!=32 { return "",fmt.Errorf("طول Reality privateKey نامعتبر است؛ انتظار ۳۲ بایت می‌رفت و %d بایت دریافت شد",len(keyBytes)) }
 private,err:=ecdh.X25519().NewPrivateKey(keyBytes)
 if err!=nil { return "",fmt.Errorf("ساخت کلید X25519 از Reality privateKey ناموفق بود: %w",err) }
 return base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()),nil
}

// buildNativeAgentShareLink builds a client URI from the live Xray config.
// The management address is deliberately never used: Agent nodes have a separate
// public endpoint because their control API commonly runs behind a loopback tunnel.
func buildNativeAgentShareLink(publicHost,nodeName string,ib job.NativeAgentInbound,client map[string]any,email string)(string,string,string,error) {
 protocol:=strings.ToLower(strings.TrimSpace(ib.Protocol))
 credential:=nativeString(client,"id")
 if credential=="" { credential=nativeString(client,"password") }
 if credential=="" { return "","","",fmt.Errorf("شناسه یا رمز واقعی کاربر در تنظیمات Xray وجود ندارد") }
 if ib.Port<1 || ib.Port>65535 { return "","","",fmt.Errorf("پورت Inbound نامعتبر است") }
 host:=strings.TrimSpace(publicHost)
 if strings.HasPrefix(host,"[") && strings.HasSuffix(host,"]") { host=host[1:len(host)-1] }
 if !validNodeHost(host) { return "","","",fmt.Errorf("آدرس عمومی اتصال نامعتبر است") }
 stream:=map[string]any{}
 if len(ib.StreamSettings)>0 { if err:=json.Unmarshal(ib.StreamSettings,&stream); err!=nil { return "","","",fmt.Errorf("خواندن StreamSettings ناموفق بود: %w",err) } }
 network:=nativeString(stream,"network"); if network=="" { network="tcp" }
 security:=nativeString(stream,"security"); if security=="" { security="none" }
 q:=url.Values{"type":{network},"security":{security}}
 if protocol=="vless" {
  q.Set("encryption","none")
  if flow:=nativeString(client,"flow"); flow!="" { q.Set("flow",flow) }
 }
 if security=="tls" || security=="reality" {
  key:="tlsSettings"; if security=="reality" { key="realitySettings" }
  cfg,_:=stream[key].(map[string]any)
  for source,target:=range map[string]string{"serverName":"sni","fingerprint":"fp"} {
   if value:=nativeString(cfg,source); value!="" { q.Set(target,value) }
  }
  if alpn,ok:=cfg["alpn"].([]any);ok && len(alpn)>0 { vals:=make([]string,0,len(alpn)); for _,v:=range alpn { vals=append(vals,fmt.Sprint(v)) }; q.Set("alpn",strings.Join(vals,",")) }
  if security=="reality" {
   settings,_:=cfg["settings"].(map[string]any)
   // Reality server configs normally contain privateKey/serverNames/shortIds;
   // client share links require the derived public key and one advertised SNI/shortId.
   publicKey:=nativeString(settings,"publicKey")
   if publicKey=="" {
    var deriveErr error
    publicKey,deriveErr=realityPublicKey(nativeString(cfg,"privateKey"))
    if deriveErr!=nil { return "","","",deriveErr }
   }
   q.Set("pbk",publicKey)
   if sni:=nativeString(settings,"serverName"); sni!="" { q.Set("sni",sni) } else if sni:=nativeFirstString(cfg["serverNames"]); sni!="" { q.Set("sni",sni) }
   if fp:=nativeString(settings,"fingerprint"); fp!="" { q.Set("fp",fp) } else if q.Get("fp")=="" { q.Set("fp","chrome") }
   shortID:=nativeString(settings,"shortId")
   if shortID!="" { q.Set("sid",shortID) } else if shortID,ok:=nativeFirstStringIncludingEmpty(cfg["shortIds"]); ok { q.Set("sid",shortID) }
   if spiderX:=nativeString(settings,"spiderX"); spiderX!="" { q.Set("spx",spiderX) }
   if q.Get("sni")=="" { return "","","",fmt.Errorf("هیچ serverName معتبری در Reality تنظیم نشده است") }
   if _,exists:=q["sid"]; !exists { return "","","",fmt.Errorf("هیچ shortId معتبری در Reality تنظیم نشده است") }
  }
 }
 switch network {
 case "ws":
  cfg,_:=stream["wsSettings"].(map[string]any)
  if p:=nativeString(cfg,"path");p!="" { q.Set("path",p) }
  headers,_:=cfg["headers"].(map[string]any); if h:=nativeString(headers,"Host");h!="" { q.Set("host",h) }
 case "grpc":
  cfg,_:=stream["grpcSettings"].(map[string]any)
  if v:=nativeString(cfg,"serviceName");v!="" { q.Set("serviceName",v) }
  if v:=nativeString(cfg,"authority");v!="" { q.Set("authority",v) }
 case "httpupgrade":
  cfg,_:=stream["httpupgradeSettings"].(map[string]any)
  if v:=nativeString(cfg,"path");v!="" { q.Set("path",v) }
  if v:=nativeString(cfg,"host");v!="" { q.Set("host",v) }
 }
 remark:=strings.TrimSpace(ib.Tag); if remark=="" { remark=nodeName }
 label:=url.QueryEscape(remark+"-"+email)
 switch protocol {
 case "vless","trojan":
  return fmt.Sprintf("%s://%s@%s?%s#%s",protocol,url.QueryEscape(credential),net.JoinHostPort(host,strconv.Itoa(ib.Port)),q.Encode(),label),protocol,remark,nil
 case "shadowsocks":
  var inboundSettings map[string]any
  if len(ib.Settings)==0 || json.Unmarshal(ib.Settings,&inboundSettings)!=nil {
   return "","","",fmt.Errorf("خواندن تنظیمات Shadowsocks ناموفق بود")
  }
  method:=nativeString(inboundSettings,"method")
  if method=="" { return "","","",fmt.Errorf("روش رمزنگاری Shadowsocks در تنظیمات Inbound مشخص نشده است") }
  userInfo:=base64.RawURLEncoding.EncodeToString([]byte(method+":"+credential))
  return fmt.Sprintf("ss://%s@%s#%s",userInfo,net.JoinHostPort(host,strconv.Itoa(ib.Port)),label),"shadowsocks",remark,nil
 case "vmess":
  tlsValue:=""; if security=="tls" { tlsValue="tls" }
  wsPath,wsHost:=q.Get("path"),q.Get("host")
  payload:=map[string]any{"v":"2","ps":remark+"-"+email,"add":host,"port":strconv.Itoa(ib.Port),"id":credential,"aid":fmt.Sprint(client["alterId"]),"scy":"auto","net":network,"type":"none","host":wsHost,"path":wsPath,"tls":tlsValue,"sni":q.Get("sni")}
  raw,err:=json.Marshal(payload); if err!=nil { return "","","",err }
  return "vmess://"+base64.RawStdEncoding.EncodeToString(raw),protocol,remark,nil
 default:
  return "","","",fmt.Errorf("تولید لینک برای پروتکل %s پشتیبانی نشده است",protocol)
 }
}


// nativeShareQRCode returns a locally generated QR image. Credentials are never
// sent to an external QR service.
func nativeShareQRCode(link string) (string,error) {
 png,err:=qrcode.Encode(link,qrcode.Medium,256)
 if err!=nil { return "",fmt.Errorf("ساخت QR کانفیگ ناموفق بود: %w",err) }
 return "data:image/png;base64,"+base64.StdEncoding.EncodeToString(png),nil
}

// nodeClientConfig fetches live Sanaei credentials and builds a share URI without
// persisting UUIDs/passwords in the local database.
func (a *NodeController) nodeClientConfig(c *gin.Context) {
 n, ok := a.loadManageableNode(c)
 if !ok { return }
 if n.AgentMode {
  email:=strings.ToLower(strings.TrimSpace(c.Param("email")))
  if !validRemoteEmail(email) { c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid username"}); return }
  if strings.TrimSpace(n.PublicAddress)=="" {
   c.JSON(http.StatusPreconditionFailed,gin.H{"success":false,"msg":"برای تولید کانفیگ، آدرس عمومی سرور را در ویرایش نود و فیلد «آدرس عمومی اتصال» وارد کنید؛ آدرس 127.0.0.1:18787 فقط تونل مدیریتی است و نباید داخل کانفیگ کاربر قرار بگیرد."}); return
  }
  ctx,cancel:=context.WithTimeout(c.Request.Context(),15*time.Second); defer cancel()
  inbounds,err:=job.NativeAgentListInbounds(ctx,n)
  if err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"دریافت Inboundهای زنده Agent ناموفق بود: "+err.Error()}); return }
  for _,ib:=range inbounds {
   var settings struct { Clients []map[string]any `json:"clients"` }
   if len(ib.Settings)>0 {
    if err=json.Unmarshal(ib.Settings,&settings); err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"ساختار تنظیمات Inbound نامعتبر است: "+err.Error()}); return }
   }
   for _,client:=range settings.Clients {
    if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(client["email"])),email) { continue }
    link,protocol,remark,linkErr:=buildNativeAgentShareLink(n.PublicAddress,n.Name,ib,client,email)
    if linkErr!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":linkErr.Error()}); return }
    qr,qrErr:=nativeShareQRCode(link)
    if qrErr!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":qrErr.Error()}); return }
    c.JSON(http.StatusOK,gin.H{"success":true,"obj":gin.H{"email":email,"nodeName":n.Name,"inbound":remark,"protocol":protocol,"port":ib.Port,"link":link,"qrCode":qr}})
    return
   }
  }
  c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"کاربر در هیچ‌یک از Inboundهای زنده Agent پیدا نشد؛ ابتدا فهرست نود را بروزرسانی کنید."})
  return
 }
 email := strings.ToLower(strings.TrimSpace(c.Param("email")))
 if !validRemoteEmail(email) { c.JSON(http.StatusBadRequest, gin.H{"success":false,"msg":"invalid username"}); return }
 var snapshot model.NodeClientSnapshot
 if err := nodeDB().Where("node_id = ? AND email = ?", n.Id, email).First(&snapshot).Error; err != nil {
  c.JSON(http.StatusNotFound, gin.H{"success":false,"msg":"client not found in this node"}); return
 }
 ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second); defer cancel()
 rawClient, err := job.ManageNodeClient(ctx, n, http.MethodGet, "panel/api/clients/get/"+url.PathEscape(email), nil)
 if err != nil { c.JSON(http.StatusBadGateway, gin.H{"success":false,"msg":"دریافت اطلاعات زنده کاربر از سنایی ناموفق بود: "+err.Error()}); return }
 client, err := decodeNodeRemoteClient(rawClient)
 if err != nil { c.JSON(http.StatusBadGateway, gin.H{"success":false,"msg":"ساختار پاسخ کاربر سنایی نامعتبر است: "+err.Error()}); return }
 if strings.ToLower(strings.TrimSpace(fmt.Sprint(client["email"]))) != email { c.JSON(http.StatusBadGateway, gin.H{"success":false,"msg":"پاسخ سنایی شامل اطلاعات همین کاربر نیست"}); return }
 rawInbounds, err := job.ManageNodeClient(ctx, n, http.MethodGet, "panel/api/inbounds/list", nil)
 if err != nil { c.JSON(http.StatusBadGateway, gin.H{"success":false,"msg":"دریافت تنظیمات Inbound ناموفق بود: "+err.Error()}); return }
 inbounds, err := decodeNodeRemoteInbounds(rawInbounds)
 if err != nil { c.JSON(http.StatusBadGateway, gin.H{"success":false,"msg":"ساختار فهرست Inbound سنایی نامعتبر است: "+err.Error()}); return }
 var chosen map[string]any
 // Prefer explicit inboundIds returned by the remote client API.
 ids, _ := client["inboundIds"].([]any)
 for _, v := range ids {
  target, _ := strconv.Atoi(fmt.Sprint(v))
  for _, ib := range inbounds { iid,_:=strconv.Atoi(fmt.Sprint(ib["id"])); if iid==target { chosen=ib; break } }
  if chosen!=nil { break }
 }
 // Otherwise match the email inside each inbound's actual settings.clients.
 if chosen == nil {
  for _, ib := range inbounds {
   rawSettings := ib["settings"]
   var settings map[string]any
   switch value := rawSettings.(type) {
   case string: _ = json.Unmarshal([]byte(value), &settings)
   case map[string]any: settings = value
   }
   clients, _ := settings["clients"].([]any)
   for _, item := range clients { if cm,ok:=item.(map[string]any);ok && strings.EqualFold(strings.TrimSpace(fmt.Sprint(cm["email"])),email) { chosen=ib; for k,v:=range cm { current:=strings.TrimSpace(fmt.Sprint(client[k])); if client[k]==nil || current=="" || current=="<nil>" { client[k]=v } }; break } }
   if chosen!=nil { break }
  }
 }
 if chosen == nil { c.JSON(http.StatusNotFound, gin.H{"success":false,"msg":"Inbound متناظر این کاربر در تنظیمات واقعی سنایی پیدا نشد"}); return }
 if chosen == nil { c.JSON(http.StatusNotFound, gin.H{"success":false,"msg":"Inbound متناظر کاربر در نود پیدا نشد"}); return }
 protocol := strings.ToLower(strings.TrimSpace(fmt.Sprint(chosen["protocol"])))
 credential := strings.TrimSpace(fmt.Sprint(client["id"]))
 if credential == "" || credential == "<nil>" { credential = strings.TrimSpace(fmt.Sprint(client["password"])) }
 if credential == "" || credential == "<nil>" { c.JSON(http.StatusBadGateway, gin.H{"success":false,"msg":"شناسه یا رمز واقعی کاربر در پاسخ سنایی موجود نیست"}); return }
 port := int(0); if f,ok:=chosen["port"].(float64);ok { port=int(f) }; if port<1 || port>65535 { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"پورت Inbound نامعتبر است"}); return }
 host := strings.TrimSpace(n.Address)
 if strings.Contains(host, ":") && !strings.HasPrefix(host,"[") { host="["+host+"]" }
 stream, _ := chosen["streamSettings"].(map[string]any)
 network := strings.TrimSpace(fmt.Sprint(stream["network"])); if network=="" || network=="<nil>" { network="tcp" }
 security := strings.TrimSpace(fmt.Sprint(stream["security"])); if security=="" || security=="<nil>" { security="none" }
 q := url.Values{"type":{network},"security":{security}}
 if protocol=="vless" { q.Set("encryption","none"); if flow:=strings.TrimSpace(fmt.Sprint(client["flow"])); flow!="" && flow!="<nil>" { q.Set("flow",flow) } }
 if security=="tls" || security=="reality" {
  key := "tlsSettings"; if security=="reality" { key="realitySettings" }
  tlsCfg,_:=stream[key].(map[string]any)
  for source,target:=range map[string]string{"serverName":"sni","fingerprint":"fp","alpn":"alpn"} {
   if val:=strings.TrimSpace(fmt.Sprint(tlsCfg[source])); val!="" && val!="<nil>" { q.Set(target,val) }
  }
  if security=="reality" {
   settings,_:=tlsCfg["settings"].(map[string]any)
   publicKey:=nativeString(settings,"publicKey")
   if publicKey=="" {
    var keyErr error
    publicKey,keyErr=realityPublicKey(nativeString(tlsCfg,"privateKey"))
    if keyErr!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":keyErr.Error()}); return }
   }
   q.Set("pbk",publicKey)
   shortID:=nativeString(settings,"shortId")
   if shortID!="" { q.Set("sid",shortID) } else if shortID,ok:=nativeFirstStringIncludingEmpty(tlsCfg["shortIds"]); ok { q.Set("sid",shortID) }
   if spiderX:=nativeString(settings,"spiderX"); spiderX!="" { q.Set("spx",spiderX) }
   if q.Get("sni")=="" {
    if sni:=nativeString(settings,"serverName"); sni!="" { q.Set("sni",sni) } else if sni:=nativeFirstString(tlsCfg["serverNames"]); sni!="" { q.Set("sni",sni) }
   }
   if q.Get("sni")=="" { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"هیچ serverName معتبری در Reality تنظیم نشده است"}); return }
   if _,exists:=q["sid"]; !exists { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"هیچ shortId معتبری در Reality تنظیم نشده است"}); return }
  }
 }
 switch network {
 case "ws":
  cfg,_:=stream["wsSettings"].(map[string]any); if p:=fmt.Sprint(cfg["path"]);p!=""&&p!="<nil>" {q.Set("path",p)}
  headers,_:=cfg["headers"].(map[string]any); if h:=fmt.Sprint(headers["Host"]);h!=""&&h!="<nil>" {q.Set("host",h)}
 case "grpc":
  cfg,_:=stream["grpcSettings"].(map[string]any); if s:=fmt.Sprint(cfg["serviceName"]);s!=""&&s!="<nil>" {q.Set("serviceName",s)}
  if a:=fmt.Sprint(cfg["authority"]);a!=""&&a!="<nil>" {q.Set("authority",a)}
 case "httpupgrade":
  cfg,_:=stream["httpupgradeSettings"].(map[string]any); if p:=fmt.Sprint(cfg["path"]);p!=""&&p!="<nil>" {q.Set("path",p)}
  if h:=fmt.Sprint(cfg["host"]);h!=""&&h!="<nil>" {q.Set("host",h)}
 }
 remark:=strings.TrimSpace(fmt.Sprint(chosen["remark"])); if remark==""||remark=="<nil>" {remark=n.Name}
 label:=url.QueryEscape(remark+"-"+email)
 var link string
 switch protocol {
 case "vless","trojan":
  scheme:=protocol
  link=fmt.Sprintf("%s://%s@%s:%d?%s#%s",scheme,url.QueryEscape(credential),host,port,q.Encode(),label)
 case "vmess":
  tlsCfg:=""; if security=="tls" {tlsCfg="tls"}
  wsPath:=q.Get("path"); wsHost:=q.Get("host")
  payload:=map[string]any{"v":"2","ps":remark+"-"+email,"add":n.Address,"port":strconv.Itoa(port),"id":credential,"aid":fmt.Sprint(client["alterId"]),"scy":"auto","net":network,"type":"none","host":wsHost,"path":wsPath,"tls":tlsCfg,"sni":q.Get("sni")}
  b,_:=json.Marshal(payload); link="vmess://"+base64.RawStdEncoding.EncodeToString(b)
 default:
  c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"تولید لینک برای پروتکل "+protocol+" پشتیبانی نشده است"}); return
 }
 qr,qrErr:=nativeShareQRCode(link)
 if qrErr!=nil { c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":qrErr.Error()}); return }
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":gin.H{"email":email,"nodeName":n.Name,"inbound":remark,"protocol":protocol,"link":link,"qrCode":qr}})
}
