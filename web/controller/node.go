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


 "github.com/google/uuid"
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

func validNodeMutation(v nodeMutation, creating bool) string {
 if strings.TrimSpace(v.Name)=="" { return "name is required" }
 if strings.TrimSpace(v.Address)=="" { return "address is required" }
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
 old.Address=strings.TrimSpace(v.Address); old.Port=v.Port; old.BasePath=strings.TrimSpace(v.BasePath)
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
 Email string `form:"email" json:"email"`
 TotalGB int64 `form:"totalGB" json:"totalGB"`
 Months int `form:"months" json:"months"`
 Days int `form:"days" json:"days"`
 Flow string `form:"flow" json:"flow"`
}

// createClient provisions a client directly on the selected remote inbound.
func (a *NodeController) createClient(c *gin.Context) {
 id, err := strconv.Atoi(c.Param("id"))
 if err != nil || id < 1 {
  c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid node id"})
  return
 }
 var n model.Node
 if err = nodeDB().First(&n, id).Error; err != nil {
  c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "node not found"})
  return
 }
 if !n.Enable {
  c.JSON(http.StatusConflict, gin.H{"success": false, "msg": "node is disabled"})
  return
 }
 var req nodeCreateClientRequest
 if err = c.ShouldBind(&req); err != nil {
  c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid request"})
  return
 }
 req.Email = strings.ToLower(strings.TrimSpace(req.Email))
 if len(req.Email) < 1 || len(req.Email) > 64 {
  c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "username must be 1 to 64 characters"})
  return
 }
 for _, r := range req.Email {
  if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
   c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "username may contain only letters, numbers, dot, underscore and dash"})
   return
  }
 }
 if req.InboundID < 1 || req.TotalGB < 0 || req.TotalGB > 1000000 || req.Months < 0 || req.Months > 120 || req.Days < 0 || req.Days > 36500 {
  c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid inbound, volume or validity"})
  return
 }
 var inbound model.NodeInboundSnapshot
 if err = nodeDB().Where("node_id = ? AND remote_id = ?", id, req.InboundID).First(&inbound).Error; err != nil {
  c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "inbound not found in this node snapshot; wait for synchronization"})
  return
 }
 if !inbound.Enable {
  c.JSON(http.StatusConflict, gin.H{"success": false, "msg": "selected inbound is disabled"})
  return
 }
 protocol := strings.ToLower(strings.TrimSpace(inbound.Protocol))
 if protocol != "vless" && protocol != "vmess" && protocol != "trojan" {
  c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "client creation currently supports VLESS, VMess and Trojan inbounds"})
  return
 }
 if req.Flow != "" && protocol != "vless" {
  c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "flow is only available for VLESS"})
  return
 }
 if n.AgentMode {
  if req.TotalGB != 0 || req.Months != 0 || req.Days != 0 {
   c.JSON(http.StatusNotImplemented, gin.H{"success":false,"msg":"AMIN Node Agent 0.2.1 does not yet enforce traffic quotas or expiry; use unlimited volume and no expiry for this node"})
   return
  }
  if inbound.RemoteTag=="" { c.JSON(http.StatusConflict,gin.H{"success":false,"msg":"native inbound tag is not synchronized yet; refresh the node snapshot"}); return }
  client:=map[string]any{"email":req.Email,"level":0}
  switch protocol {
  case "vless","vmess": client["id"]=uuid.NewString()
  case "trojan": client["password"]=uuid.NewString()
  default: c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"native Agent client creation supports VLESS, VMess and Trojan"}); return
  }
  if req.Flow!="" { client["flow"]=req.Flow }
  ctx,cancel:=context.WithTimeout(c.Request.Context(),12*time.Second); defer cancel()
  if err=job.NativeAgentCreateClient(ctx,n,inbound.RemoteTag,client); err!=nil { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":err.Error()}); return }
  _=nodeDB().Where("node_id = ? AND email = ?",id,req.Email).Delete(&model.NodeClientSnapshot{}).Error
  _=nodeDB().Create(&model.NodeClientSnapshot{NodeID:id,Email:req.Email,Enable:true,LastSyncAt:time.Now().UnixMilli()}).Error
  c.JSON(http.StatusOK,gin.H{"success":true,"obj":gin.H{"nodeId":id,"inboundId":req.InboundID,"inbound":inbound.Remark,"protocol":protocol,"email":req.Email,"id":client["id"],"password":client["password"]}})
  return
 }
 expiry := int64(0)
 if req.Days > 0 {
  expiry = time.Now().AddDate(0, 0, req.Days).UnixMilli()
 } else if req.Months > 0 {
  expiry = time.Now().AddDate(0, req.Months, 0).UnixMilli()
 }
 payload := map[string]any{
  "client": map[string]any{
   "email": req.Email, "totalGB": req.TotalGB * (1 << 30),
   "expiryTime": expiry, "enable": true, "flow": req.Flow,
  },
  "inboundIds": []int{req.InboundID},
 }
 body, err := json.Marshal(payload)
 if err != nil {
  c.JSON(http.StatusInternalServerError, gin.H{"success": false, "msg": "could not encode client request"})
  return
 }
 ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
 defer cancel()
 if _, err = job.CreateNodeClient(ctx, n, body); err != nil {
  c.JSON(http.StatusBadGateway, gin.H{"success": false, "msg": err.Error()})
  return
 }
 _ = nodeDB().Where("node_id = ? AND email = ?", id, req.Email).Delete(&model.NodeClientSnapshot{}).Error
 _ = nodeDB().Create(&model.NodeClientSnapshot{NodeID:id,Email:req.Email,Total:req.TotalGB * (1 << 30),ExpiryTime:expiry,Enable:true,LastSyncAt:time.Now().UnixMilli()}).Error
 c.JSON(http.StatusOK, gin.H{"success": true, "obj": gin.H{
  "nodeId": id, "inboundId": req.InboundID, "inbound": inbound.Remark,
  "protocol": protocol, "email": req.Email,
  "totalGB": req.TotalGB * (1 << 30), "expiryTime": expiry,
 }})
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
}

func (a *NodeController) listNodeClients(c *gin.Context) {
 type row struct {
  model.NodeClientSnapshot
  NodeName string `json:"nodeName"`
  NodeAddress string `json:"nodeAddress"`
  NodeStatus string `json:"nodeStatus"`
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
  rows = append(rows,row{NodeClientSnapshot:s,NodeName:n.Name,NodeAddress:n.Address,NodeStatus:n.Status})
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
 if n.AgentMode { c.JSON(http.StatusNotImplemented,gin.H{"success":false,"msg":"client update is not yet supported by AMIN Node Agent 0.2.1"}); return }
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

// nodeClientConfig fetches live Sanaei credentials and builds a share URI without
// persisting UUIDs/passwords in the local database.
func (a *NodeController) nodeClientConfig(c *gin.Context) {
 n, ok := a.loadManageableNode(c)
 if !ok { return }
 if n.AgentMode { c.JSON(http.StatusNotImplemented,gin.H{"success":false,"msg":"connection URI generation is not yet implemented for AMIN Node Agent nodes"}); return }
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
   for source,target:=range map[string]string{"publicKey":"pbk","shortId":"sid","spiderX":"spx"} {
    val:=strings.TrimSpace(fmt.Sprint(settings[source])); if val!="" && val!="<nil>" { q.Set(target,val) }
   }
   if q.Get("pbk")=="" { c.JSON(http.StatusBadGateway,gin.H{"success":false,"msg":"Public Key واقعی Reality در تنظیمات Inbound پیدا نشد"}); return }
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
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":gin.H{"email":email,"nodeName":n.Name,"inbound":remark,"protocol":protocol,"link":link}})
}
