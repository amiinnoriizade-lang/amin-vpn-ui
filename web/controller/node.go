package controller

import (
 "net"
 "net/http"
 "net/url"
 "strconv"
 "strings"

 "github.com/gin-gonic/gin"
 "github.com/mhsanaei/3x-ui/v2/database"
 "github.com/mhsanaei/3x-ui/v2/database/model"
 "gorm.io/gorm"
)

// NodeController exposes authenticated CRUD for configured remote nodes.
// Remote probing and synchronization are intentionally separate follow-up work.
type NodeController struct { BaseController }

type nodeMutation struct {
 Name string `json:"name"`
 Remark string `json:"remark"`
 Scheme string `json:"scheme"`
 Address string `json:"address"`
 Port int `json:"port"`
 BasePath string `json:"basePath"`
 ApiToken string `json:"apiToken"`
 Enable *bool `json:"enable"`
 AllowPrivateAddress bool `json:"allowPrivateAddress"`
 TlsVerifyMode string `json:"tlsVerifyMode"`
 PinnedCertSha256 string `json:"pinnedCertSha256"`
 InboundSyncMode string `json:"inboundSyncMode"`
 InboundTags string `json:"inboundTags"`
 OutboundTag string `json:"outboundTag"`
 Guid string `json:"guid"`
 ParentGuid string `json:"parentGuid"`
 Transitive bool `json:"transitive"`
}

func NewNodeController(g *gin.RouterGroup) *NodeController {
 c := &NodeController{}
 g.GET("/list", c.list)
 g.GET("/get/:id", c.get)
 g.POST("/add", c.add)
 g.POST("/update/:id", c.update)
 g.POST("/del/:id", c.delete)
 g.POST("/setEnable/:id", c.setEnable)
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
 old.Name=strings.TrimSpace(v.Name); old.Remark=v.Remark; old.Scheme=v.Scheme; if old.Scheme=="" {old.Scheme="https"}
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
 if err:=c.ShouldBindJSON(&v); err!=nil {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid JSON"});return}
 if msg:=validNodeMutation(v,true); msg!="" {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":msg});return}
 n:=nodeFromMutation(v,model.Node{})
 if err:=nodeDB().Create(&n).Error; err!=nil {c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":err.Error()});return}
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":n})
}
func (a *NodeController) update(c *gin.Context) {
 id,err:=strconv.Atoi(c.Param("id")); if err!=nil || id<1 {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid node id"});return}
 var v nodeMutation
 if err=c.ShouldBindJSON(&v); err!=nil {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid JSON"});return}
 if msg:=validNodeMutation(v,false); msg!="" {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":msg});return}
 var n model.Node
 if err=nodeDB().First(&n,id).Error; err!=nil {c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"});return}
 n=nodeFromMutation(v,n)
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
 var req struct { Enable bool `json:"enable"` }
 if err=c.ShouldBindJSON(&req); err!=nil {c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid JSON"});return}
 result:=nodeDB().Model(&model.Node{}).Where("id = ?",id).Update("enable",req.Enable)
 if result.Error!=nil {c.JSON(http.StatusInternalServerError,gin.H{"success":false,"msg":result.Error.Error()});return}
 if result.RowsAffected==0 {c.JSON(http.StatusNotFound,gin.H{"success":false,"msg":"node not found"});return}
 c.JSON(http.StatusOK,gin.H{"success":true})
}
