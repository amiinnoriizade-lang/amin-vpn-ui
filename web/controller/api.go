package controller

import (
 "net/http"

 "github.com/mhsanaei/3x-ui/v2/database/model"
 "github.com/mhsanaei/3x-ui/v2/web/service"
 "github.com/mhsanaei/3x-ui/v2/web/session"

 "github.com/gin-gonic/gin"
)

// APIController handles the main API routes for the vpn-ui panel, including inbounds and server management.
type APIController struct {
 BaseController
 inboundController *InboundController
 serverController *ServerController
 Tgbot service.Tgbot
}

func NewAPIController(g *gin.RouterGroup, customGeo *service.CustomGeoService) *APIController {
 a:=&APIController{}
 a.initRouter(g,customGeo)
 return a
}

func (a *APIController) checkAPIAuth(c *gin.Context) {
 if !session.IsLogin(c) { c.AbortWithStatus(http.StatusNotFound); return }
 c.Next()
}

func (a *APIController) initRouter(g *gin.RouterGroup, customGeo *service.CustomGeoService) {
 api:=g.Group("/panel/api")
 api.Use(a.checkAPIAuth)
 inbounds:=api.Group("/inbounds")
 a.inboundController=NewInboundController(inbounds)
 clients:=api.Group("/clients")
 clients.Use(requirePerm(model.PermAccessInbounds))
 NewClientsController(clients)
 server:=api.Group("/server")
 a.serverController=NewServerController(server)
 customGeoGroup:=api.Group("/custom-geo")
 customGeoGroup.Use(requireXrayOrOverviewManage())
 NewCustomGeoController(customGeoGroup,customGeo)
 // Node configuration is a super-admin capability: node API tokens grant
 // control of remote servers and must not be exposed to delegated panel admins.
 nodes:=api.Group("/nodes")
 nodes.Use(requireSuperAdmin())
 NewNodeController(nodes)
 api.GET("/backuptotgbot",requireOverviewManage(),a.BackuptoTgbot)
}

func (a *APIController) BackuptoTgbot(c *gin.Context) { a.Tgbot.SendBackupToAdmins() }
