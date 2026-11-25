package model

// NodeInboundSnapshot is a read-only mirror of the operational fields reported
// by a remote panel. It deliberately excludes inbound settings and credentials.
type NodeInboundSnapshot struct {
 Id int `json:"id" gorm:"primaryKey;autoIncrement"`
 NodeID int `json:"nodeId" gorm:"uniqueIndex:idx_node_remote_inbound,priority:1;index"`
 RemoteID int `json:"remoteId" gorm:"uniqueIndex:idx_node_remote_inbound,priority:2"`
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
 ClientCount int `json:"clientCount"`
 LastSyncAt int64 `json:"lastSyncAt"`
}
func (NodeInboundSnapshot) TableName() string { return "node_inbound_snapshots" }

// NodeClientSnapshot mirrors remote account usage without copying credentials.
type NodeClientSnapshot struct {
 Id int `json:"id" gorm:"primaryKey;autoIncrement"`
 NodeID int `json:"nodeId" gorm:"uniqueIndex:idx_node_client_email,priority:1;index"`
 Email string `json:"email" gorm:"size:255;uniqueIndex:idx_node_client_email,priority:2"`
 Up int64 `json:"up"`
 Down int64 `json:"down"`
 Total int64 `json:"total"`
 ExpiryTime int64 `json:"expiryTime"`
 Enable bool `json:"enable"`
 Online bool `json:"online"`
 LastOnline int64 `json:"lastOnline"`
 LastSyncAt int64 `json:"lastSyncAt"`
}
func (NodeClientSnapshot) TableName() string { return "node_client_snapshots" }
