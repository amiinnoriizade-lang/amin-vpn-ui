package model

// Node stores remote node control-plane configuration. Runtime metrics are not
// persisted here; heartbeat and traffic collectors own their freshness.
type Node struct {
 Id int `json:"id" gorm:"primaryKey;autoIncrement"`
 Name string `json:"name" gorm:"size:128;not null"`
 Remark string `json:"remark"`
 Scheme string `json:"scheme" gorm:"size:8;not null;default:https"`
 Address string `json:"address" gorm:"size:253;not null"`
 Port int `json:"port" gorm:"not null;default:2053"`
 BasePath string `json:"basePath"`
 ApiToken string `json:"-" gorm:"not null"`
 Enable bool `json:"enable" gorm:"not null;default:true;index"`
 AllowPrivateAddress bool `json:"allowPrivateAddress" gorm:"not null;default:false"`
 TlsVerifyMode string `json:"tlsVerifyMode" gorm:"size:24;not null;default:system"`
 PinnedCertSha256 string `json:"pinnedCertSha256" gorm:"size:64"`
 InboundSyncMode string `json:"inboundSyncMode" gorm:"size:24;not null;default:all"`
 InboundTags string `json:"inboundTags" gorm:"type:text"`
 OutboundTag string `json:"outboundTag"`
 Guid string `json:"guid" gorm:"size:64;index"`
 ParentGuid string `json:"parentGuid" gorm:"size:64;index"`
 Transitive bool `json:"transitive" gorm:"not null;default:false"`

 Status string `json:"status" gorm:"size:16;not null;default:unknown;index"`
 LastHeartbeat int64 `json:"lastHeartbeat" gorm:"not null;default:0"`
 LatencyMs int `json:"latencyMs" gorm:"not null;default:0"`
 LastError string `json:"lastError" gorm:"type:text"`
 CpuPct float64 `json:"cpuPct" gorm:"not null;default:0"`
 MemPct float64 `json:"memPct" gorm:"not null;default:0"`
 UptimeSecs uint64 `json:"uptimeSecs" gorm:"not null;default:0"`
 PanelVersion string `json:"panelVersion" gorm:"size:64"`
 XrayVersion string `json:"xrayVersion" gorm:"size:64"`
 XrayState string `json:"xrayState" gorm:"size:24"`
 NetUp uint64 `json:"netUp" gorm:"not null;default:0"`
 NetDown uint64 `json:"netDown" gorm:"not null;default:0"`
 CreatedAt int64 `json:"createdAt" gorm:"autoCreateTime:milli"`
 UpdatedAt int64 `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

func (Node) TableName() string { return "nodes" }
