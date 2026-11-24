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
 CreatedAt int64 `json:"createdAt" gorm:"autoCreateTime:milli"`
 UpdatedAt int64 `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

func (Node) TableName() string { return "nodes" }
