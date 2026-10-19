// Package domain 是系统的领域核心层，只包含业务实体、业务规则与领域接口，
// 不依赖数据库、HTTP、文件系统等任何基础设施。
package domain

// ProtocolUnknown 表示无法识别的协议。识别失败属于正常业务结果，不是错误。
const ProtocolUnknown = "unknown"

// Banner 表示一条待识别的网络扫描原始数据。
type Banner struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Fingerprint 表示一条识别结果。
// 字段与交付要求保持一致，confidence 取值区间为 (0,1]。
type Fingerprint struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}
