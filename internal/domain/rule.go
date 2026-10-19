package domain

import "context"

// Rule 描述一条协议指纹规则。
// 规则内容全部来自外部配置，领域层只负责“如何匹配”，不关心规则从哪里加载。
type Rule struct {
	// Name 规则名称，仅用于日志与排障。
	Name string
	// Protocol 命中后输出的协议名，例如 SSH、HTTP、MySQL。
	Protocol string
	// Product、Version、OSHint 是默认值；若正则命名捕获组给出了非空值，则覆盖默认值。
	Product    string
	Version    string
	OSHint     string
	Confidence float64
	// Priority 越大越先匹配，用于让“产品级规则”优先于“协议级兜底规则”。
	Priority int
	// Patterns 按顺序尝试，首个命中的正则生效。
	// 支持命名捕获组 product、version、os_hint。
	Patterns []string
	// Require 是前置条件，必须全部命中该规则才会继续匹配 Patterns。
	Require []string
}

// OSHintRule 通过 banner 中的系统特征推断操作系统线索。
type OSHintRule struct {
	Pattern string
	Value   string
}

// RuleSet 是一次加载得到的完整规则集合。
type RuleSet struct {
	Rules   []Rule
	OSHints []OSHintRule
}

// RuleRepository 定义规则读取端口，由基础设施层实现（当前为 YAML 文件）。
// 领域层不感知文件、网络等具体实现。
type RuleRepository interface {
	Load(ctx context.Context) (RuleSet, error)
}

// Matcher 定义指纹识别能力，应用层只依赖该接口。
type Matcher interface {
	// Identify 识别单条 banner。对任意输入都必须返回结果，不得 panic。
	Identify(banner Banner) Fingerprint
}
