package domain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// compiledRule 是编译后的规则，正则只在启动时编译一次。
type compiledRule struct {
	def      Rule
	patterns []*regexp.Regexp
	require  []*regexp.Regexp
}

// compiledOSHint 是编译后的系统线索规则。
type compiledOSHint struct {
	pattern *regexp.Regexp
	value   string
}

// Engine 是规则驱动的指纹识别引擎。
// 它是纯内存计算，不包含任何 IO，因此可以安全地被并发调用。
type Engine struct {
	rules   []compiledRule
	osHints []compiledOSHint
}

// NewEngine 编译并校验规则集。
// 规则为空、正则非法、必填字段缺失都会在启动阶段直接报错，避免带病运行。
func NewEngine(set RuleSet) (*Engine, error) {
	if len(set.Rules) == 0 {
		return nil, fmt.Errorf("规则集为空")
	}

	engine := &Engine{}
	for i, def := range set.Rules {
		if strings.TrimSpace(def.Protocol) == "" {
			return nil, fmt.Errorf("第 %d 条规则缺少 protocol", i+1)
		}
		if len(def.Patterns) == 0 {
			return nil, fmt.Errorf("规则 %q 缺少 patterns", def.Name)
		}
		if def.Confidence <= 0 || def.Confidence > 1 {
			return nil, fmt.Errorf("规则 %q 的 confidence 必须在 (0,1] 区间", def.Name)
		}

		compiled := compiledRule{def: def}
		for _, pattern := range def.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("规则 %q 的匹配正则非法: %w", def.Name, err)
			}
			compiled.patterns = append(compiled.patterns, re)
		}
		for _, pattern := range def.Require {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("规则 %q 的前置正则非法: %w", def.Name, err)
			}
			compiled.require = append(compiled.require, re)
		}
		engine.rules = append(engine.rules, compiled)
	}

	// 高优先级规则先匹配；同优先级保持配置顺序，保证行为可预测。
	sort.SliceStable(engine.rules, func(i, j int) bool {
		return engine.rules[i].def.Priority > engine.rules[j].def.Priority
	})

	for _, hint := range set.OSHints {
		re, err := regexp.Compile(hint.Pattern)
		if err != nil {
			return nil, fmt.Errorf("os_hint 规则 %q 正则非法: %w", hint.Pattern, err)
		}
		engine.osHints = append(engine.osHints, compiledOSHint{pattern: re, value: hint.Value})
	}

	return engine, nil
}

// Identify 识别单条 banner，返回结果永远不会是 error。
// 未命中任何规则时返回 protocol=unknown、低置信度，调用方无需特殊处理。
func (e *Engine) Identify(banner Banner) Fingerprint {
	result := Fingerprint{
		IP:         banner.IP,
		Port:       banner.Port,
		Protocol:   ProtocolUnknown,
		Confidence: 0.2,
	}

	text := banner.Banner
	if strings.TrimSpace(text) == "" {
		result.Confidence = 0.1
		return result
	}

	for _, rule := range e.rules {
		if !matchAll(rule.require, text) {
			continue
		}
		for _, re := range rule.patterns {
			matches := re.FindStringSubmatch(text)
			if matches == nil {
				continue
			}

			result.Protocol = rule.def.Protocol
			result.Product = coalesce(groupValue(re, matches, "product"), rule.def.Product)
			result.Version = coalesce(groupValue(re, matches, "version"), rule.def.Version)
			result.OSHint = coalesce(groupValue(re, matches, "os_hint"), rule.def.OSHint)
			if result.OSHint == "" {
				result.OSHint = e.detectOS(text)
			}
			result.Confidence = rule.def.Confidence
			return result
		}
	}

	return result
}

// detectOS 按配置顺序返回首个命中的系统线索。
func (e *Engine) detectOS(text string) string {
	for _, hint := range e.osHints {
		if hint.pattern.MatchString(text) {
			return hint.value
		}
	}
	return ""
}

func matchAll(patterns []*regexp.Regexp, text string) bool {
	for _, re := range patterns {
		if !re.MatchString(text) {
			return false
		}
	}
	return true
}

// groupValue 读取命名捕获组，未定义或未命中时返回空串。
func groupValue(re *regexp.Regexp, matches []string, name string) string {
	index := re.SubexpIndex(name)
	if index <= 0 || index >= len(matches) {
		return ""
	}
	return cleanValue(matches[index])
}

func cleanValue(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), ",;")
}

func coalesce(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
