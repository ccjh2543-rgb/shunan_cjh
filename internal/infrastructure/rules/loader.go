// Package rules 实现领域层 RuleRepository 端口，从 YAML 文件加载指纹规则。
package rules

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"bannerfp/internal/domain"
)

// YAMLRepository 从本地 YAML 文件读取规则，支持通过容器卷挂载覆盖。
type YAMLRepository struct {
	path string
}

// NewYAMLRepository 创建基于 YAML 文件的规则仓库。
func NewYAMLRepository(path string) *YAMLRepository {
	return &YAMLRepository{path: path}
}

// Load 读取并解析规则文件，同时对必填字段做基础校验。
func (r *YAMLRepository) Load(_ context.Context) (domain.RuleSet, error) {
	if strings.TrimSpace(r.path) == "" {
		return domain.RuleSet{}, fmt.Errorf("规则文件路径为空")
	}

	data, err := os.ReadFile(r.path)
	if err != nil {
		return domain.RuleSet{}, fmt.Errorf("读取规则文件 %s 失败: %w", r.path, err)
	}

	var cfg config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	// 拒绝未知字段，避免配置拼写错误被静默忽略。
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return domain.RuleSet{}, fmt.Errorf("解析规则文件 %s 失败: %w", r.path, err)
	}

	set := domain.RuleSet{
		Rules:   make([]domain.Rule, 0, len(cfg.Rules)),
		OSHints: make([]domain.OSHintRule, 0, len(cfg.OSHints)),
	}
	for i, item := range cfg.Rules {
		if strings.TrimSpace(item.Name) == "" {
			return domain.RuleSet{}, fmt.Errorf("第 %d 条规则缺少 name", i+1)
		}
		set.Rules = append(set.Rules, domain.Rule{
			Name:       item.Name,
			Protocol:   item.Protocol,
			Product:    item.Product,
			Version:    item.Version,
			OSHint:     item.OSHint,
			Confidence: item.Confidence,
			Priority:   item.Priority,
			Patterns:   item.Patterns,
			Require:    item.Require,
		})
	}
	for _, item := range cfg.OSHints {
		set.OSHints = append(set.OSHints, domain.OSHintRule{
			Pattern: item.Pattern,
			Value:   item.Value,
		})
	}

	return set, nil
}

// config 是 YAML 文件的结构映射，避免让领域实体直接依赖 yaml 标签。
type config struct {
	Rules   []ruleConfig   `yaml:"rules"`
	OSHints []osHintConfig `yaml:"os_hints"`
}

type ruleConfig struct {
	Name       string   `yaml:"name"`
	Protocol   string   `yaml:"protocol"`
	Product    string   `yaml:"product"`
	Version    string   `yaml:"version"`
	OSHint     string   `yaml:"os_hint"`
	Confidence float64  `yaml:"confidence"`
	Priority   int      `yaml:"priority"`
	Patterns   []string `yaml:"patterns"`
	Require    []string `yaml:"require"`
}

type osHintConfig struct {
	Pattern string `yaml:"pattern"`
	Value   string `yaml:"value"`
}
