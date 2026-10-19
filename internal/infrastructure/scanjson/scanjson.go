// Package scanjson 负责解析扫描原始数据。
//
// 除标准 JSON 外，额外兼容题目示例中出现的字面量 \xNN 转义：
// JSON 规范不支持 \x，但扫描工具（以及示例数据）经常直接输出这种写法。
package scanjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"bannerfp/internal/domain"
)

// MaxBannerBytes 限制单条 banner 的长度，防止异常字段拖垮内存。
const MaxBannerBytes = 64 << 10

// hexEscape 匹配字面量反斜杠 + xHH。
var hexEscape = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// UnmarshalItems 解析批量扫描数据，兼容：
//  1. 裸数组：[{"ip":...}]
//  2. 包装对象：{"items":[{"ip":...}]}
//  3. 非标准 \xNN 转义
//
// 空数组是合法输入，返回空切片而不是 error。
func UnmarshalItems(data []byte) ([]domain.Banner, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // 去掉 UTF-8 BOM

	items, err := decode(data)
	if err == nil {
		return normalize(items), nil
	}

	// 把字面量 \xNN 改写为私有区码点 \uE0NN 后重试，解析后再还原为原始字节。
	// 不能写成 \u00NN：JSON 字符串是 Unicode，0x80 以上会被编码成多字节 UTF-8。
	// 只在首次解析失败时执行，避免破坏正常的 JSON 字符串。
	fixed := hexEscape.ReplaceAll(data, []byte(`\ue0$1`))
	if !bytes.Equal(fixed, data) {
		if items, fallbackErr := decode(fixed); fallbackErr == nil {
			for i := range items {
				items[i].Banner = restoreBytes(items[i].Banner)
			}
			return normalize(items), nil
		}
	}

	return nil, fmt.Errorf("解析输入 JSON 失败: %w", err)
}

func decode(data []byte) ([]domain.Banner, error) {
	var items []domain.Banner
	if err := json.Unmarshal(data, &items); err == nil {
		if items == nil {
			items = []domain.Banner{}
		}
		return items, nil
	}

	var wrapper struct {
		Items *[]domain.Banner `json:"items"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Items == nil {
		return nil, errors.New("JSON 既不是数组，也不包含 items 字段")
	}
	return *wrapper.Items, nil
}

func normalize(items []domain.Banner) []domain.Banner {
	for i := range items {
		items[i].Banner = truncateBytes(items[i].Banner, MaxBannerBytes)
	}
	if items == nil {
		items = []domain.Banner{}
	}
	return items
}

// restoreBytes 把 \uE000~\uE0FF 占位码点还原为对应单字节，
// 从而正确表达 0x80~0xFF 的非 UTF-8 二进制 banner。
func restoreBytes(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, char := range value {
		if char >= 0xE000 && char <= 0xE0FF {
			builder.WriteByte(byte(char - 0xE000))
			continue
		}
		builder.WriteRune(char)
	}
	return builder.String()
}

func truncateBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
