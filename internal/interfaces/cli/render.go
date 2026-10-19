// Package cli 提供 client 程序的输入解析与结果渲染能力。
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"bannerfp/internal/domain"
)

// RenderTable 以对齐表格输出识别结果，便于人工核对。
func RenderTable(out io.Writer, results []domain.Fingerprint) error {
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE"); err != nil {
		return err
	}
	for _, item := range results {
		if _, err := fmt.Fprintf(writer, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			item.IP, item.Port, item.Protocol, item.Product, item.Version, item.OSHint, item.Confidence); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// RenderJSON 以缩进 JSON 数组输出识别结果，结构与题目示例一致。
func RenderJSON(out io.Writer, results []domain.Fingerprint) error {
	if results == nil {
		results = []domain.Fingerprint{}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(results)
}

// CountUnknown 统计未能识别的条目数，用于输出摘要。
func CountUnknown(results []domain.Fingerprint) int {
	count := 0
	for _, item := range results {
		if item.Protocol == domain.ProtocolUnknown {
			count++
		}
	}
	return count
}
