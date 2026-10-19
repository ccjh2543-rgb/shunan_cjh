// Package httpclient 封装对 server 的 HTTP 调用，供 client 程序使用。
package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"bannerfp/internal/domain"
)

// maxResponseBytes 限制单次响应体大小，避免异常响应耗尽内存。
const maxResponseBytes = 32 << 20

// Client 是 server 的 HTTP 客户端。
type Client struct {
	baseURL string
	http    *http.Client
}

// New 创建客户端，baseURL 例如 http://server:8080。
func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// responseEnvelope 对应服务端统一响应包装。
type responseEnvelope struct {
	Code    int                  `json:"code"`
	Message string               `json:"message"`
	Data    []domain.Fingerprint `json:"data"`
}

// Fingerprint 向 server 提交一批 banner 并返回识别结果。
// HTTP 非 200 或业务 code 非 0 都会返回 error，由调用方决定退出码。
func (c *Client) Fingerprint(ctx context.Context, items []domain.Banner) ([]domain.Fingerprint, error) {
	payload, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("序列化请求数据失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/fingerprint", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 server 失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server 返回 HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	var envelope responseEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if envelope.Code != 0 {
		return nil, fmt.Errorf("server 返回业务错误 code=%d: %s", envelope.Code, envelope.Message)
	}
	if envelope.Data == nil {
		envelope.Data = []domain.Fingerprint{}
	}
	return envelope.Data, nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
