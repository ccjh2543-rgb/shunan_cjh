package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bannerfp/internal/application"
	"bannerfp/internal/domain"
)

func newTestHandler(t *testing.T, maxBatch int) http.Handler {
	t.Helper()
	engine, err := domain.NewEngine(domain.RuleSet{
		Rules: []domain.Rule{
			{
				Name:       "ssh",
				Protocol:   "SSH",
				Product:    "OpenSSH",
				Confidence: 0.9,
				Priority:   1,
				Patterns:   []string{`^SSH-`},
			},
		},
	})
	if err != nil {
		t.Fatalf("构造引擎失败: %v", err)
	}
	service := application.NewFingerprintService(engine, 2)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(service, logger, maxBatch, 1, "test")
}

func TestFingerprintEndpoint(t *testing.T) {
	handler := newTestHandler(t, 10)

	body := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"},
	          {"ip":"1.2.3.5","port":9999,"banner":"QUIT"}]`
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP 状态 = %d, want 200, body=%s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Code int                  `json:"code"`
		Data []domain.Fingerprint `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if response.Code != 0 {
		t.Fatalf("业务 code = %d, want 0", response.Code)
	}
	if len(response.Data) != 2 {
		t.Fatalf("结果条数 = %d, want 2", len(response.Data))
	}
	if response.Data[0].Protocol != "SSH" || response.Data[0].Product != "OpenSSH" {
		t.Fatalf("首条结果异常: %+v", response.Data[0])
	}
	// 无法识别的条目必须是 unknown，而不是报错或空值。
	if response.Data[1].Protocol != domain.ProtocolUnknown {
		t.Fatalf("未识别条目 protocol = %q, want unknown", response.Data[1].Protocol)
	}
}

func TestFingerprintBatchLimit(t *testing.T) {
	handler := newTestHandler(t, 1)
	body := `[{"ip":"1","port":1,"banner":"a"},{"ip":"2","port":2,"banner":"b"}]`
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("HTTP 状态 = %d, want 400", recorder.Code)
	}
}

func TestFingerprintInvalidJSON(t *testing.T) {
	handler := newTestHandler(t, 10)
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`[{"ip":`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("HTTP 状态 = %d, want 400", recorder.Code)
	}
	var response struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if response.Code != 40001 {
		t.Fatalf("业务 code = %d, want 40001", response.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	handler := newTestHandler(t, 10)
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP 状态 = %d, want 200", recorder.Code)
	}
	var response struct {
		Code int `json:"code"`
		Data struct {
			Status string `json:"status"`
			Rules  int    `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if response.Code != 0 || response.Data.Status != "ok" || response.Data.Rules != 1 {
		t.Fatalf("健康检查响应异常: %+v", response)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	handler := newTestHandler(t, 10)
	request := httptest.NewRequest(http.MethodGet, "/fingerprint", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HTTP 状态 = %d, want 405", recorder.Code)
	}
}
