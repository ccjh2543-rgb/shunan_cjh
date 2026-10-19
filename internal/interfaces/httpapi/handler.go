// Package httpapi 是接口层，负责 HTTP 协议解析、参数校验与统一响应包装。
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"bannerfp/internal/application"
	"bannerfp/internal/infrastructure/scanjson"
)

// maxBodyBytes 限制单次请求体大小，避免大报文耗尽内存。
const maxBodyBytes = 32 << 20

// envelope 是统一响应包装，业务成功时 code=0。
type envelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// Handler 聚合指纹识别接口所需的依赖与运行信息。
type Handler struct {
	service   *application.FingerprintService
	logger    *slog.Logger
	maxBatch  int
	rules     int
	version   string
	startedAt time.Time
}

// NewHandler 注册路由并挂载 panic 恢复、访问日志中间件。
func NewHandler(service *application.FingerprintService, logger *slog.Logger, maxBatch, rulesCount int, version string) http.Handler {
	h := &Handler{
		service:   service,
		logger:    logger,
		maxBatch:  maxBatch,
		rules:     rulesCount,
		version:   version,
		startedAt: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /fingerprint", h.handleFingerprint)
	mux.HandleFunc("GET /health", h.handleHealth)

	return h.recoverer(h.accessLog(mux))
}

// handleFingerprint 处理批量识别请求。
// 请求体支持裸数组与 {"items":[...]} 两种形式；无法识别的条目返回 unknown，不会导致请求失败。
func (h *Handler) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer body.Close()

	raw, err := io.ReadAll(body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, 41301, "请求体超过 32MiB 限制")
			return
		}
		writeError(w, http.StatusBadRequest, 40001, "读取请求体失败")
		return
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		writeError(w, http.StatusBadRequest, 40001, "请求体为空")
		return
	}

	items, err := scanjson.UnmarshalItems(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, 40001, err.Error())
		return
	}
	if len(items) > h.maxBatch {
		writeError(w, http.StatusBadRequest, 40002, fmt.Sprintf("单批最多 %d 条，实际 %d 条", h.maxBatch, len(items)))
		return
	}

	results, err := h.service.Fingerprint(r.Context(), items)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			h.logger.Warn("客户端提前断开，批量识别被取消", "error", err)
			return
		}
		h.logger.Error("批量识别失败", "error", err)
		writeError(w, http.StatusInternalServerError, 50001, "服务内部错误")
		return
	}

	writeJSON(w, http.StatusOK, envelope{Code: 0, Message: "ok", Data: results})
}

// handleHealth 返回服务健康状态、规则数量与版本，供容器健康检查使用。
func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		Code:    0,
		Message: "ok",
		Data: map[string]any{
			"status":         "ok",
			"version":        h.version,
			"rules":          h.rules,
			"uptime_seconds": int(time.Since(h.startedAt).Seconds()),
		},
	})
}

// recoverer 防止单条异常数据导致进程崩溃。
func (h *Handler) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				h.logger.Error("请求处理发生 panic", "panic", recovered, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, 50001, "服务内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// accessLog 输出结构化访问日志，便于容器日志采集。
func (h *Handler) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		h.logger.Info("http 请求",
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", recorder.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

func writeJSON(w http.ResponseWriter, status int, payload envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload) // 响应已开始写入，编码失败无法再补救。
}

func writeError(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, envelope{Code: code, Message: message, Data: nil})
}
