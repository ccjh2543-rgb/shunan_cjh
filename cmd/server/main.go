// server 是可独立部署的 Banner 指纹识别服务。
// 除正常启动外，还提供 healthcheck 子命令（scratch 镜像内没有 shell/curl，
// 用二进制自身完成健康检查，避免为了探针而引入额外工具）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"bannerfp/internal/application"
	"bannerfp/internal/domain"
	"bannerfp/internal/infrastructure/rules"
	"bannerfp/internal/interfaces/httpapi"
)

// version 由构建参数注入，便于在 /health 中确认运行版本。
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(os.Args[2:]))
	}
	if err := run(); err != nil {
		slog.Error("server 启动失败", "error", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", env("ADDR", ":8080"), "HTTP 监听地址")
	rulesPath := flag.String("rules", env("RULES_FILE", "config/rules.yaml"), "指纹规则 YAML 文件路径")
	workers := flag.Int("workers", envInt("WORKERS", 8), "识别并发度")
	maxBatch := flag.Int("max-batch", envInt("MAX_BATCH", 10000), "单次请求最大条数")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *maxBatch <= 0 {
		return fmt.Errorf("max-batch 必须大于 0")
	}

	// 启动阶段加载并编译规则，配置错误立即失败，避免带病运行。
	repository := rules.NewYAMLRepository(*rulesPath)
	ruleSet, err := repository.Load(context.Background())
	if err != nil {
		return err
	}
	engine, err := domain.NewEngine(ruleSet)
	if err != nil {
		return err
	}
	service := application.NewFingerprintService(engine, *workers)
	handler := httpapi.NewHandler(service, logger, *maxBatch, len(ruleSet.Rules), version)

	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server 已启动", "addr", *addr, "rules", len(ruleSet.Rules), "version", version)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("收到退出信号，开始优雅停机")
	case err := <-serverErr:
		return fmt.Errorf("HTTP 服务异常退出: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("优雅停机失败: %w", err)
	}
	logger.Info("server 已退出")
	return nil
}

// runHealthcheck 调用本机 /health，只有 HTTP 200 且业务状态为 ok 才返回 0。
func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", env("HEALTHCHECK_URL", "http://127.0.0.1:8080/health"), "健康检查地址")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "构造健康检查请求失败:", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "健康检查请求失败:", err)
		return 1
	}
	defer resp.Body.Close()

	var payload struct {
		Code int `json:"code"`
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Fprintln(os.Stderr, "解析健康检查响应失败:", err)
		return 1
	}
	if resp.StatusCode != http.StatusOK || payload.Code != 0 || payload.Data.Status != "ok" {
		fmt.Fprintf(os.Stderr, "服务不健康: http=%d code=%d status=%s\n", resp.StatusCode, payload.Code, payload.Data.Status)
		return 1
	}
	return 0
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
