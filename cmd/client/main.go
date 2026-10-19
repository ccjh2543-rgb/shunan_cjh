// client 读取本地 JSON 扫描数据，调用 server 批量识别并展示结果。
// 识别不出的条目由服务端返回 unknown，不会导致客户端失败。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"time"

	"bannerfp/internal/domain"
	"bannerfp/internal/infrastructure/httpclient"
	"bannerfp/internal/infrastructure/scanjson"
	"bannerfp/internal/interfaces/cli"
)

func main() {
	var (
		file       = flag.String("file", "", "输入 JSON 文件路径（必填）")
		serverURL  = flag.String("server", env("SERVER_URL", "http://127.0.0.1:8080"), "server 地址")
		jsonOutput = flag.Bool("json", false, "以 JSON 数组输出，默认输出表格")
		outPath    = flag.String("out", "", "将结果写入指定文件，默认输出到标准输出")
		timeout    = flag.Duration("timeout", envDuration("CLIENT_TIMEOUT", 60*time.Second), "整体请求超时")
		batchSize  = flag.Int("batch", envInt("CLIENT_BATCH_SIZE", 500), "单次请求条数")
	)
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "必须通过 -file 指定输入文件")
		flag.Usage()
		os.Exit(2)
	}
	if *batchSize <= 0 {
		fmt.Fprintln(os.Stderr, "-batch 必须大于 0")
		os.Exit(2)
	}
	if err := validateServerURL(*serverURL); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	startedAt := time.Now()

	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取输入文件失败: %v\n", err)
		os.Exit(1)
	}
	items, err := scanjson.UnmarshalItems(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析输入数据失败: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := httpclient.New(*serverURL, 0)
	results := make([]domain.Fingerprint, 0, len(items))
	for start := 0; start < len(items); start += *batchSize {
		end := start + *batchSize
		if end > len(items) {
			end = len(items)
		}
		batch, err := client.Fingerprint(ctx, items[start:end])
		if err != nil {
			fmt.Fprintf(os.Stderr, "识别第 %d-%d 条失败: %v\n", start+1, end, err)
			os.Exit(1)
		}
		results = append(results, batch...)
	}

	out, closeOutput, err := openOutput(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开输出文件失败: %v\n", err)
		os.Exit(1)
	}
	defer closeOutput()

	if *jsonOutput {
		err = cli.RenderJSON(out, results)
	} else {
		err = cli.RenderTable(out, results)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "输出结果失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "共 %d 条，其中 unknown %d 条，耗时 %s\n",
		len(results), cli.CountUnknown(results), time.Since(startedAt).Round(time.Millisecond))
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return file, func() { _ = file.Close() }, nil
}

func validateServerURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("server 地址非法: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("server 地址必须以 http:// 或 https:// 开头")
	}
	if parsed.Host == "" {
		return fmt.Errorf("server 地址缺少主机名")
	}
	return nil
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

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
