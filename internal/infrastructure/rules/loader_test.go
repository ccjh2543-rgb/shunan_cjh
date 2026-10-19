package rules

import (
	"context"
	"math"
	"testing"

	"bannerfp/internal/domain"
)

// TestRulesAgainstSampleData 用交付示例数据做表驱动回归，确保规则调整不会破坏既有识别深度。
func TestRulesAgainstSampleData(t *testing.T) {
	repository := NewYAMLRepository("../../../config/rules.yaml")
	set, err := repository.Load(context.Background())
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	engine, err := domain.NewEngine(set)
	if err != nil {
		t.Fatalf("编译规则失败: %v", err)
	}

	cases := []struct {
		name       string
		banner     string
		protocol   string
		product    string
		version    string
		osHint     string
		confidence float64
	}{
		{"openssh-ubuntu", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		{"nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html", "HTTP", "nginx", "1.24.0", "", 0.9},
		{"apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57", "HTTP", "Apache", "2.4.57", "", 0.9},
		{"mysql8", "J\x00\x00\x00\n8.0.32\x00", "MySQL", "MySQL", "8.0.32", "", 0.9},
		{"redis-err", "-ERR wrong number of arguments for 'get' command", "Redis", "Redis", "", "", 0.7},
		{"proftpd", "220 ProFTPD 1.3.7 Server (ProFTPD)", "FTP", "ProFTPD", "1.3.7", "", 0.9},
		{"jetty", "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51", "HTTP", "Jetty", "9.4.51", "", 0.9},
		{"jetty-paren", "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)", "HTTP", "Jetty", "9.4.51.v20230217", "", 0.9},
		{"openssh-debian", "SSH-2.0-OpenSSH_9.3 Debian-1", "SSH", "OpenSSH", "9.3", "Debian", 0.95},
		{"nginx-ubuntu", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)", "HTTP", "nginx", "1.18.0", "Ubuntu", 0.9},
		{"apache-ubuntu", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)", "HTTP", "Apache", "2.4.41", "Ubuntu", 0.9},
		{"mysql57", "J\x00\x00\x00\n5.7.42\x00", "MySQL", "MySQL", "5.7.42", "", 0.9},
		{"redis-pong", "+PONG", "Redis", "Redis", "", "", 0.7},
		{"vsftpd", "220 (vsFTPd 3.0.5)", "FTP", "vsFTPd", "3.0.5", "", 0.9},
		{"nginx-8443", "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3", "HTTP", "nginx", "1.25.3", "", 0.9},
		{"openssh-old", "SSH-1.99-OpenSSH_4.3", "SSH", "OpenSSH", "4.3", "", 0.95},
		{"tls", "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1", "TLS", "", "", "", 0.75},
		{"iis", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0", "HTTP", "Microsoft-IIS", "10.0", "Windows", 0.9},
		{"redis-noauth", "-NOAUTH Authentication required.", "Redis", "Redis", "", "", 0.7},
		{"pure-ftpd", "220 Welcome to Pure-FTPd", "FTP", "Pure-FTPd", "", "", 0.9},
		{"unknown", "QUIT\r\n", "unknown", "", "", "", 0.2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify(domain.Banner{IP: "127.0.0.1", Port: 1, Banner: tc.banner})
			if got.Protocol != tc.protocol {
				t.Fatalf("protocol = %q, want %q", got.Protocol, tc.protocol)
			}
			if got.Product != tc.product {
				t.Fatalf("product = %q, want %q", got.Product, tc.product)
			}
			if got.Version != tc.version {
				t.Fatalf("version = %q, want %q", got.Version, tc.version)
			}
			if got.OSHint != tc.osHint {
				t.Fatalf("os_hint = %q, want %q", got.OSHint, tc.osHint)
			}
			if math.Abs(got.Confidence-tc.confidence) > 1e-9 {
				t.Fatalf("confidence = %v, want %v", got.Confidence, tc.confidence)
			}
		})
	}
}

// TestUnknownDoesNotPanic 验证任意脏数据都只会得到 unknown，不会导致崩溃。
func TestUnknownDoesNotPanic(t *testing.T) {
	repository := NewYAMLRepository("../../../config/rules.yaml")
	set, err := repository.Load(context.Background())
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	engine, err := domain.NewEngine(set)
	if err != nil {
		t.Fatalf("编译规则失败: %v", err)
	}

	for _, banner := range []string{"", "   ", "\x00\x01\x02", "<<<>>>", "HTTP/9.9 ???"} {
		got := engine.Identify(domain.Banner{IP: "127.0.0.1", Port: 1, Banner: banner})
		if got.Protocol == "" {
			t.Fatalf("banner %q 返回了空协议，必须为 unknown", banner)
		}
	}
}
