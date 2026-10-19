package scanjson

import "testing"

func TestUnmarshalItemsFormats(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantCount  int
		wantBanner string
		wantErr    bool
	}{
		{
			name:       "裸数组",
			input:      `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}]`,
			wantCount:  1,
			wantBanner: "SSH-2.0-OpenSSH_8.9p1",
		},
		{
			name:       "items 包装",
			input:      `{"items":[{"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK"}]}`,
			wantCount:  1,
			wantBanner: "HTTP/1.1 200 OK",
		},
		{
			name:       "字面量 x 转义",
			input:      `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`,
			wantCount:  1,
			wantBanner: "J\x00\x00\x00\n8.0.32\x00",
		},
		{
			name:       "TLS 字面量转义",
			input:      `[{"ip":"1.2.3.19","port":9999,"banner":"\x16\x03\x01\x00\xa5"}]`,
			wantCount:  1,
			wantBanner: "\x16\x03\x01\x00\xa5",
		},
		{
			name:      "空数组",
			input:     `[]`,
			wantCount: 0,
		},
		{
			name:    "非法 JSON",
			input:   `[{"ip":`,
			wantErr: true,
		},
		{
			name:    "对象缺少 items",
			input:   `{"data":[]}`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items, err := UnmarshalItems([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatal("期望返回错误，实际成功")
				}
				return
			}
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if len(items) != tc.wantCount {
				t.Fatalf("条数 = %d, want %d", len(items), tc.wantCount)
			}
			if tc.wantCount > 0 && items[0].Banner != tc.wantBanner {
				t.Fatalf("banner = %q, want %q", items[0].Banner, tc.wantBanner)
			}
		})
	}
}
