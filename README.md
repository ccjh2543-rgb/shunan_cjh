# Banner 指纹识别系统

基于 Golang 的 Banner 指纹识别系统，采用 client + server 架构，通过 Docker Compose 一键启动。
输入一批网络扫描原始数据（`ip`、`port`、`banner`），输出协议、产品、版本、操作系统线索与置信度。

- 规则与代码完全解耦：识别规则存放在 `config/rules.yaml`，新增协议无需改代码、无需重新编译镜像。
- 识别失败不会报错：无法识别的数据统一返回 `protocol: "unknown"`，服务不会因脏数据崩溃。
- 生产级部署：多阶段构建、静态二进制、scratch 运行、非 root、只读根文件系统、能力裁剪、内部网络、真实健康检查。

## 快速开始

```bash
docker compose up --build
```

启动后：

- `server` 监听宿主机 `127.0.0.1:8080`（默认只绑定回环地址）。
- `client` 等待 `server` 健康检查通过后，自动读取 `data/sample.json` 并输出识别结果，随后退出。

查看客户端结果：

```bash
docker compose logs client
```

只启动服务端：

```bash
docker compose up -d server
curl -s http://127.0.0.1:8080/health
```

停止并清理：

```bash
docker compose down
```

> 说明：`client` 是一次性任务（`restart: "no"`），执行完即退出，这是预期行为；
> `server` 会持续运行，直到执行 `docker compose down`。

## 接口

所有接口统一响应包装，业务成功时 `code = 0`：

```json
{ "code": 0, "message": "ok", "data": {} }
```

### POST /fingerprint

批量识别。请求体支持两种形式：

1. 裸数组：`[{"ip":"...","port":22,"banner":"..."}]`
2. 包装对象：`{"items":[{"ip":"...","port":22,"banner":"..."}]}`

同时兼容扫描工具常见的字面量 `\xNN` 转义（JSON 标准不支持，但原始扫描数据经常出现）。

请求示例：

```bash
curl -s -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  -d '[
    {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
    {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
    {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
  ]'
```

响应示例：

```json
{
  "code": 0,
  "message": "ok",
  "data": [
    {
      "ip": "1.2.3.4",
      "port": 22,
      "protocol": "SSH",
      "product": "OpenSSH",
      "version": "8.9p1",
      "os_hint": "Ubuntu",
      "confidence": 0.95
    },
    {
      "ip": "1.2.3.5",
      "port": 80,
      "protocol": "HTTP",
      "product": "nginx",
      "version": "1.24.0",
      "os_hint": "",
      "confidence": 0.9
    },
    {
      "ip": "1.2.3.23",
      "port": 12345,
      "protocol": "unknown",
      "product": "",
      "version": "",
      "os_hint": "",
      "confidence": 0.2
    }
  ]
}
```

输出顺序与请求顺序严格一致。无法识别的条目返回 `protocol: "unknown"`，不会导致整个请求失败。

错误码：

| HTTP | code  | 含义 |
| ---- | ----- | ---- |
| 400  | 40001 | 请求体为空或 JSON 非法 |
| 400  | 40002 | 单批条数超过 `MAX_BATCH` |
| 413  | 41301 | 请求体超过 32 MiB |
| 500  | 50001 | 服务内部错误（已做 panic 兜底） |

### GET /health

返回服务状态、运行版本、已加载规则数量与运行时长，供容器健康检查使用：

```json
{
  "code": 0,
  "message": "ok",
  "data": { "status": "ok", "version": "dev", "rules": 13, "uptime_seconds": 12 }
}
```

## Client 用法

`client` 是独立程序，可在容器内使用，也可单独编译运行。

```bash
# 读取本地 JSON，调用 server，以表格形式输出
./client -file data/sample.json -server http://127.0.0.1:8080

# 输出 JSON 数组（结构与题目示例一致）
./client -file data/sample.json -server http://127.0.0.1:8080 -json

# 结果写入文件
./client -file data/sample.json -server http://127.0.0.1:8080 -json -out result.json
```

| 参数 | 环境变量 | 默认值 | 说明 |
| ---- | -------- | ------ | ---- |
| `-file` | - | 无（必填） | 输入 JSON 文件路径 |
| `-server` | `SERVER_URL` | `http://127.0.0.1:8080` | server 地址 |
| `-json` | - | `false` | 输出 JSON 数组而非表格 |
| `-out` | - | 标准输出 | 结果输出文件 |
| `-timeout` | `CLIENT_TIMEOUT` | `60s` | 整体请求超时 |
| `-batch` | `CLIENT_BATCH_SIZE` | `500` | 单次请求条数 |

使用自有验收数据：

```bash
# 方式一：替换 data/sample.json 后重新启动 client
docker compose run --rm client -file /data/your_data.json

# 方式二：直接调用 HTTP 接口
curl -s -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' --data-binary @your_data.json
```

## 识别能力

内置规则见 `config/rules.yaml`：

| 协议 | 产品 | 识别依据 |
| ---- | ---- | -------- |
| SSH | OpenSSH 及其他 SSH 实现 | `SSH-<协议版本>-<产品>_<版本>` |
| HTTP | nginx、Apache、Jetty、Microsoft-IIS 等 | 状态行 + `Server` 头 |
| MySQL | MySQL、MariaDB | 握手包：3 字节包长 + 序号 + `0x0a` + 版本号 |
| Redis | Redis | `PONG`、`-ERR`、`-NOAUTH`、`INFO` 中的 `redis_version` |
| FTP | ProFTPD、vsFTPd、Pure-FTPd | `220` 欢迎语 |
| TLS | - | TLS Handshake 记录头 `0x16 0x03 0x00~0x04` |
| SMTP | - | `220 ... SMTP/ESMTP`（用于与 FTP 的 220 欢迎语区分） |

操作系统线索：Ubuntu、Debian、CentOS、Red Hat、Rocky Linux、FreeBSD、Raspbian、Windows。

示例数据自测结果：20 条中 19 条正确识别，1 条（`QUIT`）按预期返回 `unknown`。

## 规则配置

规则与程序代码解耦，全部位于 `config/rules.yaml`，启动时编译校验，配置错误会直接启动失败而不是带病运行。

```yaml
rules:
  - name: ssh                    # 规则名，仅用于排障
    protocol: SSH                # 命中后输出的协议
    product: OpenSSH             # 产品默认值
    confidence: 0.95             # 置信度，必须在 (0,1]
    priority: 100                # 越大越先匹配
    require:                     # 前置条件，必须全部命中
      - '...'
    patterns:                    # 按顺序尝试，首个命中生效
      - '(?m)^SSH-...(?P<version>...)...'
```

- 命名捕获组 `product`、`version`、`os_hint` 会覆盖规则中的默认值。
- `require` 用于收窄误报，例如 HTTP 产品规则要求同时出现状态行与 `Server` 头。
- `priority` 让产品级规则优先于协议级兜底规则（例如 `ProFTPD` 优先于通用 `220`）。
- `os_hints` 按配置顺序匹配，命中即返回。

修改规则后重启 `server` 即可生效，无需重新构建镜像：

```bash
docker compose restart server
```

## 工程结构

严格按 DDD 分层，依赖方向由外向内，`domain` 不依赖任何外部包：

```text
cmd/
  server/                      # 服务端入口（含 healthcheck 子命令）
  client/                      # 客户端入口
internal/
  domain/                      # 领域层：实体、规则模型、识别引擎、仓储接口
  application/                 # 应用层：批量识别编排、并发控制、顺序保证
  infrastructure/
    rules/                     # YAML 规则仓库（实现 domain.RuleRepository）
    scanjson/                  # 扫描数据解析（兼容 \xNN 与包装对象）
    httpclient/                # server 的 HTTP 客户端
  interfaces/
    httpapi/                   # HTTP 接口层：路由、校验、统一响应、中间件
    cli/                       # 客户端表格 / JSON 渲染
config/rules.yaml              # 指纹规则
data/sample.json               # 自测数据
```

关键设计：

- `domain.Engine` 为纯内存计算，正则只在启动时编译一次，可安全并发调用。
- `application.FingerprintService` 使用固定 worker 池并发识别，结果按下标写回，输出顺序与输入一致。
- 错误处理显式：所有 `error` 均被处理；`scanjson` 中的 `_ = file.Close()` 等忽略仅限关闭只读文件句柄。
- 服务端设置读写超时、请求体上限、批量上限、panic 恢复与访问日志。

## 部署与安全设计

- **多阶段构建**：`golang:1.25-alpine` 编译，`CGO_ENABLED=0` 生成静态二进制；先复制 `go.mod/go.sum` 下载依赖，充分利用层缓存。
- **最小运行镜像**：`scratch` 作为运行镜像，无 shell、无包管理器，仅包含二进制与 CA 证书。
- **非 root 运行**：固定 `65532:65532`，`cap_drop: ALL`，`no-new-privileges:true`。
- **只读文件系统**：`read_only: true`，仅挂载必要的只读规则与数据目录。
- **资源限制**：`pids_limit`、`mem_limit`、`cpus`，防止单容器耗尽宿主机资源。
- **网络收敛**：`backend` 为 `internal` 网络，`client` 只能通过 `http://server:8080` 访问服务端，不能访问外网；对外端口默认只绑定 `127.0.0.1`。
- **真实健康检查**：镜像内无 shell/curl，`server` 二进制自带 `healthcheck` 子命令，请求本机 `/health` 并校验业务状态；`client` 通过 `depends_on.condition: service_healthy` 等待服务就绪。
- **规则解耦**：规则通过只读卷挂载，修改后重启容器即可生效。
- **日志**：结构化 JSON 日志，配置轮转（`max-size`/`max-file`）。

## 本地开发与测试

依赖 Go 1.25+。

```bash
# 运行全部单元测试
go test ./... -count=1

# 本地启动服务端
go run ./cmd/server -addr :8080 -rules config/rules.yaml

# 本地运行客户端
go run ./cmd/client -file data/sample.json -server http://127.0.0.1:8080 -json
```

测试覆盖：

- 示例数据的表驱动回归（每条协议的产品、版本、系统线索、置信度）。
- 脏数据与空数据不会 panic、协议不为空。
- JSON 输入格式（裸数组、`items` 包装、`\xNN` 转义、空数组、非法 JSON）。
- HTTP 接口（正常识别、unknown、批量上限、非法 JSON、健康检查、方法不允许）。

## 配置项

| 环境变量 | 默认值 | 说明 |
| -------- | ------ | ---- |
| `ADDR` | `:8080` | server 监听地址 |
| `RULES_FILE` | `config/rules.yaml` | 规则文件路径 |
| `WORKERS` | `8` | 识别并发度 |
| `MAX_BATCH` | `10000` | 单次请求最大条数 |
| `SERVER_PORT` | `8080` | 宿主机映射端口 |
| `BIND_ADDR` | `127.0.0.1` | 宿主机绑定地址，远程访问时设为 `0.0.0.0` |
| `APP_VERSION` | `dev` | 镜像标签与 `/health` 中显示的版本 |

## 已知边界

- TLS 只能识别为 `TLS` 协议，无法从握手包中提取产品与版本（握手包不含明文产品信息）。
- 无版本号的 Banner 会返回空 `version`，这是符合预期的结果，不会伪造成版本号。
- 未命中任何规则时返回 `protocol: "unknown"`、低置信度，属于正常业务结果而非错误。
