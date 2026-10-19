# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# 构建阶段：使用官方 Go 镜像编译静态二进制。
# CGO_ENABLED=0 保证二进制可在 scratch 中运行。
# ---------------------------------------------------------------------------
FROM golang:1.25-alpine AS build

WORKDIR /src

# 先复制依赖清单，充分利用 Docker 层缓存。
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

# ---------------------------------------------------------------------------
# client 运行镜像：scratch + 非 root 用户，无 shell、无包管理器。
# ---------------------------------------------------------------------------
FROM scratch AS client

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/client /client

USER 65532:65532
ENTRYPOINT ["/client"]

# ---------------------------------------------------------------------------
# server 运行镜像：scratch + 非 root 用户，内置默认规则文件。
# 规则文件同时通过 compose 只读挂载，修改规则无需重新构建镜像。
# ---------------------------------------------------------------------------
FROM scratch AS server

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /server
COPY --chown=65532:65532 config/rules.yaml /etc/fp/rules.yaml

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
