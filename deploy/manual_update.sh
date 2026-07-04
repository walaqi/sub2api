#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# manual_update.sh — 更新 sub2api + image-studio（首次安装或增量更新）
#
# 用法: bash manual_update.sh（普通用户运行，需要 sudo 权限时会自动提权）
#
# 行为:
#   1. git pull sub2api, rebuild, restart sub2api.service
#   2. image-studio: 已存在则 pull+rebuild+restart; 不存在则 clone+build+配置+服务
# =============================================================================

# ─── 配置 ───────────────────────────────────────────────────────────────────────
SUB2API_DIR="/opt/sub2api"
SUB2API_REPO="$HOME/app/sub2api"
SUB2API_SERVICE="sub2api"
SUB2API_CONFIG="$SUB2API_DIR/config.yaml"

IMAGE_STUDIO_APP_DIR="$HOME/app/image-studio"
IMAGE_STUDIO_REPO="https://github.com/walaqi/ChatGpt-Image-Studio.git"
IMAGE_STUDIO_SERVICE="image-studio"
IMAGE_STUDIO_PORT=7000

# RSA 密钥对存放位置（母系统侧）
RSA_PRIVATE_KEY="$SUB2API_DIR/data/image_studio_private.pem"
RSA_PUBLIC_KEY="$SUB2API_DIR/data/image_studio_public.pem"

# image-studio 配置持久存储（在 dist/package 之外，build.sh 的 rm -rf 不会波及）。
# 这是 config.toml 的唯一真源，每次更新后再部署进 dist/package/data。
IMAGE_STUDIO_CONFIG_STORE="$HOME/app/image-studio-config"
CANONICAL_CONFIG="$IMAGE_STUDIO_CONFIG_STORE/config.toml"

# ─── 辅助函数 ─────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; exit 1; }

require_cmd() {
    command -v "$1" &>/dev/null || error "缺少依赖: $1，请先安装"
}

generate_secret() {
    openssl rand -hex 32
}

# 从 sub2api config.yaml 读取字段值（简易 YAML 取值，适用于顶层或 image_studio 块下的扁平键）
# 注：config.yaml 可能仅 root 可读，使用 sudo grep
read_yaml_field() {
    local file="$1" field="$2"
    local line
    line=$(sudo grep -E "^[[:space:]]+${field}:" "$file" 2>/dev/null | head -1) || true
    [ -z "$line" ] && return 0
    echo "$line" | sed 's/.*:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/' | xargs
}

# 从 TOML 文件读取扁平键值（key = "value" 或 key = value），去引号与行内注释
read_toml_field() {
    local file="$1" field="$2"
    [ -f "$file" ] || return 0
    local line
    line=$(grep -E "^[[:space:]]*${field}[[:space:]]*=" "$file" 2>/dev/null | head -1) || true
    [ -z "$line" ] && return 0
    echo "$line" | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*#.*$//; s/^"//; s/"$//' | xargs
}

# 判断 config.toml 是否包含所有必填的多租户字段（非空）。返回 0=完整，1=缺失/不完整。
config_is_complete() {
    local file="$1"
    [ -f "$file" ] || return 1
    local secret endpoint gateway session pubkey
    secret=$(read_toml_field "$file" "internal_secret")
    endpoint=$(read_toml_field "$file" "endpoint_base")
    gateway=$(read_toml_field "$file" "gateway_base_url")
    session=$(read_toml_field "$file" "session_secret")
    pubkey=$(read_toml_field "$file" "jwt_public_key_path")
    [ -n "$secret" ] && [ -n "$endpoint" ] && [ -n "$gateway" ] \
        && [ -n "$session" ] && [ -n "$pubkey" ]
}

# 生成持久 config.toml（唯一真源，位于 dist/package 之外）。
# 保留已有 session_secret（避免使现有会话失效）；从母系统 config.yaml 读取 internal_secret / port。
generate_canonical_config() {
    # 1. 确保母系统侧 RSA 密钥对存在，并导出公钥
    if [ ! -f "$RSA_PRIVATE_KEY" ]; then
        info "生成 RSA 密钥对..."
        sudo mkdir -p "$(dirname "$RSA_PRIVATE_KEY")"
        sudo openssl genpkey -algorithm RSA -out "$RSA_PRIVATE_KEY" -pkeyopt rsa_keygen_bits:2048
        sudo openssl rsa -in "$RSA_PRIVATE_KEY" -pubout -out "$RSA_PUBLIC_KEY"
        sudo chmod 600 "$RSA_PRIVATE_KEY"
        info "RSA 密钥对已生成: $RSA_PRIVATE_KEY / $RSA_PUBLIC_KEY"
    else
        info "RSA 私钥已存在，导出公钥..."
        sudo openssl rsa -in "$RSA_PRIVATE_KEY" -pubout -out "$RSA_PUBLIC_KEY" 2>/dev/null
    fi

    # 2. internal_secret：从母系统 config.yaml 读取，缺失/过短则生成并提示写回
    local internal_secret=""
    if [ -f "$SUB2API_CONFIG" ]; then
        internal_secret=$(read_yaml_field "$SUB2API_CONFIG" "internal_secret")
    fi
    if [ -z "$internal_secret" ] || [ ${#internal_secret} -lt 32 ]; then
        internal_secret=$(generate_secret)
        warn "母系统 config.yaml 中 image_studio.internal_secret 为空或过短"
        warn "已生成新 secret: $internal_secret"
        warn "请手动将此值写入 $SUB2API_CONFIG 的 image_studio.internal_secret 字段并重启 sub2api"
    fi

    # 3. 端口 / 基址
    local sub2api_port endpoint_base gateway_base_url
    sub2api_port=$(read_yaml_field "$SUB2API_CONFIG" "port")
    sub2api_port="${sub2api_port:-8080}"
    endpoint_base="http://127.0.0.1:${sub2api_port}"
    gateway_base_url="${endpoint_base}/v1"

    # 4. session_secret：保留已有真源里的值，否则新生成
    local session_secret=""
    session_secret=$(read_toml_field "$CANONICAL_CONFIG" "session_secret")
    if [ -z "$session_secret" ]; then
        session_secret=$(generate_secret)
    fi

    mkdir -p "$IMAGE_STUDIO_CONFIG_STORE"
    cat > "$CANONICAL_CONFIG" << EOF
[app]
name = "chatgpt2api-studio"
api_key = ""
auth_key = ""
image_format = "url"
max_upload_size_mb = 50

[server]
host = "0.0.0.0"
port = ${IMAGE_STUDIO_PORT}
static_dir = "static"
public_base_path = "/image-studio"
max_image_concurrency = 8
image_queue_limit = 32
image_queue_timeout_seconds = 20
image_task_queue_ttl_seconds = 600

[chatgpt]
model = "gpt-image-2"
sse_timeout = 600
poll_interval = 3
poll_max_wait = 600
request_timeout = 120
image_mode = "cpa"

[storage]
backend = "current"
config_backend = "file"
image_dir = "data/tmp/image"
image_storage = "server"
image_conversation_storage = "server"
image_data_storage = "server"
sqlite_path = "data/chatgpt-image-studio.db"

[cpa]
base_url = ""
api_key = ""
request_timeout = 3000
route_strategy = "codex_responses"
responses_context_max_turns = 5
responses_context_max_bytes = 8388608

[identity]
jwt_public_key_path = "data/image_studio_public.pem"
jwt_issuer = "sub2api"
jwt_audience = "image-studio"
session_secret = "${session_secret}"
session_ttl_seconds = 3600

[credential]
endpoint_base = "${endpoint_base}"
internal_secret = "${internal_secret}"
cache_ttl_seconds = 60
gateway_base_url = "${gateway_base_url}"
request_timeout = 20

[log]
log_all_requests = false
EOF
    info "已生成持久 config.toml: $CANONICAL_CONFIG"
}

# 确保持久 config.toml 存在且完整；否则从母系统配置重新生成。
# 兼容旧部署：真源缺失但 dist/package 内已有完整配置时，先迁移进真源。
ensure_canonical_config() {
    mkdir -p "$IMAGE_STUDIO_CONFIG_STORE"
    local pkg_config="$IMAGE_STUDIO_APP_DIR/dist/package/data/config.toml"
    if [ ! -f "$CANONICAL_CONFIG" ] && config_is_complete "$pkg_config"; then
        info "从现有 dist/package 迁移 config.toml 到持久存储..."
        cp "$pkg_config" "$CANONICAL_CONFIG"
    fi

    if config_is_complete "$CANONICAL_CONFIG"; then
        info "持久 config.toml 完整，保留现有配置。"
        return 0
    fi

    warn "持久 config.toml 缺失或不完整，重新生成..."
    generate_canonical_config
}

# 把真源 config.toml 与 RSA 公钥部署进 dist/package/data，并做部署后校验。
# 校验失败直接 error 退出，避免静默上线空配置导致登录跳转循环。
deploy_config_to_package() {
    local pkg_data="$IMAGE_STUDIO_APP_DIR/dist/package/data"
    mkdir -p "$pkg_data"

    if [ -f "$RSA_PUBLIC_KEY" ]; then
        sudo cp "$RSA_PUBLIC_KEY" "$pkg_data/image_studio_public.pem"
        sudo chown "$(id -u):$(id -g)" "$pkg_data/image_studio_public.pem"
    fi

    cp "$CANONICAL_CONFIG" "$pkg_data/config.toml"

    if ! config_is_complete "$pkg_data/config.toml"; then
        error "部署后 config.toml 仍缺少必填字段，image-studio 会陷入登录跳转循环；请检查 $CANONICAL_CONFIG"
    fi
    if [ ! -f "$pkg_data/image_studio_public.pem" ]; then
        error "缺少 RSA 公钥 $pkg_data/image_studio_public.pem，image-studio 无法验证入口票据"
    fi
    info "config.toml 与 RSA 公钥已部署并通过校验 ✓"
}

# ─── 前置检查 ─────────────────────────────────────────────────────────────────
require_cmd git
require_cmd go
require_cmd pnpm
require_cmd openssl
require_cmd sudo

# =============================================================================
# 第一部分: 更新 sub2api
# =============================================================================
info "── 更新 sub2api ──"

if [ -d "$SUB2API_REPO" ]; then
    info "拉取 sub2api 最新代码..."
    git -C "$SUB2API_REPO" pull --ff-only
else
    warn "未找到源码目录 $SUB2API_REPO，跳过 git pull"
    warn "（如需从源码构建，请确保 $SUB2API_REPO 存在）"
fi

if [ -d "$SUB2API_REPO/backend" ]; then
    # 先构建前端（输出到 backend/internal/web/dist/）
    if [ -d "$SUB2API_REPO/frontend" ]; then
        info "构建前端..."
        cd "$SUB2API_REPO/frontend"
        pnpm install --frozen-lockfile
        pnpm build
    fi

    # 再构建后端（-tags embed 将前端嵌入二进制）
    info "构建 sub2api 后端..."
    cd "$SUB2API_REPO/backend"
    sudo rm -f "$SUB2API_DIR/sub2api"
    CGO_ENABLED=0 go build -tags embed -o /tmp/sub2api_build ./cmd/server/
    sudo mv /tmp/sub2api_build "$SUB2API_DIR/sub2api"
fi

# sudo: 重启系统服务
info "重启 $SUB2API_SERVICE..."
sudo systemctl restart "$SUB2API_SERVICE"
sudo systemctl is-active --quiet "$SUB2API_SERVICE" && info "sub2api 运行中 ✓" || warn "sub2api 启动可能有问题，请检查 journalctl -u $SUB2API_SERVICE"

# =============================================================================
# 第二部分: image-studio
# =============================================================================
info ""
info "── 处理 image-studio ──"

IMAGE_STUDIO_EXISTS=false
if [ -d "$IMAGE_STUDIO_APP_DIR/.git" ]; then
    IMAGE_STUDIO_EXISTS=true
fi

if [ "$IMAGE_STUDIO_EXISTS" = true ]; then
    # ─── 已存在：pull + rebuild + 从持久真源重新部署配置 + restart ────────────
    info "image-studio 已存在，拉取更新..."
    git -C "$IMAGE_STUDIO_APP_DIR" pull --ff-only

    # 确保持久 config.toml 存在且完整（build.sh 会 rm -rf dist/package，
    # 因此真源必须放在 dist/package 之外；旧部署会自动迁移进真源）。
    ensure_canonical_config

    info "重新构建 image-studio..."
    cd "$IMAGE_STUDIO_APP_DIR"
    bash scripts/build.sh

    # 从持久真源重新部署 config.toml 与 RSA 公钥，并做部署后校验（失败即退出）。
    deploy_config_to_package

    # sudo: 重启系统服务
    info "重启 $IMAGE_STUDIO_SERVICE..."
    sudo systemctl restart "$IMAGE_STUDIO_SERVICE"
    sudo systemctl is-active --quiet "$IMAGE_STUDIO_SERVICE" && info "image-studio 运行中 ✓" || warn "image-studio 可能未正常启动"
else
    # ─── 首次安装：clone + build + 配置 + systemd ────────────────────────────
    info "image-studio 不存在，开始首次安装..."

    # Clone
    mkdir -p "$(dirname "$IMAGE_STUDIO_APP_DIR")"
    git clone "$IMAGE_STUDIO_REPO" "$IMAGE_STUDIO_APP_DIR"

    # Build
    info "构建 image-studio..."
    cd "$IMAGE_STUDIO_APP_DIR"
    bash scripts/build.sh

    # ─── 生成持久配置真源 + 部署进 dist/package ──────────────────────────────
    info "配置密钥与 config.toml..."

    # 生成/迁移持久真源（RSA 密钥、internal_secret、session_secret 等都在此处理）
    ensure_canonical_config

    # 从真源部署 config.toml 与公钥进 dist/package/data，并做部署后校验
    deploy_config_to_package

    PACKAGE_DIR="$IMAGE_STUDIO_APP_DIR/dist/package"

    # 供安装摘要输出使用
    INTERNAL_SECRET=$(read_toml_field "$CANONICAL_CONFIG" "internal_secret")

    # ─── 创建 systemd 服务 — sudo: 写入 /etc/systemd/system/ ─────────────────
    info "创建 systemd 服务..."
    sudo tee /etc/systemd/system/${IMAGE_STUDIO_SERVICE}.service > /dev/null << EOF
[Unit]
Description=ChatGPT Image Studio
After=network.target ${SUB2API_SERVICE}.service
Wants=${SUB2API_SERVICE}.service

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${PACKAGE_DIR}
ExecStart=${PACKAGE_DIR}/chatgpt-image-studio
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${IMAGE_STUDIO_SERVICE}

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$IMAGE_STUDIO_SERVICE"
    sudo systemctl start "$IMAGE_STUDIO_SERVICE"
    sudo systemctl is-active --quiet "$IMAGE_STUDIO_SERVICE" && info "image-studio 服务已启动 ✓" || warn "image-studio 启动可能有问题"

    # ─── 输出摘要 ──────────────────────────────────────────────────────────────
    echo ""
    info "═══════════════════════════════════════════════════════════════"
    info " image-studio 首次安装完成"
    info "═══════════════════════════════════════════════════════════════"
    info " 应用目录:     $PACKAGE_DIR"
    info " 配置真源:     $CANONICAL_CONFIG"
    info " 运行时配置:   $PACKAGE_DIR/data/config.toml"
    info " 公钥位置:     $PACKAGE_DIR/data/image_studio_public.pem"
    info " 服务名:       $IMAGE_STUDIO_SERVICE"
    info " 监听端口:     $IMAGE_STUDIO_PORT"
    info ""
    info " 母系统侧须确认:"
    info "   1. config.yaml image_studio.enabled = true"
    info "   2. config.yaml image_studio.internal_secret = ${INTERNAL_SECRET}"
    info "   3. config.yaml image_studio.jwt_private_key_file = ${RSA_PRIVATE_KEY}"
    info "   4. 后台至少一个分组: 平台=OpenAI, allow_image_generation=true, 账号映射含 gpt-image-*"
    info "   5. 确认后重启: sudo systemctl restart $SUB2API_SERVICE"
    info "   6. nginx 配置请参考 deploy/site-nginx.conf 手动配置"
    info "═══════════════════════════════════════════════════════════════"
fi

info ""
info "更新完成。"
