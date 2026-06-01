#!/bin/bash
set -e

# ============ 配置 ============
# 统一目录：二进制 / config.yaml / 安装锁 / pricing 缓存都在 INSTALL_DIR 下。
INSTALL_DIR="/opt/sub2api"
DATA_DIR="$INSTALL_DIR"          # DATA_DIR：决定 config.yaml 与 .installed 的位置
SERVICE_USER="sub2api"
BINARY="${1:-./sub2api}"
LOG_FILE="$INSTALL_DIR/data/logs/sub2api.log"

CONFIG_FILE="$DATA_DIR/config.yaml"
LOCK_FILE="$DATA_DIR/.installed"
SETUP_LOG="/tmp/sub2api-setup.log"

# ============ 检查 root ============
if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 权限运行: sudo bash $0 [binary_path]"
    exit 1
fi

# ============ 检查二进制文件 ============
if [ ! -f "$BINARY" ]; then
    echo "找不到二进制文件: $BINARY"
    echo "用法: sudo bash $0 /path/to/sub2api"
    exit 1
fi
BINARY="$(readlink -f "$BINARY")"
echo "安装二进制: $BINARY"

# ============ 创建系统用户 ============
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/sh -d "$INSTALL_DIR" "$SERVICE_USER"
    echo "用户 $SERVICE_USER 已创建"
fi

# ============ 安装文件 ============
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data"
cp "$BINARY" "$INSTALL_DIR/sub2api"
chmod +x "$INSTALL_DIR/sub2api"

# 日志目录（位于 INSTALL_DIR 下，持久且在 ReadWritePaths 覆盖内）
mkdir -p "$(dirname "$LOG_FILE")"

# ============ 首次安装：采集配置 + 自动建库/建管理员 ============
# 说明：常驻服务路径不会跑数据库迁移、也不会创建管理员，这些只发生在 AUTO_SETUP。
#       一旦 config.yaml 存在，程序会判定无需 setup，因此初始化必须在写出 config 之前完成。
if [ -f "$CONFIG_FILE" ] || [ -f "$LOCK_FILE" ]; then
    echo "检测到已存在配置（$CONFIG_FILE）或安装锁，跳过初始化向导。"
else
    echo ""
    echo "── 首次安装配置 ──"

    read -rp  "PostgreSQL 主机 [localhost]: " DB_HOST;     DB_HOST="${DB_HOST:-localhost}"
    read -rp  "PostgreSQL 端口 [5432]: "      DB_PORT;     DB_PORT="${DB_PORT:-5432}"
    read -rp  "PostgreSQL 用户 [postgres]: "  DB_USER;     DB_USER="${DB_USER:-postgres}"
    read -rsp "PostgreSQL 密码: "             DB_PASSWORD; echo
    read -rp  "数据库名 [sub2api]: "          DB_NAME;     DB_NAME="${DB_NAME:-sub2api}"
    read -rp  "SSL 模式 [disable]: "          DB_SSLMODE;  DB_SSLMODE="${DB_SSLMODE:-disable}"

    read -rp  "Redis 主机 [localhost]: "      REDIS_HOST;  REDIS_HOST="${REDIS_HOST:-localhost}"
    read -rp  "Redis 端口 [6379]: "           REDIS_PORT;  REDIS_PORT="${REDIS_PORT:-6379}"
    read -rsp "Redis 密码（无则回车）: "       REDIS_PASSWORD; echo
    read -rp  "Redis DB [0]: "                REDIS_DB;    REDIS_DB="${REDIS_DB:-0}"

    read -rp  "服务监听端口 [8080]: "         SERVER_PORT; SERVER_PORT="${SERVER_PORT:-8080}"

    ADMIN_EMAIL=""
    while [ -z "$ADMIN_EMAIL" ]; do read -rp "管理员邮箱（必填）: " ADMIN_EMAIL; done
    while :; do
        read -rsp "管理员密码: "      ADMIN_PASSWORD;  echo
        read -rsp "确认管理员密码: "  ADMIN_PASSWORD2; echo
        [ -n "$ADMIN_PASSWORD" ] && [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD2" ] && break
        echo "  密码为空或两次不一致，请重试。"
    done

    # 生成 JWT 密钥（优先 openssl，回退 /dev/urandom）
    if command -v openssl >/dev/null 2>&1; then
        JWT_SECRET="$(openssl rand -hex 32)"
    else
        JWT_SECRET="$(tr -dc 'a-f0-9' </dev/urandom | head -c 64)"
    fi

    echo ""
    echo "正在初始化数据库并创建管理员（AUTO_SETUP）..."

    # AUTO_SETUP 会完成：建库迁移 + 创建管理员 + 写出 config.yaml + 落安装锁，随后进入常驻服务。
    # 这里后台临时启动它，待安装锁出现即说明初始化完成，再优雅停止。secrets 仅存在于本进程环境，
    # 不写入 systemd unit。
    AUTO_SETUP=true \
    DATA_DIR="$DATA_DIR" \
    DATABASE_HOST="$DB_HOST" DATABASE_PORT="$DB_PORT" DATABASE_USER="$DB_USER" \
    DATABASE_PASSWORD="$DB_PASSWORD" DATABASE_DBNAME="$DB_NAME" DATABASE_SSLMODE="$DB_SSLMODE" \
    REDIS_HOST="$REDIS_HOST" REDIS_PORT="$REDIS_PORT" REDIS_PASSWORD="$REDIS_PASSWORD" REDIS_DB="$REDIS_DB" \
    SERVER_HOST="0.0.0.0" SERVER_PORT="$SERVER_PORT" SERVER_MODE="release" \
    JWT_SECRET="$JWT_SECRET" \
    ADMIN_EMAIL="$ADMIN_EMAIL" ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    GIN_MODE=release \
    "$INSTALL_DIR/sub2api" >"$SETUP_LOG" 2>&1 &
    SETUP_PID=$!

    for _ in $(seq 1 60); do
        [ -f "$LOCK_FILE" ] && break
        kill -0 "$SETUP_PID" 2>/dev/null || break   # 进程提前退出（多为初始化失败）
        sleep 1
    done

    # 停止临时进程（优雅关闭）
    kill -TERM "$SETUP_PID" 2>/dev/null || true
    wait "$SETUP_PID" 2>/dev/null || true

    if [ ! -f "$LOCK_FILE" ] || [ ! -f "$CONFIG_FILE" ]; then
        echo "初始化失败，未生成配置/安装锁。最近日志："
        tail -n 30 "$SETUP_LOG" 2>/dev/null || true
        echo "（请检查 PostgreSQL / Redis 连接与凭据后重试）"
        exit 1
    fi
    rm -f "$SETUP_LOG"
    echo "数据库与管理员初始化完成。"
fi

# ============ 写入日志配置到 config.yaml ============
# AUTO_SETUP 写出的 config.yaml 不含 log 段，这里补上，确保日志确定落到 $LOG_FILE。
if [ -f "$CONFIG_FILE" ] && ! grep -qE '^log:' "$CONFIG_FILE"; then
    cat >> "$CONFIG_FILE" << EOF

log:
  output:
    to_stdout: true
    to_file: true
    file_path: "$LOG_FILE"
EOF
    echo "已写入日志配置: $LOG_FILE"
fi

# ============ 统一属主 ============
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# ============ 安装 systemd 服务 ============
cat > /etc/systemd/system/sub2api.service << EOF
[Unit]
Description=Sub2API - AI API Gateway Platform
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/sub2api
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sub2api

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$INSTALL_DIR

Environment=GIN_MODE=release
Environment=DATA_DIR=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

# ============ 启动服务 ============
systemctl daemon-reload
systemctl enable sub2api
systemctl restart sub2api

echo ""
echo "=============================="
echo " Sub2API 安装完成"
echo "=============================="
echo " 安装目录: $INSTALL_DIR"
echo " 配置文件: $CONFIG_FILE"
echo " 日志文件: $LOG_FILE"
echo " 访问地址: http://$(hostname -I | awk '{print $1}'):${SERVER_PORT:-<config.yaml 中的端口>}"
echo ""
echo " 常用命令:"
echo "   systemctl status sub2api"
echo "   journalctl -u sub2api -f"
echo "   systemctl restart sub2api"
echo "=============================="
