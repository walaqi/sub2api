#!/bin/bash
set -e

# ============ 配置 ============
INSTALL_DIR="/opt/sub2api"
CONFIG_DIR="/etc/sub2api"
SERVICE_USER="sub2api"
BINARY="${1:-./sub2api}"

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

echo "安装二进制: $BINARY"

# ============ 创建系统用户 ============
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/sh -d "$INSTALL_DIR" "$SERVICE_USER"
    echo "用户 $SERVICE_USER 已创建"
fi

# ============ 安装文件 ============
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data" "$CONFIG_DIR"
cp "$BINARY" "$INSTALL_DIR/sub2api"
chmod +x "$INSTALL_DIR/sub2api"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR"

# ============ 安装 systemd 服务 ============
cat > /etc/systemd/system/sub2api.service << EOF
[Unit]
Description=Sub2API - AI API Gateway Platform
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=sub2api
Group=sub2api
WorkingDirectory=/opt/sub2api
ExecStart=/opt/sub2api/sub2api
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sub2api

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/sub2api

Environment=GIN_MODE=release

[Install]
WantedBy=multi-user.target
EOF

# ============ 启动服务 ============
systemctl daemon-reload
systemctl enable sub2api
systemctl start sub2api

echo ""
echo "=============================="
echo " Sub2API 安装完成"
echo "=============================="
echo " 配置文件: $CONFIG_DIR/config.yaml"
echo " 设置向导: http://$(hostname -I | awk '{print $1}'):<config.yaml 中的端口>"
echo ""
echo " 常用命令:"
echo "   systemctl status sub2api"
echo "   journalctl -u sub2api -f"
echo "   systemctl restart sub2api"
echo "=============================="
