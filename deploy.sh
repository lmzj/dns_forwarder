#!/bin/bash
# DNS Forwarder 一键部署脚本
# 用法: sudo bash deploy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PASSWORD="123123"   # 改成目标机器的 sudo 密码

# 创建目录
echo "[1/6] 创建目录..."
echo $PASSWORD | sudo -S mkdir -p /opt/dns_forwarder

# 复制脚本
echo "[2/6] 复制脚本..."
echo $PASSWORD | sudo -S cp "$SCRIPT_DIR/dns_forwarder_v2.py" /opt/dns_forwarder/
echo $PASSWORD | sudo -S chmod +x /opt/dns_forwarder/dns_forwarder_v2.py

# 停止旧服务（如果存在）
echo "[3/6] 停止旧服务..."
echo $PASSWORD | sudo -S systemctl stop dns-forwarder 2>/dev/null || true
echo $PASSWORD | sudo -S pkill -f dns_forwarder_v2.py 2>/dev/null || true

# 复制 service 文件
echo "[4/6] 安装 systemd 服务..."
echo $PASSWORD | sudo -S cp "$SCRIPT_DIR/dns-forwarder.service" /etc/systemd/system/
echo $PASSWORD | sudo -S systemctl daemon-reload

# 启用并启动
echo "[5/6] 启用并启动服务..."
echo $PASSWORD | sudo -S systemctl enable dns-forwarder
echo $PASSWORD | sudo -S systemctl start dns-forwarder

# 验证
echo "[6/6] 验证..."
sleep 1
echo $PASSWORD | sudo -S systemctl status dns-forwarder --no-pager -l

echo ""
echo "=== 测试解析 ==="
dig @127.0.0.1 cas.zrzy.gz.cegn.cn +short
dig @127.0.0.1 map.zrzy.gz.cegn.cn +short
dig @127.0.0.1 entrygzportal8-vip.yw.zrzy.gz.cegn.cn +short
