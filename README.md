# DNS Forwarder 部署包

## 目录结构
```
dns_forwarder_package/
├── dns_forwarder_v2.py    # Python DNS 转发器（纯标准库，无依赖）
├── dns-forwarder.service  # systemd 服务文件
├── deploy.sh              # 一键部署脚本
└── README.md              # 本文件
```

## 部署到新机器（另一台 UOS）
1. 把整个 `dns_forwarder_package` 文件夹传到目标机器
2. 修改 `deploy.sh` 里的 `PASSWORD` 为目标机器的 sudo 密码
3. 运行：
```bash
sudo bash deploy.sh
```
4. 把目标机器的系统 DNS 指向 `127.0.0.1`

## 依赖
- Python 3（标准库即可，无 pip 依赖）
- systemd
- dig（可选，用于测试）

## 自定义域名
编辑 `dns_forwarder_v2.py`，修改顶部的 `CUSTOM` 字典：
```python
CUSTOM = {
    'your.domain.com': '192.168.1.100',
    # 添加更多...
}
```
改完后 `sudo systemctl restart dns-forwarder`

## 自定义上游 DNS
编辑 `dns_forwarder_v2.py`，修改顶部的 `UPSTREAM` 变量：
```python
UPSTREAM = '192.168.0.1'
```
改完后 `sudo systemctl restart dns-forwarder`

## 服务管理
```bash
# 查看状态
sudo systemctl status dns-forwarder

# 重启（修改配置后）
sudo systemctl restart dns-forwarder

# 停止/启动
sudo systemctl stop dns-forwarder
sudo systemctl start dns-forwarder

# 查看日志
sudo journalctl -u dns-forwarder -f
```

## 注意事项
- 脚本监听 `0.0.0.0:53`（所有网卡），局域网其他机器可直接将其设为 DNS
- 监听端口 53/udp，需确保防火墙放行：`sudo ufw allow 53/udp` 或在桌面防火墙设置中开放
- 若仅本机使用，改脚本中 `0.0.0.0` 为 `127.0.0.1` 即可
- 无需公网互联网，依赖内部 DNS 上游
