# 🚀 Linux 端口转发管理工具 - 7种方案一键部署

## 简介

一款功能强大的 Bash 脚本工具，支持 7 种主流端口转发方案，提供自动化部署、性能优化和完善的服务管理功能。无论是游戏服务器、Web 应用还是加密代理，都能轻松搞定！

---

## ✨ 核心特性

- 🎯 **7种转发方案**：iptables、HAProxy、socat、gost、realm、rinetd、nginx
- ⚡ **自动性能优化**：BBR、TCP Fast Open、256MB缓冲区
- 🔧 **一键部署**：自动安装依赖、配置服务
- 📊 **Web管理**：HAProxy统计页面、gost API
- 🛡️ **配置备份**：自动备份，一键恢复
- 📝 **完整日志**：实时日志查看
- 🔄 **服务管理**：启动、停止、查看状态

---

## 📋 方案对比

| 方案 | 延迟 | 适用场景 | 特点 |
|:----:|:----:|:---------|:-----|
| **iptables** | ~0.01ms | 游戏/RDP/VNC | 内核级，性能最强 |
| **HAProxy** | ~0.1ms | Web/负载均衡 | Web统计界面 |
| **socat** | ~0.2ms | 通用TCP | 轻量简单 |
| **gost** | ~1-3ms | 加密代理 | 多协议支持 |
| **realm** | ~0.1-0.5ms | 高并发 | Rust编写 |
| **rinetd** | ~0.2ms | 多端口 | 简单可靠 |
| **nginx** | ~0.1ms | Web/SSL | 极高稳定性 |

---

## 📥 快速安装

### 一键安装（推荐）

```bash
wget -O port_forward.sh https://raw.githubusercontent.com/YOUR_USERNAME/linux-port-forward/main/port_forward.sh && chmod +x port_forward.sh && sudo ./port_forward.sh
```

### 分步安装

```bash
# 下载脚本
wget https://raw.githubusercontent.com/YOUR_USERNAME/linux-port-forward/main/port_forward.sh

# 添加执行权限
chmod +x port_forward.sh

# 运行（需要root权限）
sudo ./port_forward.sh
```

---

## 📖 功能菜单

```
1) 配置新的端口转发    - 创建转发规则
2) 查看当前转发状态    - 查看服务状态和配置
3) 查看运行日志        - 实时日志监控
4) 停止转发服务        - 停止服务
5) 卸载转发服务        - 完全卸载
6) 恢复原始配置        - 从备份恢复
7) 启动转发服务        - 启动已配置服务
8) 清理备份文件        - 管理历史备份
9) 退出
```

---

## 🎯 使用示例

### 场景1：游戏服务器（Minecraft）

```bash
目标IP: 192.168.1.100
目标端口: 25565
本地端口: 25565
方案: 1 (iptables)

✅ 延迟最低，性能最佳
```

### 场景2：Web服务转发

```bash
目标IP: example.com
目标端口: 80
本地端口: 8080
方案: 2 (HAProxy)
启用Web统计: y

✅ 支持负载均衡、实时统计
访问统计页面: http://服务器IP:8888/haproxy-stats
```

### 场景3：加密代理

```bash
目标IP: proxy.example.com
目标端口: 443
本地端口: 8443
方案: 4 (gost)
启用API: y

✅ 支持多协议、API管理
API地址: http://服务器IP:9999/api
```

---

## ⚡ 性能优化

脚本自动应用以下优化：

```bash
✅ BBR拥塞控制         - 吞吐量提升30-50%
✅ TCP Fast Open       - 握手延迟降低33%
✅ 256MB缓冲区         - 大文件传输提升20-40%
✅ 早期重传机制        - 丢包恢复加快50%
✅ 连接跟踪优化        - 支持百万并发
✅ 禁用延迟ACK         - 立即确认，降低延迟
✅ 快速回收重用        - 提升连接复用
```

---

## 🔧 常用管理命令

### 查看状态

```bash
# 查看服务状态
systemctl status haproxy
systemctl status port-forward
systemctl status gost-forward

# 查看端口监听
ss -tlnp | grep 端口

# 查看iptables规则
iptables -t nat -L -n -v
```

### 查看日志

```bash
# 实时日志
journalctl -u 服务名 -f

# 最近50条日志
journalctl -u 服务名 -n 50

# 查看连接
cat /proc/net/nf_conntrack | grep 目标IP
```

### 测试连接

```bash
# 测试端口
telnet 服务器IP 端口
nc -zv 服务器IP 端口

# 检查BBR
sysctl net.ipv4.tcp_congestion_control
```

---

## 🛡️ 配置备份

### 自动备份

- 📁 **备份位置**：`/root/.port_forward_backups/`
- 🕐 **备份时机**：每次配置时自动备份
- 📋 **备份内容**：系统参数、iptables规则、配置信息

### 恢复配置

```bash
sudo ./port_forward.sh
# 选择 6) 恢复原始配置
# 选择备份编号恢复
```

### 清理备份（新功能）

```bash
sudo ./port_forward.sh
# 选择 8) 清理备份文件
```

**清理选项：**
- 保留最近 5/10/20 个备份
- 删除所有备份
- 手动选择删除（支持多选）

**建议：** 定期清理旧备份，建议保留 5-10 个即可

---

## 📊 Web管理界面

### HAProxy统计页面

- 📍 **地址**：`http://服务器IP:8888/haproxy-stats`
- 📊 **功能**：实时连接、流量监控、健康状态
- 🔑 **凭据**：`/root/haproxy_credentials.txt`

### gost Web API

- 📍 **地址**：`http://服务器IP:9999/api`
- 🔌 **功能**：RESTful API、动态配置
- 🔑 **凭据**：`/root/gost_credentials.txt`

---

## 🚨 故障排查

### 端口未监听

```bash
# 检查服务
systemctl status 服务名

# 检查端口占用
ss -tlnp | grep 端口

# 查看日志
journalctl -u 服务名 -n 50
```

### 连接超时

```bash
# 测试目标
telnet 目标IP 目标端口

# 检查IP转发
cat /proc/sys/net/ipv4/ip_forward  # 应为1

# 查看iptables
iptables -t nat -L -n -v
```

### iptables 启动后不生效

```bash
# 问题：启动提示成功但没运行
# 原因：restore 命令执行失败

# 脚本已修复（自动）：
# 1. 先清理现有规则
# 2. 使用正确的 restore 命令
# 3. 验证规则是否生效

# 手动验证：
iptables -t nat -L PREROUTING -n | grep DNAT
```

### 本地无法访问

```bash
# 脚本已自动修复本地回环问题
# 验证OUTPUT链规则
iptables -t nat -L OUTPUT -n -v

# 测试本地访问
telnet 127.0.0.1 端口
```

### 备份文件过多

```bash
# 使用清理功能
sudo ./port_forward.sh
# 选择 8) 清理备份文件
# 选择 1) 保留最近5个备份

# 手动清理
cd /root/.port_forward_backups/
ls -t | tail -n +6 | xargs rm -rf
```

---

## ⚠️ 注意事项

1. **权限**：必须使用 root 权限运行
2. **端口**：确保监听端口未被占用
3. **防火墙**：放行相关端口
4. **系统**：支持 Debian/Ubuntu/CentOS/RHEL
5. **备份**：重要配置自动备份，可随时恢复

---

## 🗑️ 卸载

```bash
sudo ./port_forward.sh
# 选择 5) 卸载转发服务
# 选择 8) 卸载所有服务

# 完全清理（包括备份）
sudo rm -rf /root/.port_forward_backups
```

---

## 🎯 系统要求

- **操作系统**：Debian 9+、Ubuntu 18.04+、CentOS 7+、RHEL 7+
- **权限**：root
- **内核**：建议 4.9+（BBR支持）

---

## 💡 性能建议

| 场景 | 推荐方案 | 理由 |
|:-----|:---------|:-----|
| 游戏服务器 | iptables | 延迟最低 ~0.01ms |
| Web应用 | HAProxy/nginx | 功能丰富、稳定 |
| 流媒体 | realm | 高并发、Rust编写 |
| 加密需求 | gost | 多协议、加密传输 |
| 简单转发 | socat | 轻量、配置简单 |

---

## 📄 开源协议

MIT License

---

## 🔗 相关链接

- 📖 **详细文档**：[README.md](https://github.com/YOUR_USERNAME/linux-port-forward)
- 🐛 **问题反馈**：[GitHub Issues](https://github.com/YOUR_USERNAME/linux-port-forward/issues)
- 💬 **讨论交流**：[Discussions](https://github.com/YOUR_USERNAME/linux-port-forward/discussions)

---

## 🌟 总结

这个工具的优势在于：

✅ **简单易用**：一键安装、自动配置、无需手动操作
✅ **功能全面**：7种方案覆盖所有场景
✅ **性能优化**：自动应用BBR等优化
✅ **管理便捷**：Web界面、日志查看、配置备份
✅ **安全可靠**：自动备份、一键恢复

如果这个项目对你有帮助，欢迎 ⭐ Star 支持！

---

**最后更新：** 2024-12-09
