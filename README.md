# 🚀 Linux 端口转发管理工具

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.linux.org/)

一款功能强大的 Linux 端口转发管理工具，支持 **7 种主流转发方案**，提供自动化部署、性能优化和完善的服务管理功能。无论是游戏服务器、Web 应用还是加密代理，都能轻松搞定！

---

## ✨ 核心特性

### 🎯 多方案支持
- **7 种转发方案**：iptables、HAProxy、socat、gost、realm、rinetd、nginx stream
- **智能推荐**：根据使用场景自动推荐最优方案
- **灵活切换**：支持随时更换转发方案

### ⚡ 性能优化
- **BBR 拥塞控制**：提升网络吞吐量 30-50%
- **TCP Fast Open**：减少握手延迟
- **256MB 缓冲区**：大流量传输优化
- **早期重传机制**：快速恢复丢包
- **连接跟踪优化**：支持百万级并发连接

### 🔧 自动化管理
- **一键部署**：自动安装依赖、配置服务、启用优化
- **服务管理**：启动、停止、查看状态、查看日志
- **配置备份**：自动备份配置，支持一键恢复
- **智能检测**：自动检测系统环境和服务状态

### 📊 Web 管理界面
- **HAProxy 统计页面**：实时监控连接、流量、健康状态
- **gost Web API**：RESTful API 动态管理配置
- **安全凭据管理**：随机密码生成，安全存储

### 🛡️ 安全可靠
- **配置备份**：每次修改自动备份到 `/root/.port_forward_backups/`
- **回滚支持**：可恢复到任意历史配置
- **权限检查**：严格的 root 权限验证
- **错误处理**：完善的错误提示和容错机制

---

## 📋 转发方案对比

| 方案 | 延迟 | 性能 | 适用场景 | 特点 |
|:----:|:----:|:----:|:---------|:-----|
| **iptables DNAT** | ⭐⭐⭐⭐⭐<br>~0.01ms | ⭐⭐⭐⭐⭐ | 游戏服务器<br>RDP/VNC<br>SSH转发 | • 内核级转发，性能最强<br>• 延迟最低<br>• 支持本地回环 |
| **HAProxy** | ⭐⭐⭐⭐<br>~0.1ms | ⭐⭐⭐⭐ | Web 服务<br>HTTP(S)<br>负载均衡 | • 功能最丰富<br>• Web 统计界面<br>• 健康检查 |
| **socat** | ⭐⭐⭐⭐<br>~0.2ms | ⭐⭐⭐⭐ | 通用 TCP<br>简单转发 | • 轻量级<br>• 配置简单<br>• 稳定可靠 |
| **gost** | ⭐⭐⭐<br>~1-3ms | ⭐⭐⭐ | 加密代理<br>多协议<br>复杂场景 | • 支持多种协议<br>• 加密传输<br>• Web API 管理 |
| **realm** | ⭐⭐⭐⭐<br>~0.1-0.5ms | ⭐⭐⭐⭐ | 高并发<br>流媒体<br>大流量 | • Rust 编写<br>• 内存安全<br>• 高性能 |
| **rinetd** | ⭐⭐⭐⭐<br>~0.2ms | ⭐⭐⭐⭐ | 多端口转发<br>批量转发 | • 简单可靠<br>• 支持多端口<br>• 资源占用低 |
| **nginx stream** | ⭐⭐⭐⭐<br>~0.1ms | ⭐⭐⭐⭐ | Web 场景<br>SSL/TLS<br>反向代理 | • 稳定性极高<br>• SSL 支持<br>• 状态页面 |

---

## 🔧 系统要求

### 支持的操作系统
- ✅ Debian 9/10/11/12
- ✅ Ubuntu 18.04/20.04/22.04/24.04
- ✅ CentOS 7/8/9
- ✅ RHEL 7/8/9
- ✅ Rocky Linux 8/9
- ✅ AlmaLinux 8/9

### 权限要求
- **必须使用 root 权限运行**

### 依赖项（自动安装）
根据选择的方案自动安装所需依赖：
- `iptables` / `iptables-legacy`
- `haproxy` (方案2)
- `socat` (方案3)
- `gost` (方案4，自动下载最新版)
- `realm` (方案5，自动下载最新版)
- `rinetd` (方案6)
- `nginx` (方案7)

---

## 📥 快速开始

### 方法1：一键安装（推荐）⭐

```bash
wget -O port_forward.sh https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh && chmod +x port_forward.sh && sudo ./port_forward.sh
```

### 方法2：分步安装

```bash
# 1. 下载脚本
wget https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh

# 2. 添加执行权限
chmod +x port_forward.sh

# 3. 运行脚本（需要 root 权限）
sudo ./port_forward.sh
```

### 方法3：curl 安装

```bash
curl -fsSL https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh -o port_forward.sh && chmod +x port_forward.sh && sudo ./port_forward.sh
```

> **💡 提示**：脚本需要交互式输入，不支持通过管道直接运行。

---

## 📖 使用指南

### 主菜单功能

```
========================================
        端口转发管理工具
==========================================
请选择操作：
1) 配置新的端口转发    - 创建新的转发规则
2) 查看当前转发状态    - 查看运行中的服务和详细配置
3) 查看运行日志        - 实时查看各服务日志
4) 停止转发服务        - 停止指定或所有服务
5) 卸载转发服务        - 完全卸载服务和配置
6) 恢复原始配置        - 从备份恢复系统配置
7) 启动转发服务        - 启动已配置的服务
8) 清理备份文件        - 管理和清理历史备份
9) 退出                - 退出管理工具
```

### 详细功能说明

#### 1️⃣ 配置新的端口转发

**步骤：**
1. 输入目标服务器 IP/域名
2. 输入目标端口
3. 输入本地监听端口
4. 选择转发方案（1-7）
5. 根据方案选择是否启用 Web 管理界面
6. 确认配置并自动部署

**示例配置：**

<details>
<summary>游戏服务器转发（Minecraft）</summary>

```bash
目标服务器IP: 192.168.1.100
目标端口: 25565
本地监听端口: 25565
转发方案: 1 (iptables DNAT)

✅ 优势：延迟最低，性能最佳
```
</details>

<details>
<summary>Web 服务转发</summary>

```bash
目标服务器IP: example.com
目标端口: 80
本地监听端口: 8080
转发方案: 2 (HAProxy)
启用Web统计页面: y

✅ 优势：支持负载均衡、健康检查、实时统计
```
</details>

<details>
<summary>加密代理</summary>

```bash
目标服务器IP: proxy.example.com
目标端口: 443
本地监听端口: 8443
转发方案: 4 (gost)
启用Web API: y

✅ 优势：支持多种协议、加密传输、API 管理
```
</details>

#### 2️⃣ 查看当前转发状态

**显示内容：**
- ✅ 运行中的服务列表及监听端口
- ✅ iptables DNAT 规则数量
- ✅ 配置备份信息（数量、最近备份详情）
- ✅ Web 管理凭据文件位置
- ✅ 当前监听的端口列表
- ✅ 系统配置（IP转发、BBR状态）

**示例输出：**
```
===========================================
      当前转发服务状态
===========================================

=== 服务运行状态 ===
✅ haproxy 运行中
   监听端口: 8080 8888
✅ iptables DNAT 规则活跃
   规则数量: 3 条
共 2 个服务正在运行

=== 配置信息 ===
配置备份: 5 个备份
最近备份:
  备份时间: 2024-12-09 09:30:15
  转发方案: 方案2
  目标地址: 192.168.1.100:80
  本地端口: 8080

HAProxy 管理界面: /root/haproxy_credentials.txt

=== 当前监听端口 ===
  0.0.0.0:8080   haproxy
  0.0.0.0:8888   haproxy

=== 系统配置 ===
IP转发: 已启用
BBR拥塞控制: 已启用
```

#### 3️⃣ 查看运行日志

**支持查看的日志：**
1. iptables 规则和连接状态
2. HAProxy 日志
3. socat 日志
4. gost 日志
5. realm 日志
6. rinetd 日志
7. nginx stream 日志
8. 系统网络日志
0. 返回主菜单

**日志功能：**
- 实时跟踪日志（Ctrl+C 退出）
- 连接统计信息
- 错误排查

#### 4️⃣ 停止转发服务

**停止选项：**
1. 停止 iptables DNAT 规则（清理所有NAT规则）
2. 停止 HAProxy
3. 停止 socat
4. 停止 gost
5. 停止 realm
6. 停止 rinetd
7. 停止 nginx
8. 停止所有服务（包括清理iptables规则）
0. 返回主菜单

**注意：**
- 停止服务不会删除配置文件
- IP转发功能仍保持启用（避免影响其他服务）

#### 5️⃣ 卸载转发服务

**卸载选项：**
1. 卸载 iptables DNAT 规则
2. 卸载 HAProxy（保留软件包）
3. 卸载 socat 转发服务
4. 卸载 gost（删除二进制文件）
5. 卸载 realm（删除二进制文件）
6. 卸载 rinetd（保留软件包）
7. 卸载 nginx stream 配置
8. 卸载所有服务
0. 返回主菜单

**卸载内容：**
- systemd 服务文件
- 配置文件
- 凭据文件
- 二进制文件（gost、realm）

**保留内容：**
- 配置备份（在 `/root/.port_forward_backups/`）
- 系统内核参数优化

#### 6️⃣ 恢复原始配置

**功能：**
- 列出最近 10 个备份
- 显示每个备份的详细信息
- 选择备份编号进行恢复

**恢复内容：**
- 系统内核参数（`/etc/sysctl.conf`）
- iptables 规则

#### 7️⃣ 启动转发服务

**启动选项：**
1. 启动 iptables DNAT 规则（从备份恢复）
2. 启动 HAProxy
3. 启动 socat
4. 启动 gost
5. 启动 realm
6. 启动 rinetd
7. 启动 nginx
8. 启动所有已配置服务
0. 返回主菜单

**特点：**
- ✅ 自动检测服务是否已配置
- ✅ iptables 自动从最新备份恢复
- ✅ 自动清理旧规则后再恢复
- ✅ 验证规则是否生效
- ✅ 显示启动成功/失败状态
- ✅ 统计启动的服务数量

**iptables 启动流程：**
1. 先清理现有的 DNAT 和 MASQUERADE 规则
2. 使用正确的 restore 命令恢复备份
3. 确保 IP 转发已启用
4. 验证规则是否生效
5. 显示验证结果

#### 8️⃣ 清理备份文件

**清理选项：**
1. 保留最近 5 个备份，删除其他
2. 保留最近 10 个备份，删除其他
3. 保留最近 20 个备份，删除其他
4. 删除所有备份
5. 手动选择删除
0. 返回主菜单

**功能特点：**
- ✅ 显示当前备份数量
- ✅ 批量清理旧备份
- ✅ 手动选择特定备份删除
- ✅ 显示备份详细信息（时间、大小、配置）
- ✅ 多个备份可一次性删除（如：1 3 5）
- ✅ 删除前二次确认（全部删除时）

**备份管理建议：**
- 定期清理旧备份，节省磁盘空间
- 建议保留 5-10 个最近备份
- 重要配置可手动备份到其他位置

---

## 🎯 性能优化详解

### 自动应用的内核优化

```bash
# BBR 拥塞控制（提升吞吐量 30-50%）
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Fast Open（减少握手延迟）
net.ipv4.tcp_fastopen = 3

# 早期重传和瘦流优化
net.ipv4.tcp_early_retrans = 1
net.ipv4.tcp_thin_dupack = 1
net.ipv4.tcp_thin_linear_timeouts = 1

# 低延迟模式
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# 禁用延迟ACK
net.ipv4.tcp_delack_min = 1

# 优化缓冲区（256MB）
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = "8192 262144 268435456"
net.ipv4.tcp_wmem = "8192 262144 268435456"

# 网络队列优化
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535

# 连接跟踪优化（支持百万连接）
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

# DNAT 性能优化
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# TCP 保活优化
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3

# 快速回收和重用
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
```

### 性能提升效果

| 优化项 | 提升效果 | 适用场景 |
|:------|:--------|:---------|
| BBR 拥塞控制 | 吞吐量 +30-50% | 高延迟网络 |
| TCP Fast Open | 延迟 -33% | HTTP 短连接 |
| 256MB 缓冲区 | 大文件传输 +20-40% | 大流量传输 |
| 连接跟踪优化 | 并发连接数 10x | 高并发场景 |
| 快速重传 | 丢包恢复 -50% | 不稳定网络 |

---

## 📊 Web 管理界面

### HAProxy 统计页面

**访问地址：** `http://服务器IP:8888/haproxy-stats`

**功能特性：**
- 📈 实时连接统计
- ✅ 服务器健康状态
- 📊 流量监控（请求数、字节数）
- 🔄 后端服务器管理
- ⏱️ 响应时间统计
- 🚦 状态码分布

**凭据位置：** `/root/haproxy_credentials.txt`

**示例凭据文件：**
```
HAProxy Web管理界面
访问地址: http://192.168.1.10:8888/haproxy-stats
用户名: admin
密码: Xy9#mK2@pL5$qR8^
配置时间: 2024-12-09 09:30:15
```

### gost Web API

**访问地址：** `http://服务器IP:9999/api`

**API 功能：**
- 🔌 RESTful API 接口
- ⚙️ 动态配置管理
- 📊 服务状态查询
- 🔄 运行时配置修改

**凭据位置：** `/root/gost_credentials.txt`

**API 使用示例：**
```bash
# 获取配置
curl -u admin:password http://服务器IP:9999/api/config

# 查看服务状态
curl -u admin:password http://服务器IP:9999/api/services
```

---

## 🛡️ 备份与恢复

### 自动备份机制

**备份时机：**
- ✅ 每次配置新转发时
- ✅ 修改系统参数前

**备份位置：** `/root/.port_forward_backups/`

**备份内容：**
```
/root/.port_forward_backups/
├── 20241209_093015/
│   ├── backup_info.txt          # 备份信息
│   ├── sysctl.conf              # 系统内核参数
│   ├── iptables_backup.txt      # 原始iptables规则
│   └── iptables_current.txt     # 当前iptables规则
├── 20241208_150230/
└── 20241207_103045/
```

**备份信息示例：**
```
备份时间: 2024-12-09 09:30:15
转发方案: 方案2
目标地址: 192.168.1.100:80
本地端口: 8080
```

### 恢复配置

1. 运行脚本选择 `6) 恢复原始配置`
2. 查看备份列表（显示最近10个）
3. 输入备份编号
4. 自动恢复配置并应用

---

## 🔧 管理命令参考

### iptables 方案

```bash
# 查看 NAT 规则
iptables -t nat -L -n -v --line-numbers

# 查看 PREROUTING 链
iptables -t nat -L PREROUTING -n -v

# 查看 POSTROUTING 链
iptables -t nat -L POSTROUTING -n -v

# 查看连接跟踪
cat /proc/net/nf_conntrack | grep 目标IP

# 统计连接数
cat /proc/net/nf_conntrack | wc -l

# 检查 IP 转发
cat /proc/sys/net/ipv4/ip_forward

# 检查反向路径过滤
cat /proc/sys/net/ipv4/conf/all/rp_filter
```

### systemd 服务管理

```bash
# 查看服务状态
systemctl status haproxy
systemctl status port-forward
systemctl status gost-forward
systemctl status realm-forward
systemctl status rinetd
systemctl status nginx

# 启动/停止/重启服务
systemctl start 服务名
systemctl stop 服务名
systemctl restart 服务名

# 查看实时日志
journalctl -u 服务名 -f

# 查看最近50条日志
journalctl -u 服务名 -n 50

# 查看服务配置
systemctl cat 服务名
```

### 端口和连接检查

```bash
# 检查端口监听
ss -tlnp | grep 端口
netstat -tlnp | grep 端口

# 检查所有监听端口
ss -tlnp

# 查看活跃连接
ss -tn | grep ESTAB

# 测试端口连通性
telnet 目标IP 端口
nc -zv 目标IP 端口

# 检查路由
ip route
traceroute 目标IP
```

### BBR 和内核参数

```bash
# 查看当前拥塞控制算法
sysctl net.ipv4.tcp_congestion_control

# 查看可用算法
sysctl net.ipv4.tcp_available_congestion_control

# 查看所有TCP相关参数
sysctl -a | grep tcp

# 重新加载配置
sysctl -p
```

---

## 🚨 故障排查

### 问题1：端口未监听

**症状：** 无法访问转发端口

**排查步骤：**
```bash
# 1. 检查服务状态
systemctl status 服务名

# 2. 查看服务日志
journalctl -u 服务名 -n 50

# 3. 检查端口占用
ss -tlnp | grep 端口

# 4. 检查防火墙
iptables -L -n | grep 端口
firewall-cmd --list-all  # CentOS/RHEL

# 5. 测试端口
telnet 127.0.0.1 端口
```

**解决方案：**
- 确保服务正常运行
- 检查端口是否被其他程序占用
- 放行防火墙规则
- 检查配置文件语法

### 问题2：连接超时

**症状：** 可以连接到转发端口，但无法连接到目标服务器

**排查步骤：**
```bash
# 1. 测试目标服务器连通性
ping 目标IP
telnet 目标IP 目标端口

# 2. 检查路由
traceroute 目标IP
ip route

# 3. 检查 iptables 规则
iptables -t nat -L -n -v

# 4. 检查 IP 转发
cat /proc/sys/net/ipv4/ip_forward  # 应该为 1

# 5. 查看连接跟踪
cat /proc/net/nf_conntrack | grep 目标IP
```

**解决方案：**
- 确保目标服务器可访问
- 启用 IP 转发：`echo 1 > /proc/sys/net/ipv4/ip_forward`
- 检查 iptables 规则是否正确
- 检查目标服务器防火墙

### 问题3：iptables 启动后没有生效

**症状：** 执行启动命令提示成功，但查看状态显示没有运行

**原因：** iptables-restore 命令未正确执行

**解决方案（脚本已修复）：**
```bash
# 1. 使用正确的 restore 命令
if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
    RESTORE_CMD="iptables-legacy-restore"
else
    RESTORE_CMD="iptables-restore"
fi

# 2. 先清理现有规则
iptables -t nat -S | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
    iptables -t nat $rule
done

# 3. 恢复备份规则
iptables-restore < /root/.port_forward_backups/最近备份/iptables_current.txt

# 4. 验证规则
iptables -t nat -L PREROUTING -n | grep DNAT
```

**验证步骤：**
```bash
# 查看 NAT 规则
iptables -t nat -L -n -v

# 应该能看到 DNAT 规则
# 如果没有，说明恢复失败，需要重新配置
```

### 问题4：iptables DNAT 本地回环问题

**症状：** 外部可以访问，但服务器本地无法访问转发端口

**原因：** 本地访问需要额外的 OUTPUT 链规则

**脚本已自动修复：**
```bash
# 自动添加的本地回环规则
iptables -t nat -A OUTPUT -p tcp --dport 本地端口 -d 本地IP -j DNAT --to-destination 目标IP:目标端口
iptables -t nat -A OUTPUT -p tcp --dport 本地端口 -d 127.0.0.1 -j DNAT --to-destination 目标IP:目标端口
```

**手动验证：**
```bash
# 检查 OUTPUT 链
iptables -t nat -L OUTPUT -n -v

# 测试本地访问
telnet 127.0.0.1 本地端口
telnet 本地IP 本地端口
```

### 问题5：备份文件过多占用空间

**症状：** 备份目录占用磁盘空间过大

**查看备份：**
```bash
# 查看备份数量
ls /root/.port_forward_backups/ | wc -l

# 查看备份大小
du -sh /root/.port_forward_backups/
```

**清理备份：**
```bash
# 使用脚本清理（推荐）
sudo ./port_forward.sh
# 选择 8) 清理备份文件

# 手动清理旧备份
cd /root/.port_forward_backups/
ls -t | tail -n +6 | xargs rm -rf  # 保留最近5个
```

### 问题6：HAProxy/gost 启动失败

**症状：** 服务无法启动

**排查步骤：**
```bash
# 查看详细错误
systemctl status 服务名 -l
journalctl -u 服务名 -xe

# 测试配置文件
haproxy -c -f /etc/haproxy/haproxy.cfg  # HAProxy
gost -C /etc/gost/config.yaml           # gost

# 检查端口占用
ss -tlnp | grep 端口
```

**常见原因：**
- 配置文件语法错误
- 端口已被占用
- 权限不足
- 依赖缺失

### 问题7：性能不佳

**症状：** 转发速度慢、延迟高

**优化检查：**
```bash
# 1. 检查 BBR 是否启用
sysctl net.ipv4.tcp_congestion_control  # 应该为 bbr

# 2. 检查 TCP Fast Open
sysctl net.ipv4.tcp_fastopen  # 应该为 3

# 3. 检查缓冲区大小
sysctl net.core.rmem_max
sysctl net.core.wmem_max

# 4. 查看网络统计
ss -s

# 5. 检查连接跟踪表
cat /proc/sys/net/netfilter/nf_conntrack_max
cat /proc/net/nf_conntrack | wc -l
```

**优化建议：**
- 选择延迟更低的方案（iptables > realm > HAProxy）
- 调整缓冲区大小
- 优化网络质量
- 升级服务器配置

---

## 🗑️ 完全卸载

### 卸载单个服务

```bash
sudo ./port_forward.sh
# 选择 5) 卸载转发服务
# 选择要卸载的服务编号
```

### 卸载所有服务

```bash
sudo ./port_forward.sh
# 选择 5) 卸载转发服务
# 选择 8) 卸载所有服务
```

### 手动清理

如果需要完全清理（包括备份）：

```bash
# 卸载所有服务
sudo ./port_forward.sh  # 选择 5 -> 8

# 删除备份目录
sudo rm -rf /root/.port_forward_backups

# 删除脚本
rm -f port_forward.sh

# 恢复内核参数（可选）
# 编辑 /etc/sysctl.conf，删除脚本添加的参数
# 然后执行：
sudo sysctl -p
```

---

## ⚠️ 注意事项

### 安全建议

1. **🔐 保护 Web 管理界面**
   - 修改默认密码
   - 限制访问 IP（使用防火墙）
   - 使用 HTTPS（nginx 反向代理）

2. **🛡️ 防火墙配置**
   ```bash
   # 放行转发端口
   iptables -I INPUT -p tcp --dport 端口 -j ACCEPT
   
   # 限制管理端口访问
   iptables -I INPUT -p tcp --dport 8888 -s 信任IP -j ACCEPT
   iptables -A INPUT -p tcp --dport 8888 -j DROP
   ```

3. **💾 定期备份**
   - 配置备份自动保存在 `/root/.port_forward_backups/`
   - 建议定期手动备份重要配置

### 性能建议

1. **选择合适的方案**
   - 游戏/RDP → iptables
   - Web 服务 → HAProxy/nginx
   - 加密需求 → gost
   - 高并发 → realm

2. **系统资源**
   - iptables：几乎无资源占用
   - 用户态服务：根据流量占用 50-200MB 内存

3. **网络优化**
   - 确保 BBR 启用
   - 调整 MTU 值避免分片
   - 优化 TCP 窗口大小

### 兼容性说明

1. **nftables vs iptables**
   - 脚本自动检测并优先使用 `iptables-legacy`
   - 避免 nftables 兼容性问题

2. **systemd 版本**
   - 需要 systemd 作为 init 系统
   - 不支持 SysVinit

3. **内核版本**
   - BBR 需要 Linux 4.9+
   - TCP Fast Open 需要 Linux 3.7+
   - 建议使用 4.19+ 内核

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

### 报告问题

- 提供系统信息（OS、内核版本）
- 描述问题现象和复现步骤
- 附上相关日志

### 提交代码

1. Fork 本仓库
2. 创建特性分支
3. 提交更改
4. 发起 Pull Request

---

## 📄 开源协议

MIT License - 详见 [LICENSE](LICENSE) 文件

---

## 📞 技术支持

- 🐛 **问题反馈**：[GitHub Issues](https://github.com/YOUR_USERNAME/linux-port-forward/issues)
- 📖 **详细文档**：[Wiki](https://github.com/YOUR_USERNAME/linux-port-forward/wiki)
- 💬 **讨论交流**：[Discussions](https://github.com/YOUR_USERNAME/linux-port-forward/discussions)

---

## 🌟 Star History

如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！

[![Star History Chart](https://api.star-history.com/svg?repos=YOUR_USERNAME/linux-port-forward&type=Date)](https://star-history.com/#YOUR_USERNAME/linux-port-forward&Date)

---

## 📊 项目统计

![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/linux-port-forward?style=social)
![GitHub forks](https://img.shields.io/github/forks/YOUR_USERNAME/linux-port-forward?style=social)
![GitHub issues](https://img.shields.io/github/issues/YOUR_USERNAME/linux-port-forward)
![GitHub license](https://img.shields.io/github/license/YOUR_USERNAME/linux-port-forward)

---

**最后更新：** 2025-12-09
