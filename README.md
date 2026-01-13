# 端口转发管理工具 (Port Forward Manager)

Linux 端口转发管理工具，支持 8 种转发方案，自动安装依赖和优化网络性能。

## 功能特性

- **8 种转发方案** - nftables / iptables / HAProxy / socat / gost / realm / rinetd / nginx stream
- **IPv4/IPv6 双栈支持** - 可转发到 IPv4 或 IPv6 目标地址，所有方案同时监听双栈
- **多端口配置** - 支持单端口、多端口、端口范围、端口映射
- **多目标累加** - 同一方案可配置多个不同目标，规则不覆盖
- **流量统计** - 所有方案均支持流量统计 (iptables/nftables 内置，其他通过 iptables INPUT 链)
- **自动部署** - 自动安装依赖、配置服务、优化内核
- **实时状态** - 查看所有活跃转发规则和延迟检测
- **配置备份** - 自动备份配置，支持快速恢复
- **国内加速** - 内置多个 GitHub 代理镜像，国内服务器也能顺利安装
- **智能检测** - 自动检测网络环境，纯 IPv6 机器正确显示 IPv6 地址

## 支持系统

| 系统 | 状态 |
|------|------|
| Debian 10/11/12 | ✅ 完全支持 |
| Ubuntu 20.04/22.04/24.04 | ✅ 完全支持 |
| CentOS 7/8 | ⚠️ 基本支持 |

## 安装

### 一键安装 (推荐)

```bash
bash <(curl -sL https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh)
```

### 国内加速安装

如果上面的命令下载缓慢或失败，可以使用以下代理镜像：

```bash
# 方式1: ghproxy 代理
bash <(curl -sL https://ghproxy.com/https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh)

# 方式2: mirror.ghproxy 镜像
bash <(curl -sL https://mirror.ghproxy.com/https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh)

# 方式3: gh.ddlc 代理
bash <(curl -sL https://gh.ddlc.top/https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh)

# 方式4: moeyy 代理
bash <(curl -sL https://github.moeyy.xyz/https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh)

# 方式5: gh-proxy 代理
bash <(curl -sL https://gh-proxy.com/https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh)
```

### 手动安装 (详细步骤)

如果一键安装失败，可以按照以下步骤手动安装：

#### 步骤 1: 下载脚本

**方式 A: 直接下载 (需要能访问 GitHub)**
```bash
wget https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh
```

**方式 B: 使用代理下载 (国内推荐)**
```bash
# 使用 ghproxy 代理
wget https://ghproxy.com/https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh

# 或使用 curl
curl -sL https://ghproxy.com/https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh -o port_forward.sh
```

**方式 C: 从 Release 下载**
1. 访问 https://github.com/Chil30/port-forward/releases
2. 下载最新版本的 `port_forward.sh`
3. 上传到服务器

**方式 D: 本地上传**
1. 在能访问 GitHub 的电脑上下载脚本
2. 使用 SCP/SFTP 上传到服务器：
```bash
scp port_forward.sh root@your-server:/root/
```

#### 步骤 2: 添加执行权限

```bash
chmod +x port_forward.sh
```

#### 步骤 3: 运行脚本

```bash
./port_forward.sh
```

或使用 sudo：
```bash
sudo ./port_forward.sh
```

#### 步骤 4: 安装快捷命令 (可选)

首次运行会自动安装快捷命令 `pf`，之后可以直接使用：
```bash
pf
```

如果快捷命令未自动安装，可以手动创建：
```bash
# 复制脚本到系统目录
cp port_forward.sh /usr/local/bin/port_forward.sh
chmod +x /usr/local/bin/port_forward.sh

# 创建快捷命令
ln -sf /usr/local/bin/port_forward.sh /usr/local/bin/pf
```

### 依赖软件手动安装

如果脚本自动安装依赖失败，可以手动安装：

#### gost 手动安装

```bash
# 方式1: 官方安装脚本 (需要能访问 GitHub)
bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install

# 方式2: 使用代理安装
bash <(curl -fsSL https://ghproxy.com/https://github.com/go-gost/gost/raw/master/install.sh) --install

# 方式3: 手动下载安装
# 访问 https://github.com/go-gost/gost/releases 下载对应版本
# 国内镜像: https://ghproxy.com/https://github.com/go-gost/gost/releases/download/v3.0.0/gost_3.0.0_linux_amd64.tar.gz
wget https://ghproxy.com/https://github.com/go-gost/gost/releases/download/v3.0.0/gost_3.0.0_linux_amd64.tar.gz
tar -xzf gost_3.0.0_linux_amd64.tar.gz
mv gost /usr/local/bin/
chmod +x /usr/local/bin/gost
```

#### realm 手动安装

```bash
# 获取最新版本号
REALM_VERSION=$(curl -s https://api.github.com/repos/zhboner/realm/releases/latest | grep '"tag_name"' | cut -d '"' -f 4)

# 下载 (x86_64 架构)
# 直接下载
wget https://github.com/zhboner/realm/releases/download/${REALM_VERSION}/realm-x86_64-unknown-linux-gnu.tar.gz

# 或使用代理下载
wget https://ghproxy.com/https://github.com/zhboner/realm/releases/download/${REALM_VERSION}/realm-x86_64-unknown-linux-gnu.tar.gz

# 解压安装
tar -xzf realm-x86_64-unknown-linux-gnu.tar.gz
mv realm /usr/local/bin/
chmod +x /usr/local/bin/realm
```

#### 其他依赖 (通过包管理器)

```bash
# Debian/Ubuntu
apt update
apt install -y iptables nftables haproxy socat rinetd nginx

# CentOS/RHEL
yum install -y iptables nftables haproxy socat rinetd nginx
```

首次运行自动安装快捷命令 `pf`。

## 使用方法

### 启动工具

```bash
pf
```

### 主菜单

```
============================================================================
                      端口转发管理工具 v1.0.2
============================================================================
  状态: 运行中    转发规则: 5 条
============================================================================

  1) 配置新的端口转发
  2) 查看当前转发状态
  3) 查看运行日志
  4) 停止/启动转发服务
  5) 查看备份文件
  6) 流量统计
  7) 卸载转发服务
  0) 退出
```

### 端口配置格式

| 格式 | 示例 | 说明 |
|------|------|------|
| 单端口 | `3389` | 本地和目标端口相同 |
| 多端口 | `80,443,8080` | 多个端口，逗号分隔 |
| 端口范围 | `8000-8010` | 连续端口范围 |
| 端口映射 | `33389:3389` | 本地端口:目标端口 |
| 混合格式 | `80,443,8000-8005,33389:3389` | 以上格式组合 |

### 配置示例

**基本配置：**
```
目标服务器IP/域名: 192.168.1.100
端口配置: 3389
请选择方案: 1 (iptables)
```

**多端口配置：**
```
目标服务器IP/域名: 10.0.0.50
端口配置: 80,443,8080-8085
请选择方案: 2 (nftables)
```

**IPv6 目标：**
```
目标服务器IP/域名: 2409:871e:2700:100a:6508:120e:5e:a
端口配置: 3389
请选择方案: 2 (nftables)
```

**多目标配置（多次运行）：**
```bash
# 第一次：配置目标 A
pf → 192.168.1.100 → 80,443

# 第二次：配置目标 B（规则累加）
pf → 10.0.0.50 → 3389

# 结果：
# :80 → 192.168.1.100:80
# :443 → 192.168.1.100:443
# :3389 → 10.0.0.50:3389
```

## 转发方案对比

| 方案 | 延迟 | IPv6 | 流量统计 | 适用场景 |
|------|------|------|----------|----------|
| iptables DNAT | ⭐ 最低 | ✅ (ip6tables) | ✅ 内置 | 游戏/RDP/VNC |
| nftables DNAT | ⭐ 最低 | ✅ | ✅ 内置 | 新系统/高性能 |
| realm | ⭐⭐ 较低 | ✅ | ✅ iptables | 高并发场景 |
| HAProxy | ⭐⭐ 较低 | ✅ | ✅ iptables | Web/负载均衡 |
| nginx stream | ⭐⭐ 较低 | ✅ | ✅ iptables | Web/SSL |
| socat | ⭐⭐ 较低 | ✅ | ✅ iptables | 通用转发 |
| rinetd | ⭐⭐ 较低 | ❌ | ✅ iptables | 多端口转发 |
| gost | ⭐⭐⭐ 中等 | ✅ | ✅ iptables | 加密代理 |

**流量统计说明：**
- 所有方案都支持流量统计
- iptables/nftables 使用内置计数器
- 其他方案通过 iptables INPUT 链统计入站流量
- 菜单选项 6 可查看所有方案的流量统计

**性能排序**: iptables/nftables > realm > HAProxy/nginx > socat/rinetd > gost

**功能排序**: gost > nginx/HAProxy > realm > socat/rinetd > iptables/nftables

## 性能优化

脚本自动应用以下内核优化：

- BBR 拥塞控制算法
- TCP Fast Open
- 256MB 网络缓冲区
- 早期重传机制
- 连接跟踪优化

## 文件位置

| 文件 | 路径 |
|------|------|
| 脚本命令 | `/usr/local/bin/pf` |
| 配置备份 | `/root/.port_forward_backups/` |
| nftables 配置 | `/etc/nftables.d/port_forward.nft` |
| realm 配置 | `/etc/realm/config.toml` |
| gost 配置 | `/etc/gost/config.yaml` |
| HAProxy 配置 | `/etc/haproxy/haproxy.cfg` |
| rinetd 配置 | `/etc/rinetd.conf` |
| nginx stream | `/etc/nginx/stream.d/` |

## 常见问题

**Q: 规则重启后丢失？**

iptables:
```bash
apt install iptables-persistent
netfilter-persistent save
```

nftables:
```bash
systemctl enable nftables
```

**Q: 如何查看转发是否生效？**

1. 菜单选择 `2) 查看当前转发状态`
2. 或使用 `telnet 本机IP 端口` 测试

**Q: 如何完全卸载？**

菜单选择 `7) 卸载转发服务` → `9) 卸载所有服务`

**Q: IPv6 支持哪些方案？**

除了 rinetd 外，所有方案都支持 IPv6 目标地址：
- iptables (使用 ip6tables)
- nftables
- HAProxy
- socat
- gost
- realm
- nginx stream

**Q: 国内服务器下载失败怎么办？**

脚本已内置多个 GitHub 代理镜像，会自动尝试。如果仍然失败：

1. 手动使用代理下载脚本（见上方手动安装部分）
2. 在能访问 GitHub 的电脑下载后上传到服务器
3. 检查服务器 DNS 设置，尝试更换为公共 DNS：
```bash
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 114.114.114.114" >> /etc/resolv.conf
```

**Q: 代理镜像不可用怎么办？**

代理镜像可能会变化，如果内置的镜像都不可用，可以：
1. 搜索 "GitHub 代理" 找到最新可用的代理
2. 手动下载文件后上传到服务器
3. 在 Issues 中反馈，我们会更新镜像列表

## 国内镜像列表

以下是脚本内置的 GitHub 代理镜像，按优先级排序：

| 镜像 | 地址 | 说明 |
|------|------|------|
| ghproxy | https://ghproxy.com/ | 稳定，推荐 |
| mirror.ghproxy | https://mirror.ghproxy.com/ | ghproxy 镜像 |
| gh.ddlc | https://gh.ddlc.top/ | 备用 |
| moeyy | https://github.moeyy.xyz/ | 备用 |
| gh-proxy | https://gh-proxy.com/ | 备用 |

使用方法：在原始 GitHub 链接前加上代理地址即可。

例如：
- 原始: `https://raw.githubusercontent.com/xxx/xxx/main/file.sh`
- 代理: `https://ghproxy.com/https://raw.githubusercontent.com/xxx/xxx/main/file.sh`

## 更新日志

查看 [CHANGELOG.txt](CHANGELOG.txt)

## 许可证

MIT License

## 链接

- GitHub: https://github.com/Chil30/port-forward
- Issues: https://github.com/Chil30/port-forward/issues
