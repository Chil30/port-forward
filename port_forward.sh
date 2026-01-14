#!/bin/bash
# ============================================================================
# 端口转发管理工具 v1.0.2
# 支持多种转发方案：iptables/nftables/HAProxy/socat/gost/realm/rinetd/nginx
# 
# 作者: Chli30
# 项目: https://github.com/Chil30/port-forward
# 许可: MIT License
# ============================================================================

# 版本信息
VERSION="1.0.3"
AUTHOR="Chli30"
GITHUB_URL="https://github.com/Chil30/port-forward"

# 流量统计文件
TRAFFIC_STATS_FILE="/var/lib/port-forward/traffic_stats.json"
TRAFFIC_STATS_DIR="/var/lib/port-forward"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# GitHub 代理镜像列表 (国内加速) - 代理优先，直连放最后
GITHUB_MIRRORS=(
    "https://ghproxy.com/"               # ghproxy 代理 (优先)
    "https://mirror.ghproxy.com/"        # ghproxy 镜像
    "https://gh.ddlc.top/"               # ddlc 代理
    "https://github.moeyy.xyz/"          # moeyy 代理
    "https://gh-proxy.com/"              # gh-proxy
    ""                                    # 直连 (最后尝试)
)

# 智能下载函数 - 自动尝试多个镜像源 (wget 优先)
# 用法: smart_download <原始URL> <保存路径> [超时秒数]
# 返回: 0=成功, 1=失败
smart_download() {
    local original_url="$1"
    local output_path="$2"
    local timeout=${3:-15}  # 默认15秒超时
    
    # 检测是否为 GitHub 相关 URL
    local is_github=false
    if [[ "$original_url" =~ github\.com|githubusercontent\.com|github\.io ]]; then
        is_github=true
    fi
    
    # 如果不是 GitHub URL，直接下载
    if [ "$is_github" = false ]; then
        if command -v wget >/dev/null 2>&1; then
            wget -q --timeout="$timeout" -O "$output_path" "$original_url" 2>/dev/null && return 0
        fi
        if command -v curl >/dev/null 2>&1; then
            curl -sL --connect-timeout "$timeout" --max-time 60 -o "$output_path" "$original_url" 2>/dev/null && return 0
        fi
        return 1
    fi
    
    # GitHub URL - 尝试多个镜像源 (代理优先)
    for mirror in "${GITHUB_MIRRORS[@]}"; do
        local download_url
        local try_timeout
        if [ -z "$mirror" ]; then
            # 直连 - 使用更短的超时
            download_url="$original_url"
            try_timeout=8
        else
            # 使用代理镜像
            download_url="${mirror}${original_url}"
            try_timeout="$timeout"
        fi
        
        echo -e "${DIM}尝试: ${download_url}${NC}" >&2
        
        # 清理之前的失败文件
        rm -f "$output_path" 2>/dev/null
        
        # 优先使用 wget 下载
        if command -v wget >/dev/null 2>&1; then
            if wget --timeout="$try_timeout" --tries=1 -q -O "$output_path" "$download_url" 2>/dev/null; then
                # 验证下载是否成功 (文件非空且大于1KB)
                if [ -f "$output_path" ] && [ -s "$output_path" ]; then
                    local fsize=$(stat -c%s "$output_path" 2>/dev/null || stat -f%z "$output_path" 2>/dev/null || echo 0)
                    if [ "$fsize" -gt 1024 ]; then
                        [ -n "$mirror" ] && echo -e "${GREEN}✓ 使用镜像下载成功${NC}" >&2
                        return 0
                    fi
                fi
            fi
        fi
        
        # wget 失败，尝试 curl (带 timeout 命令强制限时)
        rm -f "$output_path" 2>/dev/null
        if command -v curl >/dev/null 2>&1; then
            if timeout $((try_timeout + 10)) curl -sL --connect-timeout "$try_timeout" -o "$output_path" "$download_url" 2>/dev/null; then
                if [ -f "$output_path" ] && [ -s "$output_path" ]; then
                    local fsize=$(stat -c%s "$output_path" 2>/dev/null || stat -f%z "$output_path" 2>/dev/null || echo 0)
                    if [ "$fsize" -gt 1024 ]; then
                        [ -n "$mirror" ] && echo -e "${GREEN}✓ 使用镜像下载成功${NC}" >&2
                        return 0
                    fi
                fi
            fi
        fi
        
        echo -e "${YELLOW}失败，尝试下一个...${NC}" >&2
    done
    
    rm -f "$output_path" 2>/dev/null
    echo -e "${RED}所有下载源均失败${NC}" >&2
    return 1
}

# 智能执行远程脚本 - 自动尝试多个镜像源 (wget 优先)
# 用法: smart_bash_remote <原始URL> [参数...]
# 返回: 脚本执行的返回值
smart_bash_remote() {
    local original_url="$1"
    shift
    local args="$@"
    
    # 检测是否为 GitHub 相关 URL
    local is_github=false
    if [[ "$original_url" =~ github\.com|githubusercontent\.com|github\.io ]]; then
        is_github=true
    fi
    
    # 如果不是 GitHub URL，直接执行 (wget 优先)
    if [ "$is_github" = false ]; then
        if command -v wget >/dev/null 2>&1; then
            bash <(wget -qO- "$original_url") $args && return 0
        elif command -v curl >/dev/null 2>&1; then
            bash <(curl -fsSL "$original_url") $args && return 0
        fi
        return 1
    fi
    
    # GitHub URL - 尝试多个镜像源 (代理优先, wget 优先)
    for mirror in "${GITHUB_MIRRORS[@]}"; do
        local download_url
        local try_timeout
        if [ -z "$mirror" ]; then
            download_url="$original_url"
            try_timeout=8  # 直连用更短超时
        else
            download_url="${mirror}${original_url}"
            try_timeout=15
        fi
        
        echo -e "${DIM}尝试: ${download_url}${NC}" >&2
        
        # wget 优先
        if command -v wget >/dev/null 2>&1; then
            if bash <(wget --timeout="$try_timeout" --tries=1 -qO- "$download_url") $args 2>/dev/null; then
                [ -n "$mirror" ] && echo -e "${GREEN}✓ 使用镜像执行成功${NC}" >&2
                return 0
            fi
        fi
        
        # curl 备用
        if command -v curl >/dev/null 2>&1; then
            if bash <(timeout $((try_timeout + 5)) curl -fsSL --connect-timeout "$try_timeout" "$download_url") $args 2>/dev/null; then
                [ -n "$mirror" ] && echo -e "${GREEN}✓ 使用镜像执行成功${NC}" >&2
                return 0
            fi
        fi
        
        echo -e "${YELLOW}失败，尝试下一个...${NC}" >&2
    done
    
    return 1
}

# 智能获取 API 内容 (wget 优先)
# 用法: smart_api_get <原始URL> [超时秒数]
# 返回: API 响应内容 (stdout)
smart_api_get() {
    local original_url="$1"
    local timeout=${2:-10}  # API 请求超时
    local result=""
    
    # wget 优先
    if command -v wget >/dev/null 2>&1; then
        result=$(wget --timeout="$timeout" --tries=2 -qO- "$original_url" 2>/dev/null)
        if [ -n "$result" ] && [[ "$result" != *"rate limit"* ]] && [[ "$result" == *"tag_name"* || "$result" == *"{"* ]]; then
            echo "$result"
            return
        fi
    fi
    
    # curl 备用
    if command -v curl >/dev/null 2>&1; then
        result=$(curl -s --connect-timeout "$timeout" --max-time $((timeout + 5)) "$original_url" 2>/dev/null)
        if [ -n "$result" ] && [[ "$result" != *"rate limit"* ]]; then
            echo "$result"
            return
        fi
    fi
    
    echo "$result"
}

# 初始化流量统计目录
init_traffic_stats() {
    mkdir -p "$TRAFFIC_STATS_DIR"
    if [ ! -f "$TRAFFIC_STATS_FILE" ]; then
        echo '{"rules":{}}' > "$TRAFFIC_STATS_FILE"
    fi
}

# 获取 nftables 流量统计
get_nft_traffic() {
    local port=$1
    if command -v nft >/dev/null 2>&1; then
        local bytes=$(nft list chain inet port_forward prerouting 2>/dev/null | grep -E "dport $port.*counter" | grep -oE 'bytes [0-9]+' | awk '{print $2}' | head -1)
        echo "${bytes:-0}"
    else
        echo "0"
    fi
}

# 获取 iptables 流量统计
get_iptables_traffic() {
    local port=$1
    local IPTABLES_CMD=$(get_iptables_cmd)
    local bytes=$($IPTABLES_CMD -t nat -L PREROUTING -n -v 2>/dev/null | grep "dpt:$port" | awk '{print $2}' | head -1)
    # 转换为字节数
    if [[ "$bytes" =~ ^[0-9]+$ ]]; then
        echo "$bytes"
    elif [[ "$bytes" =~ ^([0-9.]+)K$ ]]; then
        echo $(echo "${BASH_REMATCH[1]} * 1024" | bc 2>/dev/null || echo "0")
    elif [[ "$bytes" =~ ^([0-9.]+)M$ ]]; then
        echo $(echo "${BASH_REMATCH[1]} * 1048576" | bc 2>/dev/null || echo "0")
    elif [[ "$bytes" =~ ^([0-9.]+)G$ ]]; then
        echo $(echo "${BASH_REMATCH[1]} * 1073741824" | bc 2>/dev/null || echo "0")
    else
        echo "0"
    fi
}

# 格式化流量显示
format_traffic() {
    local bytes=$1
    if [ -z "$bytes" ] || [ "$bytes" = "0" ]; then
        echo "0 B"
        return
    fi
    
    if [ "$bytes" -lt 1024 ]; then
        echo "${bytes} B"
    elif [ "$bytes" -lt 1048576 ]; then
        echo "$(echo "scale=2; $bytes/1024" | bc 2>/dev/null || echo "0") KB"
    elif [ "$bytes" -lt 1073741824 ]; then
        echo "$(echo "scale=2; $bytes/1048576" | bc 2>/dev/null || echo "0") MB"
    else
        echo "$(echo "scale=2; $bytes/1073741824" | bc 2>/dev/null || echo "0") GB"
    fi
}

# 检测本机网络环境
detect_local_network() {
    LOCAL_HAS_IPV4=false
    LOCAL_HAS_IPV6=false
    LOCAL_IPV4=""
    LOCAL_IPV6=""
    LOCAL_IPV4_TYPE=""  # public/private
    LOCAL_IPV6_TYPE=""  # public/private
    
    # 检测 IPv4
    LOCAL_IPV4=$(ip -4 addr show scope global 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1)
    if [ -n "$LOCAL_IPV4" ]; then
        LOCAL_HAS_IPV4=true
        # 判断是否为内网地址
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 (CGNAT)
        if [[ "$LOCAL_IPV4" =~ ^10\. ]] || \
           [[ "$LOCAL_IPV4" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
           [[ "$LOCAL_IPV4" =~ ^192\.168\. ]] || \
           [[ "$LOCAL_IPV4" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
            LOCAL_IPV4_TYPE="private"
        else
            LOCAL_IPV4_TYPE="public"
        fi
    fi
    
    # 检测 IPv6
    LOCAL_IPV6=$(ip -6 addr show scope global 2>/dev/null | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -1)
    if [ -n "$LOCAL_IPV6" ]; then
        LOCAL_HAS_IPV6=true
        # 判断是否为内网地址 (fc00::/7 ULA, fe80::/10 link-local)
        if [[ "$LOCAL_IPV6" =~ ^[fF][cCdD] ]] || [[ "$LOCAL_IPV6" =~ ^[fF][eE][89aAbB] ]]; then
            LOCAL_IPV6_TYPE="private"
        else
            LOCAL_IPV6_TYPE="public"
        fi
    fi
}

# 智能获取本机 IP 地址 (优先公网，无 IPv4 出口时返回 IPv6)
get_local_ip() {
    detect_local_network
    
    # 检测是否有 IPv4 出口
    local has_ipv4_outbound=false
    if ping -4 -c 1 -W 1 8.8.8.8 &>/dev/null 2>&1 || ping -4 -c 1 -W 1 114.114.114.114 &>/dev/null 2>&1; then
        has_ipv4_outbound=true
    fi
    
    # 有 IPv4 出口，返回 IPv4 地址
    if [ "$has_ipv4_outbound" = true ] && [ "$LOCAL_HAS_IPV4" = true ]; then
        echo "$LOCAL_IPV4"
        return
    fi
    
    # 无 IPv4 出口，返回 IPv6 地址
    if [ "$LOCAL_HAS_IPV6" = true ]; then
        echo "$LOCAL_IPV6"
        return
    fi
    
    # 兜底：返回 hostname -I 的第一个地址
    hostname -I 2>/dev/null | awk '{print $1}'
}

# 配置 DNS64 (仅用于无 IPv4 出口的纯 IPv6 环境)
setup_dns64() {
    # 检测 IPv4 出口连通性 (不是检测有没有 IPv4 地址)
    # 尝试 ping 几个常用的 IPv4 地址
    local has_ipv4_outbound=false
    
    for ip in 8.8.8.8 1.1.1.1 114.114.114.114; do
        if ping -4 -c 1 -W 2 "$ip" &>/dev/null 2>&1; then
            has_ipv4_outbound=true
            break
        fi
    done
    
    # 有 IPv4 出口，无需 DNS64
    if [ "$has_ipv4_outbound" = true ]; then
        return 0
    fi
    
    # 检测是否有 IPv6 地址
    if ! ip -6 addr show scope global 2>/dev/null | grep -q "inet6 "; then
        return 0  # 没有 IPv6，也不需要 DNS64
    fi
    
    # 到这里说明是纯 IPv6 环境（无 IPv4 出口），询问用户
    echo -e "${YELLOW}检测到无 IPv4 出口（纯 IPv6 环境）${NC}"
    read -p "是否配置 DNS64 以访问 IPv4 资源? [y/N]: " SETUP_DNS64
    if [[ ! "$SETUP_DNS64" =~ ^[Yy]$ ]]; then
        return 0
    fi
    
    # 备份原有配置
    if [[ -f /etc/resolv.conf ]] && [[ ! -f /etc/resolv.conf.bak ]]; then
        cp /etc/resolv.conf /etc/resolv.conf.bak
        echo -e "${GREEN}已备份原 DNS 配置到 /etc/resolv.conf.bak${NC}"
    fi
    
    # 写入 DNS64 服务器
    cat > /etc/resolv.conf << 'EOF'
nameserver 2a00:1098:2b::1
nameserver 2001:4860:4860::6464
nameserver 2a00:1098:2c::1
EOF
    
    echo -e "${GREEN}DNS64 配置完成${NC}"
}

# 显示本机网络状态
show_network_status() {
    detect_local_network
    
    echo -e "${CYAN}本机网络:${NC}"
    if [ "$LOCAL_HAS_IPV4" = true ]; then
        if [ "$LOCAL_IPV4_TYPE" = "public" ]; then
            echo -e "  IPv4: ${GREEN}$LOCAL_IPV4 (公网)${NC}"
        else
            echo -e "  IPv4: ${YELLOW}$LOCAL_IPV4 (内网)${NC}"
        fi
    else
        echo -e "  IPv4: ${RED}无${NC}"
    fi
    if [ "$LOCAL_HAS_IPV6" = true ]; then
        if [ "$LOCAL_IPV6_TYPE" = "public" ]; then
            echo -e "  IPv6: ${GREEN}$LOCAL_IPV6 (公网)${NC}"
        else
            echo -e "  IPv6: ${YELLOW}$LOCAL_IPV6 (内网)${NC}"
        fi
    else
        echo -e "  IPv6: ${DIM}无${NC}"
    fi
    echo ""
}

# 检测系统使用的防火墙类型
detect_firewall_backend() {
    # 检查是否有 nftables
    if command -v nft >/dev/null 2>&1; then
        # 检查 nftables 是否有规则
        if nft list tables 2>/dev/null | grep -q .; then
            echo "nftables"
            return
        fi
    fi
    
    # 检查 iptables-nft (iptables 使用 nftables 后端)
    if iptables -V 2>/dev/null | grep -q "nf_tables"; then
        echo "iptables-nft"
        return
    fi
    
    # 默认使用 iptables-legacy
    echo "iptables-legacy"
}

# 获取 nft 命令
get_nft_cmd() {
    if command -v nft >/dev/null 2>&1; then
        echo "nft"
    else
        echo ""
    fi
}

# 生成随机密码函数
generate_password() {
    local length=${1:-16}
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c $length
}

# 智能选择 iptables 命令（避免 nftables 兼容性问题）
get_iptables_cmd() {
    if command -v iptables-legacy >/dev/null 2>&1; then
        echo "iptables-legacy"
    else
        echo "iptables"
    fi
}

# 检查 nftables 转发规则是否存在
check_nft_forward_running() {
    if command -v nft >/dev/null 2>&1; then
        if nft list chain inet port_forward prerouting 2>/dev/null | grep -q "dnat"; then
            return 0
        fi
    fi
    return 1
}

# 获取 nftables 转发规则数量
get_nft_forward_count() {
    if command -v nft >/dev/null 2>&1; then
        nft list chain inet port_forward prerouting 2>/dev/null | grep -c "dnat" || echo "0"
    else
        echo "0"
    fi
}

# 检查转发服务是否运行
check_forward_running() {
    local IPTABLES_CMD=$(get_iptables_cmd)
    
    # 检查 nftables DNAT规则
    if check_nft_forward_running; then
        return 0
    fi
    
    # 检查iptables DNAT规则
    if $IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -q DNAT; then
        return 0
    fi
    
    # 检查用户态服务
    for service in haproxy port-forward gost-forward realm-forward rinetd; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            return 0
        fi
    done
    
    # 检查nginx stream配置
    if systemctl is-active nginx >/dev/null 2>&1; then
        if [ -d /etc/nginx/stream.d ] && ls /etc/nginx/stream.d/port-forward-*.conf >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    return 1
}

# 获取当前转发规则数量
get_forward_count() {
    local count=0
    local IPTABLES_CMD=$(get_iptables_cmd)
    
    # nftables DNAT规则数
    local nft_count=$(get_nft_forward_count | tr -d '[:space:]' | sed 's/^0*//' | grep -E '^[0-9]+$' || echo "")
    [ -z "$nft_count" ] && nft_count=0
    count=$((count + nft_count))
    
    # iptables DNAT规则数
    local dnat_count=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -c DNAT 2>/dev/null | tr -d '[:space:]' | sed 's/^0*//' | grep -E '^[0-9]+$' || echo "")
    [ -z "$dnat_count" ] && dnat_count=0
    count=$((count + dnat_count))
    
    # 用户态服务数
    for service in haproxy port-forward gost-forward realm-forward rinetd; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            count=$((count + 1))
        fi
    done
    
    # nginx stream配置数
    if systemctl is-active nginx >/dev/null 2>&1 && [ -d /etc/nginx/stream.d ]; then
        local nginx_count=$(ls /etc/nginx/stream.d/port-forward-*.conf 2>/dev/null | wc -l | tr -d '[:space:]' | sed 's/^0*//' | grep -E '^[0-9]+$' || echo "")
        [ -z "$nginx_count" ] && nginx_count=0
        count=$((count + nginx_count))
    fi
    
    echo $count
}

# 清屏并显示头部
show_header() {
    clear
    local forward_count=$(get_forward_count)
    local status_text
    
    if check_forward_running; then
        status_text="${GREEN}运行中${NC}"
    else
        status_text="${RED}已停止${NC}"
    fi
    
    # 检测本机网络
    detect_local_network
    local net_info=""
    local has_public_v4=false
    local has_public_v6=false
    
    [ "$LOCAL_IPV4_TYPE" = "public" ] && has_public_v4=true
    [ "$LOCAL_IPV6_TYPE" = "public" ] && has_public_v6=true
    
    if [ "$has_public_v4" = true ] && [ "$has_public_v6" = true ]; then
        net_info="${GREEN}IPv4+IPv6${NC}"
    elif [ "$has_public_v4" = true ]; then
        net_info="${GREEN}IPv4${NC}"
    elif [ "$has_public_v6" = true ]; then
        net_info="${CYAN}仅IPv6${NC}"
    elif [ "$LOCAL_HAS_IPV4" = true ]; then
        net_info="${YELLOW}内网IPv4${NC}"
    else
        net_info="${RED}无公网IP${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "      ${CYAN}端口转发管理工具${NC}  ${BOLD}v${VERSION}${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────${NC}"
    echo -e "  状态: ${status_text}    规则: ${CYAN}${forward_count}${NC} 条    网络: ${net_info}"
    echo -e "  作者: ${CYAN}${AUTHOR}${NC}    命令: ${CYAN}pf${NC}"
    echo -e "  项目: ${CYAN}${GITHUB_URL}${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
}

# 设置开机自启（自动调用，无需用户操作）
setup_autostart() {
    local method="$1"  # nftables, iptables, haproxy, gost, realm, etc.
    
    # 对于 nftables/iptables，创建恢复服务
    if [[ "$method" == "nftables" || "$method" == "iptables" ]]; then
        # 检查是否已存在
        if systemctl is-enabled port-forward-restore >/dev/null 2>&1; then
            return 0
        fi
        
        # 创建恢复脚本
        mkdir -p /var/lib/port-forward
        cat > /var/lib/port-forward/restore.sh << 'RESTORE_SCRIPT'
#!/bin/bash
# 端口转发规则恢复脚本

# 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null

# 恢复 nftables 规则
if [ -f /etc/nftables.d/port_forward.nft ]; then
    nft -f /etc/nftables.d/port_forward.nft 2>/dev/null
fi

# 恢复 iptables 规则
if [ -f /root/.port_forward_iptables_running.txt ]; then
    if command -v iptables-legacy-restore >/dev/null 2>&1; then
        iptables-legacy-restore < /root/.port_forward_iptables_running.txt 2>/dev/null
    else
        iptables-restore < /root/.port_forward_iptables_running.txt 2>/dev/null
    fi
fi

# 恢复 nftables 运行时备份
if [ -f /root/.port_forward_nftables_running.txt ]; then
    nft -f /root/.port_forward_nftables_running.txt 2>/dev/null
fi
RESTORE_SCRIPT
        chmod +x /var/lib/port-forward/restore.sh
        
        # 创建 systemd 服务
        cat > /etc/systemd/system/port-forward-restore.service << 'SERVICE_FILE'
[Unit]
Description=Port Forward Rules Restore
After=network.target

[Service]
Type=oneshot
ExecStart=/var/lib/port-forward/restore.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE_FILE
        
        systemctl daemon-reload
        systemctl enable port-forward-restore >/dev/null 2>&1
    fi
    
    # 对于用户态服务，直接启用开机自启
    case "$method" in
        haproxy|gost|realm|rinetd|nginx)
            systemctl enable "${method}" >/dev/null 2>&1 || true
            ;;
        gost-forward)
            systemctl enable gost-forward >/dev/null 2>&1 || true
            ;;
        realm-forward)
            systemctl enable realm-forward >/dev/null 2>&1 || true
            ;;
    esac
}

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "错误: 需要 root 权限运行此脚本"
    echo "请使用: sudo $0"
    exit 1
fi

# 初始化流量统计
init_traffic_stats

# 同步检查系统脚本 (MD5校验)
sync_system_script() {
    local system_script="/usr/local/bin/port_forward.sh"
    local current_script="$0"
    
    # 获取当前脚本的绝对路径（解析软链接）
    local real_path
    if [[ "$current_script" == /* ]]; then
        real_path=$(readlink -f "$current_script" 2>/dev/null || echo "$current_script")
    elif [[ "$current_script" == "bash" || "$current_script" == "-bash" ]]; then
        real_path=""
    else
        real_path="$(cd "$(dirname "$current_script")" 2>/dev/null && pwd)/$(basename "$current_script")"
        real_path=$(readlink -f "$real_path" 2>/dev/null || echo "$real_path")
    fi
    
    # 如果当前脚本不是系统脚本，检查是否需要更新
    if [[ -n "$real_path" && -f "$real_path" && "$real_path" != "$system_script" ]]; then
        local need_update=false
        
        if [[ ! -f "$system_script" ]]; then
            need_update=true
        else
            # 用 md5 校验文件内容是否不同
            local cur_md5 sys_md5
            cur_md5=$(md5sum "$real_path" 2>/dev/null | cut -d' ' -f1)
            sys_md5=$(md5sum "$system_script" 2>/dev/null | cut -d' ' -f1)
            [[ "$cur_md5" != "$sys_md5" ]] && need_update=true
        fi
        
        if [[ "$need_update" == "true" ]]; then
            cp -f "$real_path" "$system_script" 2>/dev/null
            chmod +x "$system_script" 2>/dev/null
            ln -sf "$system_script" /usr/local/bin/pf 2>/dev/null
            ln -sf "$system_script" /usr/bin/pf 2>/dev/null
            hash -r 2>/dev/null
            echo -e "${GREEN}✓ 系统脚本已同步更新 (v$VERSION)${NC}"
        fi
    fi
}

# 快捷命令安装函数
create_shortcut() {
    local system_script="/usr/local/bin/port_forward.sh"
    local current_script="$0"

    # 获取当前脚本的绝对路径（解析软链接）
    local real_path
    if [[ "$current_script" == /* ]]; then
        real_path=$(readlink -f "$current_script" 2>/dev/null || echo "$current_script")
    elif [[ "$current_script" == "bash" || "$current_script" == "-bash" ]]; then
        real_path=""
    else
        real_path="$(cd "$(dirname "$current_script")" 2>/dev/null && pwd)/$(basename "$current_script")"
        real_path=$(readlink -f "$real_path" 2>/dev/null || echo "$real_path")
    fi

    # 如果系统目录没有脚本，需要创建
    if [[ ! -f "$system_script" ]]; then
        if [[ -n "$real_path" && -f "$real_path" ]]; then
            cp -f "$real_path" "$system_script"
        else
            # 内存运行模式，从网络下载
            local raw_url="https://raw.githubusercontent.com/Chil30/port-forward/main/port_forward.sh"
            echo -e "${CYAN}正在下载脚本...${NC}"
            if ! smart_download "$raw_url" "$system_script" 15; then
                echo -e "${YELLOW}无法下载脚本到系统目录${NC}"
                return 1
            fi
        fi
    elif [[ -n "$real_path" && -f "$real_path" && "$real_path" != "$system_script" ]]; then
        # 用 md5 校验，不同才更新
        local cur_md5 sys_md5
        cur_md5=$(md5sum "$real_path" 2>/dev/null | cut -d' ' -f1)
        sys_md5=$(md5sum "$system_script" 2>/dev/null | cut -d' ' -f1)
        [[ "$cur_md5" != "$sys_md5" ]] && cp -f "$real_path" "$system_script"
    fi

    chmod +x "$system_script" 2>/dev/null

    # 创建软链接
    ln -sf "$system_script" /usr/local/bin/pf 2>/dev/null
    ln -sf "$system_script" /usr/bin/pf 2>/dev/null
    hash -r 2>/dev/null

    echo -e "${GREEN}✓ 快捷命令已创建: pf${NC}"
}

# 移除快捷命令
remove_shortcut() { 
    rm -f /usr/local/bin/pf /usr/local/bin/port_forward.sh /usr/bin/pf 2>/dev/null
    echo -e "${GREEN}✓ 快捷命令已移除${NC}"
}

# 每次运行时同步检查并更新系统脚本
sync_system_script

# 首次运行时自动安装快捷命令
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SYSTEM_SCRIPT="/usr/local/bin/port_forward.sh"

if [[ ! -f "/usr/local/bin/pf" ]]; then
    echo "首次运行，正在安装快捷命令..."
    create_shortcut
    sleep 1
fi

# 显示头部
show_header

# 主菜单
echo "  1) 配置新的端口转发"
echo "  2) 查看当前转发状态"
echo "  3) 查看运行日志"
if check_forward_running; then
    echo "  4) 停止转发服务"
else
    echo "  4) 启动转发服务"
fi
echo "  5) 流量统计"
echo "  6) 卸载转发服务"
echo "  7) 导入/导出配置"
echo "  0) 退出"
echo ""

while true; do
    read -p "请选择操作 [1]: " MAIN_ACTION
    MAIN_ACTION=${MAIN_ACTION:-1}
    if [[ $MAIN_ACTION =~ ^[0-7]$ ]]; then
        break
    else
        echo "请输入 0-7 之间的数字"
    fi
done

# 菜单映射（新菜单编号 -> 原功能）
case $MAIN_ACTION in
    0)
        echo -e "${GREEN}再见！${NC}"
        exit 0
        ;;
    1)
        # 配置新的端口转发 - 跳转到原来的配置流程
        MAIN_ACTION=1
        ;;
    2)
        echo -e "${BLUE}${BOLD}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}${BOLD}║        当前转发服务状态                   ║${NC}"
        echo -e "${BLUE}${BOLD}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        
        # 显示所有活跃的转发规则
        echo -e "${CYAN}${BOLD}=== 活跃转发规则 ===${NC}"
        ACTIVE_COUNT=0
        
        # 0. nftables DNAT 规则
        if command -v nft >/dev/null 2>&1; then
            NFT_RULES=$(nft list chain inet port_forward prerouting 2>/dev/null | grep -E "dnat (ip )?to")
            if [ -n "$NFT_RULES" ]; then
                echo "$NFT_RULES" | while read line; do
                    LOCAL_P=$(echo "$line" | grep -oE 'dport [0-9]+' | awk '{print $2}')
                    TARGET=$(echo "$line" | grep -oE 'dnat (ip )?to [0-9.]+:[0-9]+' | sed -E 's/dnat (ip )?to //')
                    TRAFFIC=$(get_nft_traffic "$LOCAL_P")
                    TRAFFIC_FMT=$(format_traffic "$TRAFFIC")
                    if [ -n "$LOCAL_P" ] && [ -n "$TARGET" ]; then
                        ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                        echo -e "${GREEN}✅ nftables${NC}  :$LOCAL_P -> $TARGET  ${CYAN}[${TRAFFIC_FMT}]${NC}"
                    fi
                done
            fi
        fi
        
        # 1. iptables DNAT 规则
        IPTABLES_CMD=$(get_iptables_cmd)
        DNAT_RULES=$($IPTABLES_CMD -t nat -L PREROUTING -n -v 2>/dev/null | grep DNAT)
        if [ -n "$DNAT_RULES" ]; then
            echo "$DNAT_RULES" | while read line; do
                LOCAL_P=$(echo "$line" | grep -oE 'dpt:[0-9]+' | cut -d: -f2)
                TARGET=$(echo "$line" | grep -oE 'to:[0-9.]+:[0-9]+' | sed 's/to://')
                BYTES=$(echo "$line" | awk '{print $2}')
                TRAFFIC_FMT=$(format_traffic "$BYTES")
                if [ -n "$LOCAL_P" ] && [ -n "$TARGET" ]; then
                    ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                    echo -e "${GREEN}✅ iptables${NC}  :$LOCAL_P -> $TARGET  ${CYAN}[${TRAFFIC_FMT}]${NC}"
                fi
            done
        fi
        
        # 2. realm
        if systemctl is-active realm-forward >/dev/null 2>&1 && [ -f /etc/realm/config.toml ]; then
            # 解析所有 endpoint
            while IFS= read -r listen_line; do
                LOCAL_P=$(echo "$listen_line" | grep -oE '[0-9]+$')
                read -r remote_line
                TARGET=$(echo "$remote_line" | sed -n 's/.*remote = "\([^"]*\)".*/\1/p')
                if [ -n "$LOCAL_P" ] && [ -n "$TARGET" ]; then
                    ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                    echo -e "${GREEN}✅ realm${NC}     :$LOCAL_P -> $TARGET"
                fi
            done < <(grep -E "^listen|^remote" /etc/realm/config.toml 2>/dev/null)
        fi
        
        # 3. gost
        if systemctl is-active gost-forward >/dev/null 2>&1 && [ -f /etc/gost/config.json ]; then
            # 支持 IPv4 和 IPv6 (带方括号) 地址提取
            TARGET=$(grep -oE '"\[?[0-9a-fA-F:.]+\]?:[0-9]+"' /etc/gost/config.json | grep -v '^":' | tr -d '"' | head -1)
            LOCAL_P=$(grep -oE '":[0-9]+"' /etc/gost/config.json | tr -d '":' | head -1)
            if [ -n "$TARGET" ]; then
                ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                echo -e "${GREEN}✅ gost${NC}      :$LOCAL_P -> $TARGET"
            fi
        fi
        
        # 4. haproxy
        if systemctl is-active haproxy >/dev/null 2>&1 && [ -f /etc/haproxy/haproxy.cfg ]; then
            LOCAL_P=$(grep "bind \*:" /etc/haproxy/haproxy.cfg | grep -oE ':[0-9]+' | tr -d ':' | head -1)
            # 支持 IPv4 和 IPv6 (带方括号) 地址提取
            TARGET=$(grep "server " /etc/haproxy/haproxy.cfg | sed -n 's/.*server [^ ]* \([^ ]*\).*/\1/p' | head -1)
            if [ -n "$TARGET" ]; then
                ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                echo -e "${GREEN}✅ haproxy${NC}   :$LOCAL_P -> $TARGET"
            fi
        fi
        
        # 5. rinetd
        if systemctl is-active rinetd >/dev/null 2>&1 && [ -f /etc/rinetd.conf ]; then
            grep -v "^#" /etc/rinetd.conf | grep -E '^[0-9]' | while read line; do
                LOCAL_P=$(echo "$line" | awk '{print $2}')
                TARGET_IP=$(echo "$line" | awk '{print $3}')
                TARGET_PORT=$(echo "$line" | awk '{print $4}')
                if [ -n "$TARGET_IP" ]; then
                    ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                    echo -e "${GREEN}✅ rinetd${NC}    :$LOCAL_P -> $TARGET_IP:$TARGET_PORT"
                fi
            done
        fi
        
        # 6. socat (port-forward)
        if systemctl is-active port-forward >/dev/null 2>&1; then
            ACTIVE_COUNT=$((ACTIVE_COUNT+1))
            echo -e "${GREEN}✅ socat${NC}     运行中"
        fi
        
        # 7. nginx stream
        if systemctl is-active nginx >/dev/null 2>&1 && [ -d /etc/nginx/stream.d ]; then
            for conf in /etc/nginx/stream.d/port-forward-*.conf; do
                [ -f "$conf" ] || continue
                LOCAL_P=$(grep "listen" "$conf" | grep -oE '[0-9]+' | head -1)
                # 支持 IPv4 和 IPv6 (带方括号) 地址提取
                TARGET=$(grep "proxy_pass" "$conf" | sed -n 's/.*proxy_pass \([^;]*\);.*/\1/p' | head -1)
                if [ -n "$TARGET" ]; then
                    ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                    echo -e "${GREEN}✅ nginx${NC}     :$LOCAL_P -> $TARGET"
                fi
            done
        fi
        
        # 使用get_forward_count函数获取准确的计数
        REAL_COUNT=$(get_forward_count)
        if [ "$REAL_COUNT" -eq 0 ]; then
            echo -e "  ${DIM}没有运行中的转发服务${NC}"
        fi
        
        # 延迟检测 - 测试所有活跃的转发目标
        echo ""
        echo -e "${CYAN}${BOLD}=== 延迟检测 ===${NC}"
        TESTED_IPS=""
        HAS_TARGET=false
        
        # 定义ping测试函数
        do_ping_test() {
            local ip=$1
            local port=$2
            local label=$3
            
            # 避免重复测试同一IP
            if echo "$TESTED_IPS" | grep -q "$ip"; then
                return
            fi
            TESTED_IPS="$TESTED_IPS $ip"
            
            echo -n "  $label $ip:$port ... "
            
            # 判断是 IPv4 还是 IPv6
            local is_ipv6=false
            [[ "$ip" =~ : ]] && is_ipv6=true
            
            # 优先用 ping 测试延迟
            local PING_RESULT=""
            if [ "$is_ipv6" = true ]; then
                PING_RESULT=$(ping -6 -c 1 -W 2 "$ip" 2>/dev/null | grep 'time=' | sed 's/.*time=\([0-9.]*\).*/\1/')
            else
                # 纯 IPv6 环境无法 ping IPv4，先尝试
                PING_RESULT=$(ping -c 1 -W 2 "$ip" 2>/dev/null | grep 'time=' | sed 's/.*time=\([0-9.]*\).*/\1/')
            fi
            
            if [ -n "$PING_RESULT" ]; then
                PING_INT=${PING_RESULT%.*}
                if [ "$PING_INT" -lt 50 ]; then
                    echo -e "${GREEN}${PING_RESULT}ms${NC} ✓"
                elif [ "$PING_INT" -lt 150 ]; then
                    echo -e "${YELLOW}${PING_RESULT}ms${NC}"
                else
                    echo -e "${RED}${PING_RESULT}ms${NC} (较高)"
                fi
            else
                # ping 失败，尝试 TCP 连接测试（支持 NAT64 环境）
                local start_time=$(date +%s%3N 2>/dev/null || echo "0")
                if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
                    local end_time=$(date +%s%3N 2>/dev/null || echo "0")
                    if [ "$start_time" != "0" ] && [ "$end_time" != "0" ]; then
                        local tcp_ms=$((end_time - start_time))
                        if [ "$tcp_ms" -lt 50 ]; then
                            echo -e "${GREEN}${tcp_ms}ms${NC} (TCP) ✓"
                        elif [ "$tcp_ms" -lt 150 ]; then
                            echo -e "${YELLOW}${tcp_ms}ms${NC} (TCP)"
                        else
                            echo -e "${RED}${tcp_ms}ms${NC} (TCP)"
                        fi
                    else
                        echo -e "${GREEN}可达${NC} (TCP)"
                    fi
                else
                    echo -e "${RED}超时${NC}"
                fi
            fi
        }
        
        # 从 iptables DNAT 规则提取
        IPTABLES_CMD=$(get_iptables_cmd)
        DNAT_TARGETS=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep DNAT | grep -oE 'to:[0-9.]+:[0-9]+' | sed 's/to://')
        if [ -n "$DNAT_TARGETS" ]; then
            echo "$DNAT_TARGETS" | while read target; do
                HAS_TARGET=true
                TARGET_IP=$(echo "$target" | cut -d: -f1)
                TARGET_PORT=$(echo "$target" | cut -d: -f2)
                do_ping_test "$TARGET_IP" "$TARGET_PORT" "iptables"
            done
        fi
        
        # 从 realm 配置获取
        if systemctl is-active realm-forward >/dev/null 2>&1 && [ -f /etc/realm/config.toml ]; then
            TARGET_ADDR=$(grep "remote" /etc/realm/config.toml | sed -n 's/.*remote = "\([^"]*\)".*/\1/p' | head -1)
            if [ -n "$TARGET_ADDR" ]; then
                HAS_TARGET=true
                # 处理 IPv6 地址 [IPv6]:port 格式
                if [[ "$TARGET_ADDR" =~ ^\[.*\]:[0-9]+$ ]]; then
                    TARGET_IP=$(echo "$TARGET_ADDR" | sed 's/\[\(.*\)\]:.*/\1/')
                    TARGET_PORT=$(echo "$TARGET_ADDR" | sed 's/.*\]://')
                else
                    TARGET_IP=$(echo "$TARGET_ADDR" | cut -d: -f1)
                    TARGET_PORT=$(echo "$TARGET_ADDR" | cut -d: -f2)
                fi
                do_ping_test "$TARGET_IP" "$TARGET_PORT" "realm"
            fi
        fi
        
        # 从 gost 配置获取
        if systemctl is-active gost-forward >/dev/null 2>&1 && [ -f /etc/gost/config.json ]; then
            TARGET_ADDR=$(grep -oE '"\[?[0-9a-fA-F:.]+\]?:[0-9]+"' /etc/gost/config.json | grep -v '^":' | tr -d '"' | head -1)
            if [ -n "$TARGET_ADDR" ]; then
                HAS_TARGET=true
                # 处理 IPv6 地址 [IPv6]:port 格式
                if [[ "$TARGET_ADDR" =~ ^\[.*\]:[0-9]+$ ]]; then
                    TARGET_IP=$(echo "$TARGET_ADDR" | sed 's/\[\(.*\)\]:.*/\1/')
                    TARGET_PORT=$(echo "$TARGET_ADDR" | sed 's/.*\]://')
                else
                    TARGET_IP=$(echo "$TARGET_ADDR" | cut -d: -f1)
                    TARGET_PORT=$(echo "$TARGET_ADDR" | cut -d: -f2)
                fi
                do_ping_test "$TARGET_IP" "$TARGET_PORT" "gost"
            fi
        fi
        
        # 从 haproxy 配置获取
        if systemctl is-active haproxy >/dev/null 2>&1 && [ -f /etc/haproxy/haproxy.cfg ]; then
            TARGET_ADDR=$(grep "server " /etc/haproxy/haproxy.cfg | sed -n 's/.*server [^ ]* \([^ ]*\).*/\1/p' | head -1)
            if [ -n "$TARGET_ADDR" ]; then
                HAS_TARGET=true
                # 处理 IPv6 地址 [IPv6]:port 格式
                if [[ "$TARGET_ADDR" =~ ^\[.*\]:[0-9]+$ ]]; then
                    TARGET_IP=$(echo "$TARGET_ADDR" | sed 's/\[\(.*\)\]:.*/\1/')
                    TARGET_PORT=$(echo "$TARGET_ADDR" | sed 's/.*\]://')
                else
                    TARGET_IP=$(echo "$TARGET_ADDR" | cut -d: -f1)
                    TARGET_PORT=$(echo "$TARGET_ADDR" | cut -d: -f2)
                fi
                do_ping_test "$TARGET_IP" "$TARGET_PORT" "haproxy"
            fi
        fi
        
        # 从 rinetd 配置获取
        if systemctl is-active rinetd >/dev/null 2>&1 && [ -f /etc/rinetd.conf ]; then
            TARGET_LINE=$(grep -v "^#" /etc/rinetd.conf | grep -E '^[0-9]' | head -1)
            if [ -n "$TARGET_LINE" ]; then
                HAS_TARGET=true
                TARGET_IP=$(echo "$TARGET_LINE" | awk '{print $3}')
                TARGET_PORT=$(echo "$TARGET_LINE" | awk '{print $4}')
                do_ping_test "$TARGET_IP" "$TARGET_PORT" "rinetd"
            fi
        fi
        
        # 从 nginx stream 配置获取
        if systemctl is-active nginx >/dev/null 2>&1 && [ -d /etc/nginx/stream.d ]; then
            for conf in /etc/nginx/stream.d/port-forward-*.conf; do
                [ -f "$conf" ] || continue
                TARGET_ADDR=$(grep "server " "$conf" | sed -n 's/.*server \([^ ;]*\).*/\1/p' | head -1)
                if [ -n "$TARGET_ADDR" ]; then
                    HAS_TARGET=true
                    # 处理 IPv6 地址 [IPv6]:port 格式
                    if [[ "$TARGET_ADDR" =~ ^\[.*\]:[0-9]+$ ]]; then
                        TARGET_IP=$(echo "$TARGET_ADDR" | sed 's/\[\(.*\)\]:.*/\1/')
                        TARGET_PORT=$(echo "$TARGET_ADDR" | sed 's/.*\]://')
                    else
                        TARGET_IP=$(echo "$TARGET_ADDR" | cut -d: -f1)
                        TARGET_PORT=$(echo "$TARGET_ADDR" | cut -d: -f2)
                    fi
                    do_ping_test "$TARGET_IP" "$TARGET_PORT" "nginx"
                fi
            done
        fi
        
        # 使用get_forward_count检查是否有活跃目标
        if [ "$(get_forward_count)" -eq 0 ]; then
            echo -e "  ${DIM}无活跃的转发目标${NC}"
        fi
        
        # 显示配置信息
        echo ""
        echo "=== 配置信息 ==="
        
        # 检查备份目录
        BACKUP_BASE_DIR="/root/.port_forward_backups"
        if [ -d "$BACKUP_BASE_DIR" ]; then
            BACKUP_COUNT=$(ls -d "$BACKUP_BASE_DIR"/* 2>/dev/null | wc -l)
            echo "配置备份: $BACKUP_COUNT 个备份"
            LATEST_BACKUP=$(ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -1)
            if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/backup_info.txt" ]; then
                echo "最近备份:"
                # 读取并转换旧格式的方案名称
                cat "$LATEST_BACKUP/backup_info.txt" | sed \
                    -e 's/方案1/iptables DNAT/' \
                    -e 's/方案2/HAProxy/' \
                    -e 's/方案3/socat/' \
                    -e 's/方案4/gost/' \
                    -e 's/方案5/realm/' \
                    -e 's/方案6/rinetd/' \
                    -e 's/方案7/nginx stream/' \
                    | sed 's/^/  /'
            fi
        else
            echo "配置备份: 无"
        fi
        
        # 检查凭据文件
        if [ -f /root/haproxy_credentials.txt ]; then
            echo ""
            echo "HAProxy 管理界面: /root/haproxy_credentials.txt"
        fi
        if [ -f /root/gost_credentials.txt ]; then
            echo ""
            echo "Gost API 凭据: /root/gost_credentials.txt"
        fi
        
        # 显示当前监听的端口
        echo ""
        echo "=== 当前监听端口 ==="
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | grep -E 'haproxy|socat|gost|realm|rinetd|nginx' | awk '{printf "  %-25s %s\n", $4, $6}'
        fi
        
        # IP转发状态
        echo ""
        echo "=== 系统配置 ==="
        IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
        if [ "$IP_FORWARD" = "1" ]; then
            echo -e "IP转发: ${GREEN}已启用${NC}"
        else
            echo -e "IP转发: ${RED}已禁用${NC}"
        fi
        
        # BBR状态
        BBR_STATUS=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
        if [ "$BBR_STATUS" = "bbr" ]; then
            echo -e "BBR拥塞控制: ${GREEN}已启用${NC}"
        else
            echo -e "BBR拥塞控制: ${YELLOW}$BBR_STATUS${NC}"
        fi
        
        echo ""
        echo "==========================================="
        echo "按回车键返回主菜单..."
        read
        exec $0
        ;;
    3)
        echo "查看运行日志"
        echo ""
        echo "请选择要查看的服务日志："
        echo "1) nftables 规则和连接"
        echo "2) iptables 规则和连接"
        echo "3) HAProxy 日志"
        echo "4) socat 日志"
        echo "5) gost 日志"
        echo "6) realm 日志"
        echo "7) rinetd 日志"
        echo "8) nginx stream 日志"
        echo "0) 返回主菜单"
        echo ""
        read -p "请选择 [1]: " LOG_CHOICE
        LOG_CHOICE=${LOG_CHOICE:-1}
        
        case $LOG_CHOICE in
            1)
                echo "nftables 规则和连接状态:"
                echo ""
                if command -v nft >/dev/null 2>&1; then
                    echo "=== nftables 端口转发规则 ==="
                    if nft list table inet port_forward >/dev/null 2>&1; then
                        nft list table inet port_forward
                    else
                        echo "没有找到 port_forward 表"
                    fi
                    echo ""
                    echo "=== 所有 NAT 规则 ==="
                    nft list tables | grep -E 'nat|forward' | while read table; do
                        echo "--- $table ---"
                        nft list table $table 2>/dev/null
                    done
                else
                    echo "nftables 未安装"
                fi
                echo ""
                echo "=== 当前监听端口 ==="
                ss -tlnp 2>/dev/null | grep -v "127.0.0" | head -20 || netstat -tlnp 2>/dev/null | grep -v "127.0.0" | head -20
                echo ""
                echo "=== 活跃连接 ==="
                if [ -f /proc/net/nf_conntrack ]; then
                    cat /proc/net/nf_conntrack | grep -E 'ESTABLISHED|SYN' | head -20
                    echo ""
                    echo "总连接数: $(cat /proc/net/nf_conntrack | wc -l)"
                    echo "ESTABLISHED: $(cat /proc/net/nf_conntrack | grep ESTABLISHED | wc -l)"
                else
                    ss -tn 2>/dev/null | grep ESTAB | head -20 || netstat -tn 2>/dev/null | grep ESTABLISHED | head -20
                fi
                ;;
            2)
                echo "iptables 规则和连接状态:"
                echo ""
                echo "=== NAT 转发规则 ==="
                # 优先使用 iptables-legacy，避免 nftables 兼容性问题
                if command -v iptables-legacy >/dev/null 2>&1; then
                    iptables-legacy -t nat -L -n -v --line-numbers
                elif iptables -t nat -L -n -v --line-numbers 2>&1 | grep -q "incompatible"; then
                    echo "检测到系统使用 nftables 后端，尝试使用 iptables-legacy..."
                    if command -v iptables-legacy >/dev/null 2>&1; then
                        iptables-legacy -t nat -L -n -v --line-numbers
                    else
                        echo "请安装 iptables-legacy: apt install iptables"
                        echo "或使用 nft 命令查看规则: nft list ruleset"
                    fi
                else
                    iptables -t nat -L -n -v --line-numbers
                fi
                echo ""
                echo "=== 当前监听端口 ==="
                ss -tlnp 2>/dev/null | grep -v "127.0.0" | head -20 || netstat -tlnp 2>/dev/null | grep -v "127.0.0" | head -20
                echo ""
                echo "=== 活跃连接 ==="
                if [ -f /proc/net/nf_conntrack ]; then
                    cat /proc/net/nf_conntrack | grep -E 'ESTABLISHED|SYN' | head -20
                    echo ""
                    echo "总连接数: $(cat /proc/net/nf_conntrack | wc -l)"
                    echo "ESTABLISHED: $(cat /proc/net/nf_conntrack | grep ESTABLISHED | wc -l)"
                else
                    ss -tn 2>/dev/null | grep ESTAB | head -20 || netstat -tn 2>/dev/null | grep ESTABLISHED | head -20
                fi
                ;;
            3)
                if systemctl is-active haproxy >/dev/null 2>&1; then
                    echo "HAProxy 实时日志 (Ctrl+C 退出):"
                    journalctl -u haproxy -f --no-pager -n 50
                else
                    echo "HAProxy 服务未运行"
                fi
                ;;
            4)
                if systemctl is-active port-forward >/dev/null 2>&1; then
                    echo "socat 实时日志 (Ctrl+C 退出):"
                    journalctl -u port-forward -f --no-pager -n 50
                else
                    echo "socat 服务未运行"
                fi
                ;;
            5)
                if systemctl is-active gost-forward >/dev/null 2>&1; then
                    echo "gost 实时日志 (Ctrl+C 退出):"
                    journalctl -u gost-forward -f --no-pager -n 50
                else
                    echo "gost 服务未运行"
                fi
                ;;
            6)
                if systemctl is-active realm-forward >/dev/null 2>&1; then
                    echo "realm 实时日志 (Ctrl+C 退出):"
                    journalctl -u realm-forward -f --no-pager -n 50
                else
                    echo "realm 服务未运行"
                fi
                ;;
            7)
                if systemctl is-active rinetd >/dev/null 2>&1; then
                    echo "rinetd 实时日志 (Ctrl+C 退出):"
                    journalctl -u rinetd -f --no-pager -n 50
                else
                    echo "rinetd 服务未运行"
                fi
                ;;
            8)
                if systemctl is-active nginx >/dev/null 2>&1; then
                    echo "nginx 实时日志 (Ctrl+C 退出):"
                    if [ -f /var/log/nginx/stream.log ]; then
                        tail -f /var/log/nginx/stream.log
                    else
                        journalctl -u nginx -f --no-pager -n 50
                    fi
                else
                    echo "nginx 服务未运行"
                fi
                ;;
            0)
                exec $0
                ;;
            *)
                echo "无效选择"
                ;;
        esac
        echo ""
        echo "按回车键返回主菜单..."
        read
        exec $0
        ;;
    4)
        # 动态启动/停止服务
        if check_forward_running; then
            # 当前运行中，执行停止
            echo "=== 停止转发服务 ==="
            echo ""
            echo "请选择要停止的服务："
            echo "1) nftables DNAT 规则"
            echo "2) iptables DNAT 规则"
            echo "3) HAProxy"
            echo "4) socat"
            echo "5) gost"
            echo "6) realm"
            echo "7) rinetd"
            echo "8) nginx"
            echo "9) 停止所有服务"
            echo "0) 返回主菜单"
            echo ""
            read -p "请选择 [9]: " STOP_CHOICE
            STOP_CHOICE=${STOP_CHOICE:-9}
            
            case $STOP_CHOICE in
                1)
                    echo -e "${YELLOW}停止 nftables DNAT 规则...${NC}"
                    NFT_RUNNING_BACKUP="/root/.port_forward_nftables_running.txt"
                    
                    if command -v nft >/dev/null 2>&1; then
                        # 备份当前规则
                        if nft list table inet port_forward >/dev/null 2>&1; then
                            echo -e "${YELLOW}备份当前 nftables 规则...${NC}"
                            nft list table inet port_forward > "$NFT_RUNNING_BACKUP" 2>/dev/null
                            echo -e "${GREEN}规则已备份到: $NFT_RUNNING_BACKUP${NC}"
                            
                            # 删除表
                            nft delete table inet port_forward 2>/dev/null
                            echo -e "${GREEN}✓ nftables DNAT 规则已清理${NC}"
                        else
                            echo -e "${YELLOW}没有找到 nftables port_forward 表${NC}"
                        fi
                    else
                        echo -e "${RED}nftables 未安装${NC}"
                    fi
                    ;;
                2)
                    echo -e "${YELLOW}停止 iptables DNAT 规则...${NC}"
                    IPTABLES_CMD=$(get_iptables_cmd)
                    
                    # 首先备份当前规则到固定位置
                    IPTABLES_RUNNING_BACKUP="/root/.port_forward_iptables_running.txt"
                    if $IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -q DNAT; then
                        echo -e "${YELLOW}备份当前 iptables 规则...${NC}"
                        if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                            iptables-legacy-save > "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
                        else
                            iptables-save > "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
                        fi
                        echo -e "${GREEN}规则已备份到: $IPTABLES_RUNNING_BACKUP${NC}"
                    fi
                    
                    # 清理DNAT规则
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    # 清理MASQUERADE规则
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    # 清理FORWARD规则
                    $IPTABLES_CMD -L FORWARD --line-numbers -n 2>/dev/null | grep ACCEPT | tac | awk '{print $1}' | while read line; do
                        $IPTABLES_CMD -D FORWARD $line 2>/dev/null || true
                    done
                    echo -e "${GREEN}✓ iptables DNAT 规则已清理${NC}"
                    ;;
            3)
                systemctl stop haproxy 2>/dev/null && echo -e "${GREEN}HAProxy已停止${NC}" || echo -e "${YELLOW}HAProxy未运行${NC}"
                ;;
            4)
                systemctl stop port-forward 2>/dev/null && echo -e "${GREEN}socat已停止${NC}" || echo -e "${YELLOW}socat未运行${NC}"
                ;;
            5)
                systemctl stop gost-forward 2>/dev/null && echo -e "${GREEN}gost已停止${NC}" || echo -e "${YELLOW}gost未运行${NC}"
                ;;
            6)
                systemctl stop realm-forward 2>/dev/null && echo -e "${GREEN}realm已停止${NC}" || echo -e "${YELLOW}realm未运行${NC}"
                ;;
            7)
                systemctl stop rinetd 2>/dev/null && echo -e "${GREEN}rinetd已停止${NC}" || echo -e "${YELLOW}rinetd未运行${NC}"
                ;;
            8)
                systemctl stop nginx 2>/dev/null && echo -e "${GREEN}nginx已停止${NC}" || echo -e "${YELLOW}nginx未运行${NC}"
                ;;
            9)
                echo -e "${YELLOW}停止所有转发服务...${NC}"
                
                # 备份并清理 nftables 规则
                NFT_RUNNING_BACKUP="/root/.port_forward_nftables_running.txt"
                if command -v nft >/dev/null 2>&1 && nft list table inet port_forward >/dev/null 2>&1; then
                    nft list table inet port_forward > "$NFT_RUNNING_BACKUP" 2>/dev/null
                    nft delete table inet port_forward 2>/dev/null
                    echo -e "${GREEN}✓ nftables 规则已备份并清理${NC}"
                fi
                
                # 停止所有systemd服务
                systemctl stop haproxy 2>/dev/null || true
                systemctl stop port-forward 2>/dev/null || true
                systemctl stop gost-forward 2>/dev/null || true
                systemctl stop realm-forward 2>/dev/null || true
                systemctl stop rinetd 2>/dev/null || true
                systemctl stop nginx 2>/dev/null || true
                
                # 备份并清理iptables DNAT规则
                IPTABLES_CMD=$(get_iptables_cmd)
                IPTABLES_RUNNING_BACKUP="/root/.port_forward_iptables_running.txt"
                if $IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -q DNAT; then
                    if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                        iptables-legacy-save > "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
                    else
                        iptables-save > "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
                    fi
                fi
                $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                    $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                done
                $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                    $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                done
                $IPTABLES_CMD -L FORWARD --line-numbers -n 2>/dev/null | grep ACCEPT | tac | awk '{print $1}' | while read line; do
                    $IPTABLES_CMD -D FORWARD $line 2>/dev/null || true
                done
                
                echo -e "${GREEN}✓ 所有转发服务已停止${NC}"
                ;;
            0)
                exec $0
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                ;;
        esac
        else
            # 当前已停止，执行启动
            echo -e "${CYAN}${BOLD}=== 启动转发服务 ===${NC}"
            echo ""
            
            # 检查有哪些可启动的服务
            echo "请选择要启动的服务："
            echo ""
            
            # 检查可用的服务配置
            HAS_OPTIONS=false
            
            # 1. nftables - 检查配置文件或备份
            NFT_RUNNING_BACKUP="/root/.port_forward_nftables_running.txt"
            NFT_CONFIG="/etc/nftables.d/port_forward.nft"
            if [ -f "$NFT_RUNNING_BACKUP" ] && [ -s "$NFT_RUNNING_BACKUP" ]; then
                echo "1) nftables DNAT (从运行时备份恢复)"
                HAS_OPTIONS=true
            elif [ -f "$NFT_CONFIG" ] && [ -s "$NFT_CONFIG" ]; then
                echo "1) nftables DNAT (从配置文件恢复)"
                HAS_OPTIONS=true
            fi
            
            # 2. iptables - 检查备份文件或 netfilter-persistent
            IPTABLES_RUNNING_BACKUP="/root/.port_forward_iptables_running.txt"
            if [ -f "$IPTABLES_RUNNING_BACKUP" ] && [ -s "$IPTABLES_RUNNING_BACKUP" ]; then
                echo "2) iptables DNAT (从备份恢复)"
                HAS_OPTIONS=true
            elif [ -f /etc/iptables/rules.v4 ] && grep -q DNAT /etc/iptables/rules.v4 2>/dev/null; then
                echo "2) iptables DNAT (从 netfilter-persistent 恢复)"
                HAS_OPTIONS=true
            fi
            
            # 3. HAProxy - 检查配置文件存在即可
            if [ -f /etc/haproxy/haproxy.cfg ]; then
                if systemctl is-active haproxy >/dev/null 2>&1; then
                    echo "3) HAProxy (已运行)"
                else
                    echo "3) HAProxy"
                    HAS_OPTIONS=true
                fi
            fi
            
            # 4. socat - 检查服务文件
            if [ -f /etc/systemd/system/port-forward.service ] || [ -f /etc/systemd/system/port-forward@.service ]; then
                if systemctl is-active port-forward >/dev/null 2>&1; then
                    echo "4) socat (已运行)"
                else
                    echo "4) socat"
                    HAS_OPTIONS=true
                fi
            fi
            
            # 5. gost - 检查配置文件
            if [ -f /etc/gost/config.json ] || [ -f /etc/gost/config.yaml ]; then
                if systemctl is-active gost-forward >/dev/null 2>&1; then
                    echo "5) gost (已运行)"
                else
                    echo "5) gost"
                    HAS_OPTIONS=true
                fi
            fi
            
            # 6. realm - 检查配置文件
            if [ -f /etc/realm/config.toml ]; then
                if systemctl is-active realm-forward >/dev/null 2>&1; then
                    echo "6) realm (已运行)"
                else
                    echo "6) realm"
                    HAS_OPTIONS=true
                fi
            fi
            
            # 7. rinetd - 检查配置文件
            if [ -f /etc/rinetd.conf ] && grep -qE '^[0-9]' /etc/rinetd.conf 2>/dev/null; then
                if systemctl is-active rinetd >/dev/null 2>&1; then
                    echo "7) rinetd (已运行)"
                else
                    echo "7) rinetd"
                    HAS_OPTIONS=true
                fi
            fi
            
            # 8. nginx stream - 检查配置文件
            if [ -d /etc/nginx/stream.d ] && ls /etc/nginx/stream.d/port-forward-*.conf >/dev/null 2>&1; then
                if systemctl is-active nginx >/dev/null 2>&1; then
                    echo "8) nginx stream (已运行)"
                else
                    echo "8) nginx stream"
                    HAS_OPTIONS=true
                fi
            fi
            
            echo "9) 启动所有可用服务"
            echo "0) 返回主菜单"
            echo ""
            
            if [ "$HAS_OPTIONS" = false ]; then
                echo -e "${YELLOW}未找到任何可启动的转发配置${NC}"
                echo -e "${YELLOW}请先配置端口转发（选项1）或导入配置（选项8）${NC}"
            else
                read -p "请选择 [9]: " START_CHOICE
                START_CHOICE=${START_CHOICE:-9}
                
                case $START_CHOICE in
                    1)
                        # 恢复 nftables 规则
                        if command -v nft >/dev/null 2>&1; then
                            echo 1 > /proc/sys/net/ipv4/ip_forward
                            echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
                            
                            if [ -f "$NFT_RUNNING_BACKUP" ] && [ -s "$NFT_RUNNING_BACKUP" ]; then
                                if nft -f "$NFT_RUNNING_BACKUP" 2>/dev/null; then
                                    echo -e "${GREEN}✓ nftables 规则已从运行时备份恢复${NC}"
                                else
                                    echo -e "${RED}✗ 从运行时备份恢复失败，尝试配置文件...${NC}"
                                    [ -f "$NFT_CONFIG" ] && nft -f "$NFT_CONFIG" 2>/dev/null && echo -e "${GREEN}✓ 从配置文件恢复成功${NC}"
                                fi
                            elif [ -f "$NFT_CONFIG" ]; then
                                if nft -f "$NFT_CONFIG" 2>/dev/null; then
                                    echo -e "${GREEN}✓ nftables 规则已从配置文件恢复${NC}"
                                else
                                    echo -e "${RED}✗ 恢复失败，配置文件可能损坏${NC}"
                                fi
                            fi
                            
                            # 显示当前规则数
                            rule_count=$(nft list table inet port_forward 2>/dev/null | grep -c "dnat" || echo "0")
                            echo -e "${GREEN}当前规则数: $rule_count${NC}"
                        else
                            echo -e "${RED}nftables 未安装${NC}"
                        fi
                        ;;
                    2)
                        IPTABLES_CMD=$(get_iptables_cmd)
                        echo 1 > /proc/sys/net/ipv4/ip_forward
                        
                        if [ -f "$IPTABLES_RUNNING_BACKUP" ] && [ -s "$IPTABLES_RUNNING_BACKUP" ]; then
                            if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                                iptables-legacy-restore < "$IPTABLES_RUNNING_BACKUP" 2>/dev/null
                            else
                                iptables-restore < "$IPTABLES_RUNNING_BACKUP" 2>/dev/null
                            fi
                            DNAT_COUNT=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -c DNAT || echo "0")
                            echo -e "${GREEN}✓ iptables 规则已从备份恢复，$DNAT_COUNT 条规则${NC}"
                        elif [ -f /etc/iptables/rules.v4 ]; then
                            # 使用 netfilter-persistent 恢复
                            netfilter-persistent reload 2>/dev/null || iptables-restore < /etc/iptables/rules.v4 2>/dev/null
                            DNAT_COUNT=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -c DNAT || echo "0")
                            echo -e "${GREEN}✓ iptables 规则已从 netfilter-persistent 恢复，$DNAT_COUNT 条规则${NC}"
                        else
                            echo -e "${RED}未找到 iptables 备份文件${NC}"
                        fi
                        ;;
                    3)
                        if systemctl start haproxy 2>/dev/null; then
                            echo -e "${GREEN}✓ HAProxy 已启动${NC}"
                        else
                            echo -e "${RED}✗ HAProxy 启动失败${NC}"
                            journalctl -u haproxy -n 5 --no-pager 2>/dev/null
                        fi
                        ;;
                    4)
                        if systemctl start port-forward 2>/dev/null; then
                            echo -e "${GREEN}✓ socat 已启动${NC}"
                        else
                            echo -e "${RED}✗ socat 启动失败${NC}"
                        fi
                        ;;
                    5)
                        if systemctl start gost-forward 2>/dev/null; then
                            echo -e "${GREEN}✓ gost 已启动${NC}"
                        else
                            echo -e "${RED}✗ gost 启动失败${NC}"
                            journalctl -u gost-forward -n 5 --no-pager 2>/dev/null
                        fi
                        ;;
                    6)
                        if systemctl start realm-forward 2>/dev/null; then
                            echo -e "${GREEN}✓ realm 已启动${NC}"
                        else
                            echo -e "${RED}✗ realm 启动失败${NC}"
                            journalctl -u realm-forward -n 5 --no-pager 2>/dev/null
                        fi
                        ;;
                    7)
                        if systemctl start rinetd 2>/dev/null; then
                            echo -e "${GREEN}✓ rinetd 已启动${NC}"
                        else
                            echo -e "${RED}✗ rinetd 启动失败${NC}"
                        fi
                        ;;
                    8)
                        if systemctl start nginx 2>/dev/null; then
                            echo -e "${GREEN}✓ nginx 已启动${NC}"
                        else
                            echo -e "${RED}✗ nginx 启动失败${NC}"
                            nginx -t 2>&1
                        fi
                        ;;
                    9)
                        echo -e "${YELLOW}启动所有可用服务...${NC}"
                        echo 1 > /proc/sys/net/ipv4/ip_forward
                        
                        # nftables
                        if command -v nft >/dev/null 2>&1; then
                            if [ -f "$NFT_RUNNING_BACKUP" ] && [ -s "$NFT_RUNNING_BACKUP" ]; then
                                nft -f "$NFT_RUNNING_BACKUP" 2>/dev/null && echo -e "${GREEN}✓ nftables 规则已恢复${NC}"
                            elif [ -f /etc/nftables.d/port_forward.nft ]; then
                                nft -f /etc/nftables.d/port_forward.nft 2>/dev/null && echo -e "${GREEN}✓ nftables 规则已恢复${NC}"
                            fi
                        fi
                        
                        # iptables
                        if [ -f "$IPTABLES_RUNNING_BACKUP" ] && [ -s "$IPTABLES_RUNNING_BACKUP" ]; then
                            IPTABLES_CMD=$(get_iptables_cmd)
                            if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                                iptables-legacy-restore < "$IPTABLES_RUNNING_BACKUP" 2>/dev/null
                            else
                                iptables-restore < "$IPTABLES_RUNNING_BACKUP" 2>/dev/null
                            fi
                            echo -e "${GREEN}✓ iptables 规则已恢复${NC}"
                        fi
                        
                        # 其他服务
                        for service in haproxy port-forward gost-forward realm-forward rinetd nginx; do
                            if systemctl is-enabled "$service" >/dev/null 2>&1; then
                                systemctl start "$service" 2>/dev/null && echo -e "${GREEN}✓ $service 已启动${NC}"
                            fi
                        done
                        ;;
                    0)
                        exec $0
                        ;;
                    *)
                        echo -e "${RED}无效选择${NC}"
                        ;;
                esac
            fi
        fi
        echo ""
        echo -e "${YELLOW}按回车键返回主菜单...${NC}"
        read
        exec $0
        ;;
    5)
        # 流量统计
        echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}${BOLD}║           流量统计                        ║${NC}"
        echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}说明: 仅 iptables/nftables 方案支持内置流量统计${NC}"
        echo -e "${DIM}其他方案 (realm/gost/haproxy等) 需通过各自管理界面查看${NC}"
        echo ""
        
        TOTAL_TRAFFIC=0
        HAS_RULES=false
        
        # nftables 流量统计 (支持 IPv4 和 IPv6)
        if command -v nft >/dev/null 2>&1; then
            NFT_RULES=$(nft list chain inet port_forward prerouting 2>/dev/null | grep -E "dnat ip6? to")
            if [ -n "$NFT_RULES" ]; then
                echo -e "${CYAN}${BOLD}=== nftables 转发流量 ===${NC}"
                echo "$NFT_RULES" | while read line; do
                    LOCAL_P=$(echo "$line" | grep -oE 'dport [0-9]+' | awk '{print $2}')
                    # 匹配 IPv4 或 IPv6 目标
                    if echo "$line" | grep -q "dnat ip6 to"; then
                        # IPv6 格式: dnat ip6 to [xxxx:xxxx:...]:port
                        TARGET=$(echo "$line" | grep -oE 'dnat ip6 to \[[^\]]+\]:[0-9]+' | sed 's/dnat ip6 to //')
                    else
                        # IPv4 格式: dnat ip to x.x.x.x:port
                        TARGET=$(echo "$line" | grep -oE 'dnat ip to [0-9.]+:[0-9]+' | sed 's/dnat ip to //')
                    fi
                    BYTES=$(echo "$line" | grep -oE 'bytes [0-9]+' | awk '{print $2}')
                    PACKETS=$(echo "$line" | grep -oE 'packets [0-9]+' | awk '{print $2}')
                    TRAFFIC_FMT=$(format_traffic "${BYTES:-0}")
                    if [ -n "$LOCAL_P" ] && [ -n "$TARGET" ]; then
                        HAS_RULES=true
                        echo -e "  :${LOCAL_P} -> ${TARGET}"
                        echo -e "    流量: ${GREEN}${TRAFFIC_FMT}${NC}  包数: ${CYAN}${PACKETS:-0}${NC}"
                    fi
                done
                echo ""
            fi
        fi
        
        # iptables 流量统计
        IPTABLES_CMD=$(get_iptables_cmd)
        DNAT_RULES=$($IPTABLES_CMD -t nat -L PREROUTING -n -v 2>/dev/null | grep DNAT)
        if [ -n "$DNAT_RULES" ]; then
            echo -e "${CYAN}${BOLD}=== iptables 转发流量 ===${NC}"
            echo "$DNAT_RULES" | while read line; do
                LOCAL_P=$(echo "$line" | grep -oE 'dpt:[0-9]+' | cut -d: -f2)
                TARGET=$(echo "$line" | grep -oE 'to:[0-9.]+:[0-9]+' | sed 's/to://')
                PACKETS=$(echo "$line" | awk '{print $1}')
                BYTES=$(echo "$line" | awk '{print $2}')
                TRAFFIC_FMT=$(format_traffic "${BYTES:-0}")
                if [ -n "$LOCAL_P" ] && [ -n "$TARGET" ]; then
                    HAS_RULES=true
                    echo -e "  :${LOCAL_P} -> ${TARGET}"
                    echo -e "    流量: ${GREEN}${TRAFFIC_FMT}${NC}  包数: ${CYAN}${PACKETS:-0}${NC}"
                fi
            done
            echo ""
        fi
        
        # 用户态服务统计 (通过 iptables/nftables 统计)
        echo -e "${CYAN}${BOLD}=== 用户态服务流量 ===${NC}"
        echo -e "${DIM}(通过 iptables INPUT 链统计)${NC}"
        echo ""
        
        # 收集所有用户态服务的端口
        USER_PORTS=""
        
        # realm 端口
        if [ -f /etc/realm/config.toml ] && systemctl is-active realm-forward >/dev/null 2>&1; then
            REALM_PORTS=$(grep -E "^listen" /etc/realm/config.toml 2>/dev/null | grep -oE '[0-9]+$')
            USER_PORTS="$USER_PORTS $REALM_PORTS"
            for port in $REALM_PORTS; do
                # 检查是否已有统计规则
                if ! iptables -L INPUT -n -v 2>/dev/null | grep -q "dpt:$port.*ACCEPT"; then
                    # 添加统计规则 (不影响转发，只统计)
                    iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                    iptables -I INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
                fi
                # 获取流量
                TCP_STATS=$(iptables -L INPUT -n -v 2>/dev/null | grep "dpt:$port" | grep tcp | head -1)
                TCP_BYTES=$(echo "$TCP_STATS" | awk '{print $2}')
                TCP_PKTS=$(echo "$TCP_STATS" | awk '{print $1}')
                UDP_STATS=$(iptables -L INPUT -n -v 2>/dev/null | grep "dpt:$port" | grep udp | head -1)
                UDP_BYTES=$(echo "$UDP_STATS" | awk '{print $2}')
                # 获取目标
                TARGET=$(grep -A1 "listen.*:$port" /etc/realm/config.toml 2>/dev/null | grep remote | sed -n 's/.*remote = "\([^"]*\)".*/\1/p')
                TRAFFIC_FMT=$(format_traffic "${TCP_BYTES:-0}")
                echo -e "  ${GREEN}realm${NC} :$port -> $TARGET"
                echo -e "    流量: ${GREEN}${TRAFFIC_FMT}${NC}  包数: ${CYAN}${TCP_PKTS:-0}${NC}"
            done
        fi
        
        # gost 端口
        if [ -f /etc/gost/config.yaml ] && systemctl is-active gost-forward >/dev/null 2>&1; then
            GOST_PORTS=$(grep "addr:" /etc/gost/config.yaml 2>/dev/null | grep -oE ':[0-9]+' | tr -d ':')
            for port in $GOST_PORTS; do
                if ! iptables -L INPUT -n -v 2>/dev/null | grep -q "dpt:$port.*ACCEPT"; then
                    iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                fi
                TCP_STATS=$(iptables -L INPUT -n -v 2>/dev/null | grep "dpt:$port" | grep tcp | head -1)
                TCP_BYTES=$(echo "$TCP_STATS" | awk '{print $2}')
                TCP_PKTS=$(echo "$TCP_STATS" | awk '{print $1}')
                TRAFFIC_FMT=$(format_traffic "${TCP_BYTES:-0}")
                echo -e "  ${YELLOW}gost${NC} :$port"
                echo -e "    流量: ${GREEN}${TRAFFIC_FMT}${NC}  包数: ${CYAN}${TCP_PKTS:-0}${NC}"
            done
        fi
        
        # haproxy 端口
        if [ -f /etc/haproxy/haproxy.cfg ] && systemctl is-active haproxy >/dev/null 2>&1; then
            HAPROXY_PORTS=$(grep "bind \*:" /etc/haproxy/haproxy.cfg 2>/dev/null | grep -oE ':[0-9]+' | tr -d ':' | grep -v 8888)
            for port in $HAPROXY_PORTS; do
                if ! iptables -L INPUT -n -v 2>/dev/null | grep -q "dpt:$port.*ACCEPT"; then
                    iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                fi
                TCP_STATS=$(iptables -L INPUT -n -v 2>/dev/null | grep "dpt:$port" | grep tcp | head -1)
                TCP_BYTES=$(echo "$TCP_STATS" | awk '{print $2}')
                TCP_PKTS=$(echo "$TCP_STATS" | awk '{print $1}')
                TRAFFIC_FMT=$(format_traffic "${TCP_BYTES:-0}")
                echo -e "  ${BLUE}haproxy${NC} :$port"
                echo -e "    流量: ${GREEN}${TRAFFIC_FMT}${NC}  包数: ${CYAN}${TCP_PKTS:-0}${NC}"
            done
        fi
        
        # socat 端口
        SOCAT_SERVICES=$(systemctl list-units --type=service --state=running 2>/dev/null | grep "port-forward-" | awk '{print $1}')
        if [ -n "$SOCAT_SERVICES" ]; then
            for svc in $SOCAT_SERVICES; do
                port=$(echo "$svc" | grep -oE "[0-9]+" | head -1)
                if [ -n "$port" ]; then
                    if ! iptables -L INPUT -n -v 2>/dev/null | grep -q "dpt:$port.*ACCEPT"; then
                        iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                    fi
                    TCP_STATS=$(iptables -L INPUT -n -v 2>/dev/null | grep "dpt:$port" | grep tcp | head -1)
                    TCP_BYTES=$(echo "$TCP_STATS" | awk '{print $2}')
                    TCP_PKTS=$(echo "$TCP_STATS" | awk '{print $1}')
                    TRAFFIC_FMT=$(format_traffic "${TCP_BYTES:-0}")
                    echo -e "  ${CYAN}socat${NC} :$port"
                    echo -e "    流量: ${GREEN}${TRAFFIC_FMT}${NC}  包数: ${CYAN}${TCP_PKTS:-0}${NC}"
                fi
            done
        fi
        
        # nginx stream 端口
        if [ -d /etc/nginx/stream.d ] && systemctl is-active nginx >/dev/null 2>&1; then
            for conf in /etc/nginx/stream.d/port-forward-*.conf; do
                [ -f "$conf" ] || continue
                port=$(grep "listen" "$conf" | grep -oE '[0-9]+' | head -1)
                if [ -n "$port" ]; then
                    if ! iptables -L INPUT -n -v 2>/dev/null | grep -q "dpt:$port.*ACCEPT"; then
                        iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                    fi
                    TCP_STATS=$(iptables -L INPUT -n -v 2>/dev/null | grep "dpt:$port" | grep tcp | head -1)
                    TCP_BYTES=$(echo "$TCP_STATS" | awk '{print $2}')
                    TCP_PKTS=$(echo "$TCP_STATS" | awk '{print $1}')
                    TRAFFIC_FMT=$(format_traffic "${TCP_BYTES:-0}")
                    echo -e "  ${MAGENTA}nginx${NC} :$port"
                    echo -e "    流量: ${GREEN}${TRAFFIC_FMT}${NC}  包数: ${CYAN}${TCP_PKTS:-0}${NC}"
                fi
            done
        fi
        
        echo ""
        
        # 连接跟踪统计
        echo -e "${CYAN}${BOLD}=== 连接跟踪统计 ===${NC}"
        if [ -f /proc/net/nf_conntrack ]; then
            TOTAL_CONN=$(cat /proc/net/nf_conntrack 2>/dev/null | wc -l)
            ESTABLISHED=$(cat /proc/net/nf_conntrack 2>/dev/null | grep -c ESTABLISHED)
            SYN_SENT=$(cat /proc/net/nf_conntrack 2>/dev/null | grep -c SYN_SENT)
            TIME_WAIT=$(cat /proc/net/nf_conntrack 2>/dev/null | grep -c TIME_WAIT)
            echo -e "  总连接数: ${GREEN}${TOTAL_CONN}${NC}"
            echo -e "  ESTABLISHED: ${GREEN}${ESTABLISHED}${NC}"
            echo -e "  SYN_SENT: ${YELLOW}${SYN_SENT}${NC}"
            echo -e "  TIME_WAIT: ${CYAN}${TIME_WAIT}${NC}"
        else
            echo -e "  ${DIM}连接跟踪信息不可用${NC}"
        fi
        
        # 网络接口流量
        echo ""
        echo -e "${CYAN}${BOLD}=== 网络接口流量 ===${NC}"
        for iface in $(ls /sys/class/net/ 2>/dev/null | grep -v lo); do
            RX_BYTES=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo "0")
            TX_BYTES=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo "0")
            RX_FMT=$(format_traffic "$RX_BYTES")
            TX_FMT=$(format_traffic "$TX_BYTES")
            echo -e "  ${BOLD}$iface${NC}: 接收 ${GREEN}${RX_FMT}${NC} / 发送 ${CYAN}${TX_FMT}${NC}"
        done
        
        echo ""
        echo -e "${YELLOW}提示: 流量统计会在服务/iptables重启后重置${NC}"
        echo -e "${DIM}用户态服务流量通过 iptables INPUT 链统计${NC}"
        echo ""
        echo "按回车键返回主菜单..."
        read
        exec $0
        ;;
    6)
        echo -e "${CYAN}${BOLD}=== 卸载转发服务 ===${NC}"
        echo ""
        echo -e "${YELLOW}请选择要卸载的服务：${NC}"
        echo -e "1) iptables DNAT 规则"
        echo -e "2) nftables DNAT 规则"
        echo -e "3) HAProxy"
        echo -e "4) socat (port-forward)"
        echo -e "5) gost"
        echo -e "6) realm"
        echo -e "7) rinetd"
        echo -e "8) nginx stream配置"
        echo -e "9) ${RED}卸载所有服务${NC}"
        echo -e "0) 返回主菜单"
        echo ""
        read -p "$(echo -e ${YELLOW}请选择 [0]: ${NC})" UNINSTALL_CHOICE
        UNINSTALL_CHOICE=${UNINSTALL_CHOICE:-0}
        
        if [ "$UNINSTALL_CHOICE" = "0" ]; then
            exec $0
        fi
        
        echo -e "${RED}警告：此操作将卸载选定的服务！${NC}"
        read -p "$(echo -e ${YELLOW}确认卸载? [y/N]: ${NC})" CONFIRM_UNINSTALL
        
        if [[ $CONFIRM_UNINSTALL =~ ^[Yy]$ ]]; then
            case $UNINSTALL_CHOICE in
                1)
                    echo -e "${YELLOW}清理 iptables DNAT 规则...${NC}"
                    IPTABLES_CMD=$(get_iptables_cmd)
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    rm -f /root/.port_forward_iptables_running.txt 2>/dev/null
                    echo -e "${GREEN}✓ iptables DNAT 规则已清理${NC}"
                    ;;
                2)
                    echo -e "${YELLOW}清理 nftables DNAT 规则...${NC}"
                    if command -v nft >/dev/null 2>&1; then
                        nft delete table inet port_forward 2>/dev/null || true
                        rm -f /etc/nftables.d/port_forward.nft 2>/dev/null || true
                        rm -f /root/.port_forward_nftables_running.txt 2>/dev/null
                        echo -e "${GREEN}✓ nftables DNAT 规则已清理${NC}"
                    else
                        echo -e "${YELLOW}nftables 未安装${NC}"
                    fi
                    ;;
                3)
                    systemctl stop haproxy 2>/dev/null || true
                    systemctl disable haproxy 2>/dev/null || true
                    echo -e "${GREEN}✓ HAProxy已停止和禁用${NC}"
                    ;;
                4)
                    systemctl stop port-forward 2>/dev/null || true
                    systemctl disable port-forward 2>/dev/null || true
                    rm -f /etc/systemd/system/port-forward.service
                    systemctl daemon-reload
                    echo -e "${GREEN}✓ socat转发服务已卸载${NC}"
                    ;;
                5)
                    systemctl stop gost-forward 2>/dev/null || true
                    systemctl disable gost-forward 2>/dev/null || true
                    rm -f /etc/systemd/system/gost-forward.service
                    rm -f /usr/local/bin/gost
                    rm -rf /etc/gost
                    systemctl daemon-reload
                    echo -e "${GREEN}✓ gost已卸载${NC}"
                    ;;
                6)
                    systemctl stop realm-forward 2>/dev/null || true
                    systemctl disable realm-forward 2>/dev/null || true
                    rm -f /etc/systemd/system/realm-forward.service
                    rm -rf /etc/realm
                    rm -f /usr/local/bin/realm
                    systemctl daemon-reload
                    echo -e "${GREEN}✓ realm已卸载${NC}"
                    ;;
                7)
                    systemctl stop rinetd 2>/dev/null || true
                    systemctl disable rinetd 2>/dev/null || true
                    rm -f /etc/rinetd.conf
                    echo -e "${GREEN}✓ rinetd已停止和禁用${NC}"
                    ;;
                8)
                    # 删除stream转发配置文件
                    if [ -d /etc/nginx/stream.d ]; then
                        rm -f /etc/nginx/stream.d/port-forward-*.conf
                    fi
                    
                    # 如果stream.d目录为空，清理nginx.conf中的stream块
                    if [ -d /etc/nginx/stream.d ] && [ -z "$(ls -A /etc/nginx/stream.d 2>/dev/null)" ]; then
                        echo -e "${YELLOW}清理nginx.conf中的stream配置...${NC}"
                        # 删除stream块
                        sed -i '/^# Stream模块配置/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
                        sed -i '/^stream {/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
                        rmdir /etc/nginx/stream.d 2>/dev/null || true
                    fi
                    
                    # 重载nginx（如果还在运行）
                    if systemctl is-active nginx >/dev/null 2>&1; then
                        nginx -t 2>/dev/null && nginx -s reload 2>/dev/null
                    fi
                    echo -e "${GREEN}✓ nginx stream配置已删除${NC}"
                    ;;
                9)
                    echo -e "${YELLOW}卸载所有转发服务...${NC}"
                    
                    # 停止所有服务
                    systemctl stop haproxy port-forward gost-forward realm-forward rinetd nginx 2>/dev/null || true
                    systemctl disable haproxy port-forward gost-forward realm-forward rinetd 2>/dev/null || true
                    
                    # 清理进程
                    pkill -f "socat.*tcp-listen" 2>/dev/null || true
                    pkill -f "gost.*forward" 2>/dev/null || true
                    pkill -f "realm.*forward" 2>/dev/null || true
                    
                    # 删除服务文件
                    rm -f /etc/systemd/system/port-forward.service
                    rm -f /etc/systemd/system/gost-forward.service
                    rm -f /etc/systemd/system/realm-forward.service
                    rm -f /etc/systemd/system/port-forward-restore.service
                    
                    # 删除配置文件
                    rm -rf /etc/realm /etc/gost
                    rm -f /etc/haproxy/haproxy.cfg /etc/rinetd.conf
                    rm -f /root/haproxy_credentials.txt /root/gost_credentials.txt
                    rm -f /root/.port_forward_iptables_running.txt
                    rm -f /root/.port_forward_nftables_running.txt
                    rm -rf /var/lib/port-forward
                    
                    # 清理nginx stream配置
                    if [ -d /etc/nginx/stream.d ]; then
                        rm -f /etc/nginx/stream.d/port-forward-*.conf
                        # 如果目录为空，清理nginx.conf中的stream块
                        if [ -z "$(ls -A /etc/nginx/stream.d 2>/dev/null)" ]; then
                            sed -i '/^# Stream模块配置/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
                            sed -i '/^stream {/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
                            rmdir /etc/nginx/stream.d 2>/dev/null || true
                        fi
                    fi
                    
                    # 清理 nftables 规则
                    if command -v nft >/dev/null 2>&1; then
                        nft delete table inet port_forward 2>/dev/null || true
                        rm -f /etc/nftables.d/port_forward.nft 2>/dev/null || true
                        echo -e "${GREEN}✓ nftables 规则已清理${NC}"
                    fi
                    
                    # 清理iptables
                    IPTABLES_CMD=$(get_iptables_cmd)
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    echo -e "${GREEN}✓ iptables 规则已清理${NC}"
                    
                    # 删除二进制文件
                    rm -f /usr/local/bin/gost /usr/local/bin/realm
                    
                    # 删除脚本
                    rm -f /usr/local/bin/pf /usr/local/bin/port_forward.sh /usr/bin/pf
                    
                    systemctl daemon-reload
                    
                    # 询问是否删除备份
                    read -p "$(echo -e ${YELLOW}是否删除所有配置备份? [y/N]: ${NC})" DELETE_BACKUPS
                    [[ $DELETE_BACKUPS =~ ^[Yy]$ ]] && rm -rf /root/.port_forward_backups
                    
                    echo ""
                    echo -e "${GREEN}${BOLD}✓ 所有转发服务已完全卸载！${NC}"
                    exit 0
                    ;;
                *)
                    echo -e "${RED}无效选择${NC}"
                    ;;
            esac
        else
            echo -e "${YELLOW}卸载已取消${NC}"
        fi
        echo ""
        echo -e "${YELLOW}按回车键返回主菜单...${NC}"
        read
        exec $0
        ;;
    7)
        # 导入/导出配置
        echo -e "${CYAN}${BOLD}=== 导入/导出配置 ===${NC}"
        echo ""
        echo "1) 导出当前配置"
        echo "2) 导入配置文件"
        echo "3) 查看备份文件"
        echo "0) 返回主菜单"
        echo ""
        read -p "请选择 [0]: " EXPORT_CHOICE
        EXPORT_CHOICE=${EXPORT_CHOICE:-0}
        
        case $EXPORT_CHOICE in
            1)
                # 导出配置
                echo ""
                echo -e "${CYAN}正在导出配置...${NC}"
                
                EXPORT_DIR="/var/lib/port-forward"
                mkdir -p "$EXPORT_DIR"
                EXPORT_FILE="$EXPORT_DIR/backup_$(date '+%Y%m%d_%H%M%S').json"
                
                # 构建导出数据
                export_data='{"export_info":{},"forward_rules":[]}'
                
                # 添加导出信息
                export_data=$(echo "$export_data" | jq \
                    --arg version "$VERSION" \
                    --arg export_time "$(date '+%Y-%m-%dT%H:%M:%S')" \
                    --arg ipv4 "$(get_local_ip)" \
                    '.export_info.version = $version | .export_info.export_time = $export_time | .export_info.source_ip = $ipv4')
                
                # 收集 nftables 规则
                if command -v nft >/dev/null 2>&1; then
                    nft_rules=$(nft list chain inet port_forward prerouting 2>/dev/null | grep -E "dnat ip6? to" || true)
                    if [ -n "$nft_rules" ]; then
                        while read -r line; do
                            local_p=$(echo "$line" | grep -oE 'dport [0-9]+' | awk '{print $2}')
                            if echo "$line" | grep -q "dnat ip6 to"; then
                                target=$(echo "$line" | grep -oE 'dnat ip6 to \[[^\]]+\]:[0-9]+' | sed 's/dnat ip6 to //')
                            else
                                target=$(echo "$line" | grep -oE 'dnat ip to [0-9.]+:[0-9]+' | sed 's/dnat ip to //')
                            fi
                            if [ -n "$local_p" ] && [ -n "$target" ]; then
                                target_ip=$(echo "$target" | sed 's/\[//;s/\]//;s/:[0-9]*$//')
                                target_port=$(echo "$target" | grep -oE '[0-9]+$')
                                export_data=$(echo "$export_data" | jq \
                                    --arg type "nftables" \
                                    --arg local_port "$local_p" \
                                    --arg target_ip "$target_ip" \
                                    --arg target_port "$target_port" \
                                    '.forward_rules += [{"type":$type,"local_port":$local_port,"target_ip":$target_ip,"target_port":$target_port}]')
                            fi
                        done <<< "$nft_rules"
                    fi
                fi
                
                # 收集 iptables 规则
                IPTABLES_CMD=$(get_iptables_cmd)
                iptables_rules=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep DNAT || true)
                if [ -n "$iptables_rules" ]; then
                    while read -r line; do
                        local_p=$(echo "$line" | grep -oE 'dpt:[0-9]+' | cut -d: -f2)
                        target=$(echo "$line" | grep -oE 'to:[0-9.]+:[0-9]+' | sed 's/to://')
                        if [ -n "$local_p" ] && [ -n "$target" ]; then
                            target_ip=$(echo "$target" | cut -d: -f1)
                            target_port=$(echo "$target" | cut -d: -f2)
                            export_data=$(echo "$export_data" | jq \
                                --arg type "iptables" \
                                --arg local_port "$local_p" \
                                --arg target_ip "$target_ip" \
                                --arg target_port "$target_port" \
                                '.forward_rules += [{"type":$type,"local_port":$local_port,"target_ip":$target_ip,"target_port":$target_port}]')
                        fi
                    done <<< "$iptables_rules"
                fi
                
                # 收集 realm 配置
                if [ -f /etc/realm/config.toml ]; then
                    while IFS= read -r listen_line; do
                        local_p=$(echo "$listen_line" | grep -oE '[0-9]+$')
                        read -r remote_line
                        target=$(echo "$remote_line" | sed -n 's/.*remote = "\([^"]*\)".*/\1/p')
                        if [ -n "$local_p" ] && [ -n "$target" ]; then
                            if [[ "$target" =~ ^\[.*\]:[0-9]+$ ]]; then
                                target_ip=$(echo "$target" | sed 's/\[\(.*\)\]:.*/\1/')
                                target_port=$(echo "$target" | sed 's/.*\]://')
                            else
                                target_ip=$(echo "$target" | cut -d: -f1)
                                target_port=$(echo "$target" | cut -d: -f2)
                            fi
                            export_data=$(echo "$export_data" | jq \
                                --arg type "realm" \
                                --arg local_port "$local_p" \
                                --arg target_ip "$target_ip" \
                                --arg target_port "$target_port" \
                                '.forward_rules += [{"type":$type,"local_port":$local_port,"target_ip":$target_ip,"target_port":$target_port}]')
                        fi
                    done < <(grep -E "^listen|^remote" /etc/realm/config.toml 2>/dev/null)
                fi
                
                # 收集 gost 配置
                if [ -f /etc/gost/config.json ]; then
                    export_data=$(echo "$export_data" | jq --slurpfile gost /etc/gost/config.json '.gost_config = $gost[0]')
                fi
                
                # 收集 haproxy 配置
                if [ -f /etc/haproxy/haproxy.cfg ]; then
                    haproxy_content=$(cat /etc/haproxy/haproxy.cfg | base64 -w 0)
                    export_data=$(echo "$export_data" | jq --arg cfg "$haproxy_content" '.haproxy_config = $cfg')
                fi
                
                # 写入文件
                echo "$export_data" | jq . > "$EXPORT_FILE"
                
                if [ -f "$EXPORT_FILE" ]; then
                    file_size=$(stat -c%s "$EXPORT_FILE" 2>/dev/null || stat -f%z "$EXPORT_FILE" 2>/dev/null)
                    rule_count=$(echo "$export_data" | jq '.forward_rules | length')
                    echo ""
                    echo -e "${GREEN}✓ 配置导出成功${NC}"
                    echo -e "  文件路径: ${CYAN}$EXPORT_FILE${NC}"
                    echo -e "  文件大小: ${file_size} 字节"
                    echo -e "  规则数量: ${rule_count} 条"
                    echo ""
                    echo -e "${DIM}提示: 可使用 scp 下载此文件${NC}"
                    echo -e "${DIM}示例: scp root@$(get_local_ip):$EXPORT_FILE ./backup.json${NC}"
                else
                    echo -e "${RED}导出失败${NC}"
                fi
                ;;
            2)
                # 导入配置
                echo ""
                
                # 列出可用的备份文件
                EXPORT_DIR="/var/lib/port-forward"
                backup_files=()
                if [ -d "$EXPORT_DIR" ]; then
                    while IFS= read -r f; do
                        [ -n "$f" ] && backup_files+=("$f")
                    done < <(ls -t "$EXPORT_DIR"/backup_*.json 2>/dev/null)
                fi
                
                if [ ${#backup_files[@]} -gt 0 ]; then
                    echo -e "${CYAN}可用的备份文件:${NC}"
                    i=1
                    for f in "${backup_files[@]}"; do
                        fname=$(basename "$f")
                        fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
                        echo -e "  ${GREEN}$i)${NC} $fname (${fsize}B)"
                        ((i++))
                    done
                    echo ""
                fi
                
                echo -e "${DIM}输入备份文件路径，或输入序号选择上方文件${NC}"
                read -p "文件路径: " import_path
                
                [ -z "$import_path" ] && { echo -e "${YELLOW}已取消${NC}"; exec $0; }
                
                # 如果输入的是数字，选择对应的备份文件
                if [[ "$import_path" =~ ^[0-9]+$ ]] && [ "$import_path" -le ${#backup_files[@]} ]; then
                    import_path="${backup_files[$((import_path-1))]}"
                fi
                
                # 验证文件
                if [ ! -f "$import_path" ]; then
                    echo -e "${RED}文件不存在: $import_path${NC}"
                    exec $0
                fi
                
                if ! jq empty "$import_path" 2>/dev/null; then
                    echo -e "${RED}无效的 JSON 格式${NC}"
                    exec $0
                fi
                
                # 显示配置信息
                echo ""
                echo -e "${CYAN}配置文件信息:${NC}"
                export_version=$(jq -r '.export_info.version // "未知"' "$import_path")
                export_time=$(jq -r '.export_info.export_time // "未知"' "$import_path")
                source_ip=$(jq -r '.export_info.source_ip // "未知"' "$import_path")
                rule_count=$(jq '.forward_rules | length' "$import_path")
                
                echo -e "  导出版本: $export_version"
                echo -e "  导出时间: $export_time"
                echo -e "  源服务器: $source_ip"
                echo -e "  规则数量: ${GREEN}$rule_count${NC} 条"
                echo ""
                
                # 显示规则列表
                if [ "$rule_count" -gt 0 ]; then
                    echo -e "${CYAN}转发规则:${NC}"
                    jq -r '.forward_rules[] | "  \(.type): :\(.local_port) -> \(.target_ip):\(.target_port)"' "$import_path"
                    echo ""
                fi
                
                echo -e "${YELLOW}选择导入方式:${NC}"
                echo "1) 使用 nftables 导入所有规则"
                echo "2) 使用 iptables 导入所有规则"
                echo "3) 使用 realm 导入所有规则"
                echo "0) 取消"
                echo ""
                read -p "请选择 [1]: " import_method
                import_method=${import_method:-1}
                
                case $import_method in
                    1)
                        # 使用 nftables 导入
                        echo ""
                        echo -e "${CYAN}使用 nftables 导入规则...${NC}"
                        
                        # 启用 IP 转发
                        echo 1 > /proc/sys/net/ipv4/ip_forward
                        grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
                        
                        # 创建 nftables 表和链
                        nft add table inet port_forward 2>/dev/null || true
                        nft add chain inet port_forward prerouting '{ type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true
                        nft add chain inet port_forward postrouting '{ type nat hook postrouting priority srcnat; policy accept; }' 2>/dev/null || true
                        
                        # 导入规则
                        jq -c '.forward_rules[]' "$import_path" | while read -r rule; do
                            local_p=$(echo "$rule" | jq -r '.local_port')
                            target_ip=$(echo "$rule" | jq -r '.target_ip')
                            target_port=$(echo "$rule" | jq -r '.target_port')
                            
                            if [[ "$target_ip" =~ : ]]; then
                                # IPv6
                                nft add rule inet port_forward prerouting ip6 nexthdr tcp tcp dport "$local_p" counter dnat ip6 to "[$target_ip]:$target_port" 2>/dev/null
                                nft add rule inet port_forward postrouting ip6 daddr "$target_ip" tcp dport "$target_port" counter masquerade 2>/dev/null
                            else
                                # IPv4
                                nft add rule inet port_forward prerouting ip protocol tcp tcp dport "$local_p" counter dnat ip to "$target_ip:$target_port" 2>/dev/null
                                nft add rule inet port_forward postrouting ip daddr "$target_ip" tcp dport "$target_port" counter masquerade 2>/dev/null
                            fi
                            echo -e "  ${GREEN}✓${NC} :$local_p -> $target_ip:$target_port"
                        done
                        
                        # 保存规则
                        mkdir -p /etc/nftables.d
                        nft list table inet port_forward > /etc/nftables.d/port_forward.nft 2>/dev/null
                        systemctl enable nftables 2>/dev/null || true
                        
                        echo ""
                        echo -e "${GREEN}✓ 导入完成${NC}"
                        ;;
                    2)
                        # 使用 iptables 导入
                        echo ""
                        echo -e "${CYAN}使用 iptables 导入规则...${NC}"
                        
                        IPTABLES_CMD=$(get_iptables_cmd)
                        
                        # 启用 IP 转发
                        echo 1 > /proc/sys/net/ipv4/ip_forward
                        grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
                        
                        # 导入规则
                        jq -c '.forward_rules[]' "$import_path" | while read -r rule; do
                            local_p=$(echo "$rule" | jq -r '.local_port')
                            target_ip=$(echo "$rule" | jq -r '.target_ip')
                            target_port=$(echo "$rule" | jq -r '.target_port')
                            
                            $IPTABLES_CMD -t nat -A PREROUTING -p tcp --dport "$local_p" -j DNAT --to-destination "$target_ip:$target_port" 2>/dev/null
                            $IPTABLES_CMD -t nat -A POSTROUTING -p tcp -d "$target_ip" --dport "$target_port" -j MASQUERADE 2>/dev/null
                            echo -e "  ${GREEN}✓${NC} :$local_p -> $target_ip:$target_port"
                        done
                        
                        # 保存规则
                        if [ -f /etc/debian_version ]; then
                            netfilter-persistent save >/dev/null 2>&1
                        elif [ -f /etc/redhat-release ]; then
                            service iptables save >/dev/null 2>&1
                        fi
                        
                        echo ""
                        echo -e "${GREEN}✓ 导入完成${NC}"
                        ;;
                    3)
                        # 使用 realm 导入
                        echo ""
                        echo -e "${CYAN}使用 realm 导入规则...${NC}"
                        
                        # 检查 realm 是否安装
                        if ! command -v realm >/dev/null 2>&1; then
                            echo -e "${YELLOW}正在安装 realm...${NC}"
                            # 下载安装 realm
                            ARCH=$(uname -m)
                            case $ARCH in
                                x86_64) REALM_ARCH="x86_64-unknown-linux-gnu" ;;
                                aarch64) REALM_ARCH="aarch64-unknown-linux-gnu" ;;
                                *) echo -e "${RED}不支持的架构: $ARCH${NC}"; exec $0 ;;
                            esac
                            REALM_URL="https://github.com/zhboner/realm/releases/latest/download/realm-${REALM_ARCH}.tar.gz"
                            smart_download "$REALM_URL" "/tmp/realm.tar.gz" 30
                            tar -xzf /tmp/realm.tar.gz -C /usr/local/bin/
                            chmod +x /usr/local/bin/realm
                            rm -f /tmp/realm.tar.gz
                        fi
                        
                        # 生成配置
                        mkdir -p /etc/realm
                        cat > /etc/realm/config.toml << 'REALM_HEADER'
[log]
level = "warn"
output = "/var/log/realm.log"

[network]
no_tcp = false
use_udp = true

REALM_HEADER
                        
                        jq -c '.forward_rules[]' "$import_path" | while read -r rule; do
                            local_p=$(echo "$rule" | jq -r '.local_port')
                            target_ip=$(echo "$rule" | jq -r '.target_ip')
                            target_port=$(echo "$rule" | jq -r '.target_port')
                            
                            if [[ "$target_ip" =~ : ]]; then
                                target="[$target_ip]:$target_port"
                            else
                                target="$target_ip:$target_port"
                            fi
                            
                            cat >> /etc/realm/config.toml << EOF

[[endpoints]]
listen = "0.0.0.0:$local_p"
remote = "$target"
EOF
                            echo -e "  ${GREEN}✓${NC} :$local_p -> $target"
                        done
                        
                        # 创建服务
                        cat > /etc/systemd/system/realm-forward.service << 'EOF'
[Unit]
Description=Realm Port Forward
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/realm/config.toml
Restart=always
RestartSec=3
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
                        
                        systemctl daemon-reload
                        systemctl enable realm-forward
                        systemctl restart realm-forward
                        
                        echo ""
                        echo -e "${GREEN}✓ 导入完成${NC}"
                        ;;
                    *)
                        echo -e "${YELLOW}已取消${NC}"
                        ;;
                esac
                ;;
            3)
                # 查看备份文件
                echo ""
                echo -e "${CYAN}${BOLD}=== 备份文件列表 ===${NC}"
                echo ""
                BACKUP_BASE_DIR="/root/.port_forward_backups"
                EXPORT_DIR="/var/lib/port-forward"
                
                # 收集所有备份文件
                backup_list=()
                backup_types=()
                
                # 收集配置备份
                if [ -d "$BACKUP_BASE_DIR" ]; then
                    while IFS= read -r backup; do
                        [ -n "$backup" ] && backup_list+=("$backup") && backup_types+=("config")
                    done < <(ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -10)
                fi
                
                # 收集导出文件
                if [ -d "$EXPORT_DIR" ]; then
                    while IFS= read -r f; do
                        [ -n "$f" ] && backup_list+=("$f") && backup_types+=("export")
                    done < <(ls -t "$EXPORT_DIR"/backup_*.json 2>/dev/null | head -10)
                fi
                
                if [ ${#backup_list[@]} -eq 0 ]; then
                    echo -e "${YELLOW}没有找到备份文件${NC}"
                else
                    echo -e "${CYAN}可用备份:${NC}"
                    i=1
                    for idx in "${!backup_list[@]}"; do
                        f="${backup_list[$idx]}"
                        t="${backup_types[$idx]}"
                        if [ "$t" = "config" ]; then
                            timestamp=$(basename "$f")
                            size=$(du -sh "$f" 2>/dev/null | awk '{print $1}')
                            # 尝试读取备份信息
                            info=""
                            if [ -f "$f/method" ]; then
                                method=$(cat "$f/method" 2>/dev/null)
                                info=" [$method]"
                            fi
                            echo -e "  ${GREEN}$i)${NC} $timestamp (${size})${info} ${DIM}[配置备份]${NC}"
                        else
                            fname=$(basename "$f")
                            fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
                            # 读取规则数量
                            rule_count=$(jq '.forward_rules | length' "$f" 2>/dev/null || echo "?")
                            echo -e "  ${GREEN}$i)${NC} $fname (${fsize}B) ${DIM}[$rule_count 条规则]${NC}"
                        fi
                        ((i++))
                    done
                    echo ""
                    echo -e "  ${GREEN}0)${NC} 返回"
                    echo ""
                    read -p "$(echo -e ${YELLOW}输入序号查看详情 [0]: ${NC})" view_choice
                    view_choice=${view_choice:-0}
                    
                    if [[ "$view_choice" =~ ^[0-9]+$ ]] && [ "$view_choice" -gt 0 ] && [ "$view_choice" -le ${#backup_list[@]} ]; then
                        selected="${backup_list[$((view_choice-1))]}"
                        selected_type="${backup_types[$((view_choice-1))]}"
                        echo ""
                        echo -e "${CYAN}${BOLD}=== 备份详情 ===${NC}"
                        echo -e "路径: ${selected}"
                        echo ""
                        
                        if [ "$selected_type" = "export" ]; then
                            # JSON 导出文件
                            echo -e "${CYAN}导出信息:${NC}"
                            jq -r '.export_info | "  时间: \(.export_time)\n  版本: \(.version)\n  来源IP: \(.source_ip)"' "$selected" 2>/dev/null
                            echo ""
                            echo -e "${CYAN}转发规则:${NC}"
                            jq -r '.forward_rules[] | "  \(.type): :\(.local_port) -> \(.target_ip):\(.target_port)"' "$selected" 2>/dev/null
                        else
                            # 配置备份目录
                            echo -e "${CYAN}转发配置:${NC}"
                            
                            # 优先读取 backup_info.txt
                            if [ -f "$selected/backup_info.txt" ]; then
                                cat "$selected/backup_info.txt" | while read line; do
                                    echo -e "  $line"
                                done
                            else
                                # 兼容旧格式
                                [ -f "$selected/method" ] && echo -e "  转发类型: $(cat "$selected/method")"
                                [ -f "$selected/target_ip" ] && echo -e "  目标IP: $(cat "$selected/target_ip")"
                                if [ -f "$selected/ports" ]; then
                                    echo -e "  端口映射:"
                                    cat "$selected/ports" | while read line; do
                                        [ -n "$line" ] && echo -e "    $line"
                                    done
                                fi
                            fi
                            
                            # 显示具体配置文件内容
                            echo ""
                            if [ -f "$selected/iptables_backup.txt" ]; then
                                # 只显示 NAT 相关规则
                                nat_rules=$(grep -E "DNAT|MASQUERADE|SNAT" "$selected/iptables_backup.txt" 2>/dev/null | head -10)
                                if [ -n "$nat_rules" ]; then
                                    echo -e "${CYAN}iptables NAT 规则:${NC}"
                                    echo "$nat_rules" | while read line; do
                                        echo -e "  $line"
                                    done
                                fi
                            fi
                            if [ -f "$selected/nftables_rules.txt" ]; then
                                echo -e "${CYAN}nftables 规则:${NC}"
                                cat "$selected/nftables_rules.txt" | head -20 | while read line; do
                                    echo -e "  $line"
                                done
                            fi
                            if [ -f "$selected/haproxy.cfg" ]; then
                                echo -e "${CYAN}HAProxy 配置:${NC}"
                                cat "$selected/haproxy.cfg" | head -30 | while read line; do
                                    echo -e "  $line"
                                done
                            fi
                            if [ -f "$selected/realm_config.toml" ]; then
                                echo -e "${CYAN}Realm 配置:${NC}"
                                cat "$selected/realm_config.toml" | head -20 | while read line; do
                                    echo -e "  $line"
                                done
                            fi
                            if [ -f "$selected/gost_config.json" ]; then
                                echo -e "${CYAN}Gost 配置:${NC}"
                                cat "$selected/gost_config.json" | head -20 | while read line; do
                                    echo -e "  $line"
                                done
                            fi
                        fi
                    fi
                fi
                
                echo ""
                # 显示 iptables/nftables 规则备份
                echo -e "${CYAN}规则备份文件:${NC}"
                [ -f /root/.port_forward_iptables_running.txt ] && echo -e "  iptables: /root/.port_forward_iptables_running.txt"
                [ -f /root/.port_forward_nftables_running.txt ] && echo -e "  nftables: /root/.port_forward_nftables_running.txt"
                [ -f /etc/nftables.d/port_forward.nft ] && echo -e "  nftables: /etc/nftables.d/port_forward.nft"
                [ -f /etc/iptables/rules.v4 ] && echo -e "  iptables: /etc/iptables/rules.v4"
                ;;
            *)
                ;;
        esac
        
        echo ""
        echo -e "${YELLOW}按回车键返回主菜单...${NC}"
        read
        exec $0
        ;;
esac

# 以下是配置新端口转发的代码（case 1 继续执行到这里）
echo -e "${BLUE}请输入转发配置信息：${NC}"
echo ""

# 检测 IP 地址类型的函数
detect_ip_type() {
    local ip=$1
    # IPv4 检测
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ipv4"
    # IPv6 检测 (包括完整格式和压缩格式)
    elif [[ $ip =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]] || [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}:$ ]] || [[ $ip =~ ^:(:([0-9a-fA-F]{0,4})){1,7}$ ]] || [[ $ip =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ ]]; then
        echo "ipv6"
    else
        echo "unknown"
    fi
}

# 获取目标IP
IS_IPV6=false
while true; do
    read -p "$(echo -e "${YELLOW}目标服务器IP/域名: ${NC}")" TARGET_IP
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}请输入目标服务器IP或域名${NC}"
        continue
    fi
    
    IP_TYPE=$(detect_ip_type "$TARGET_IP")
    
    # 检查是否为有效的IPv4地址
    if [ "$IP_TYPE" = "ipv4" ]; then
        # 验证IP地址的每个段是否在0-255范围内
        IFS='.' read -ra IP_PARTS <<< "$TARGET_IP"
        valid_ip=true
        for part in "${IP_PARTS[@]}"; do
            if [ "$part" -lt 0 ] || [ "$part" -gt 255 ]; then
                valid_ip=false
                break
            fi
        done
        if [ "$valid_ip" = true ]; then
            echo -e "${GREEN}✅ 有效的IPv4地址: $TARGET_IP${NC}"
            IS_IPV6=false
            break
        else
            echo -e "${RED}❌ IP地址格式错误，每段应在0-255范围内${NC}"
        fi
    # 检查是否为有效的IPv6地址
    elif [ "$IP_TYPE" = "ipv6" ]; then
        echo -e "${GREEN}✅ 有效的IPv6地址: $TARGET_IP${NC}"
        IS_IPV6=true
        echo -e "${YELLOW}⚠️  注意: IPv6 转发仅支持 nftables、socat、gost、realm 方案${NC}"
        break
    # 检查是否为有效的域名
    elif [[ $TARGET_IP =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo -e "${GREEN}✅ 有效的域名: $TARGET_IP${NC}"
        # 尝试解析域名
        if command -v nslookup >/dev/null 2>&1; then
            echo -e "${YELLOW}正在解析域名...${NC}"
            RESOLVED_IP=$(nslookup "$TARGET_IP" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | head -1 | awk '{print $2}' || echo "")
            if [ -n "$RESOLVED_IP" ]; then
                echo -e "${GREEN}✅ 域名解析成功: $TARGET_IP -> $RESOLVED_IP${NC}"
                # 检测解析后的 IP 类型
                if [ "$(detect_ip_type "$RESOLVED_IP")" = "ipv6" ]; then
                    IS_IPV6=true
                    echo -e "${YELLOW}⚠️  注意: 域名解析为 IPv6，仅支持 nftables、socat、gost、realm 方案${NC}"
                fi
            else
                echo -e "${YELLOW}⚠️  域名解析失败，但将继续使用域名${NC}"
            fi
        fi
        break
    else
        echo -e "${RED}❌ 请输入有效的IP地址或域名${NC}"
        echo -e "${YELLOW}IPv4示例: 192.168.1.100${NC}"
        echo -e "${YELLOW}IPv6示例: 2409:871e:2700:100a:6508:120e:5e:a${NC}"
        echo -e "${YELLOW}域名示例: example.com${NC}"
    fi
done

# 解析端口映射的函数
# 支持格式: 单端口(80), 端口范围(80-90), 端口映射(80:8080), 多端口(80,443,8080)
parse_port_mappings() {
    local input=$1
    local mappings=()
    
    # 按逗号分割
    IFS=',' read -ra parts <<< "$input"
    for part in "${parts[@]}"; do
        part=$(echo "$part" | tr -d ' ')  # 去除空格
        
        if [[ $part =~ ^([0-9]+)-([0-9]+)$ ]]; then
            # 端口范围: 80-90 (本地和目标端口相同)
            local start=${BASH_REMATCH[1]}
            local end=${BASH_REMATCH[2]}
            for ((p=start; p<=end; p++)); do
                mappings+=("$p:$p")
            done
        elif [[ $part =~ ^([0-9]+):([0-9]+)$ ]]; then
            # 端口映射: 本地端口:目标端口
            mappings+=("$part")
        elif [[ $part =~ ^[0-9]+$ ]]; then
            # 单端口 (本地和目标端口相同)
            mappings+=("$part:$part")
        fi
    done
    
    echo "${mappings[@]}"
}

# 验证端口是否有效
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
        return 0
    fi
    return 1
}

# 获取端口配置
echo ""
echo -e "${CYAN}${BOLD}========== 端口配置 ==========${NC}"
echo -e "${YELLOW}支持的格式：${NC}"
echo -e "  单端口:     ${BOLD}3389${NC}"
echo -e "  多端口:     ${BOLD}80,443,8080${NC}"
echo -e "  端口范围:   ${BOLD}8000-8010${NC}"
echo -e "  端口映射:   ${BOLD}本地端口:目标端口${NC} (如 ${BOLD}33389:3389${NC})"
echo -e "  混合格式:   ${BOLD}80,443,8000-8005,33389:3389${NC}"
echo ""

while true; do
    read -p "$(echo -e "${YELLOW}端口配置 [3389]: ${NC}")" PORT_INPUT
    PORT_INPUT=${PORT_INPUT:-3389}
    
    # 解析端口映射
    PORT_MAPPINGS=($(parse_port_mappings "$PORT_INPUT"))
    
    if [ ${#PORT_MAPPINGS[@]} -eq 0 ]; then
        echo -e "${RED}无效的端口格式${NC}"
        continue
    fi
    
    # 验证所有端口
    all_valid=true
    for mapping in "${PORT_MAPPINGS[@]}"; do
        local_p=$(echo "$mapping" | cut -d: -f1)
        target_p=$(echo "$mapping" | cut -d: -f2)
        
        if ! validate_port "$local_p" || ! validate_port "$target_p"; then
            echo -e "${RED}无效的端口: $mapping (端口范围 1-65535)${NC}"
            all_valid=false
            break
        fi
    done
    
    if [ "$all_valid" = false ]; then
        continue
    fi
    
    # 显示解析结果
    echo -e "${GREEN}✅ 将配置 ${#PORT_MAPPINGS[@]} 条转发规则：${NC}"
    for mapping in "${PORT_MAPPINGS[@]}"; do
        local_p=$(echo "$mapping" | cut -d: -f1)
        target_p=$(echo "$mapping" | cut -d: -f2)
        if [ "$local_p" = "$target_p" ]; then
            echo -e "   本地 :$local_p -> 目标 :$target_p"
        else
            echo -e "   本地 :$local_p -> 目标 :$target_p"
        fi
    done
    
    # 检查端口占用
    occupied_ports=()
    for mapping in "${PORT_MAPPINGS[@]}"; do
        local_p=$(echo "$mapping" | cut -d: -f1)
        if command -v ss >/dev/null 2>&1; then
            if ss -tlnp 2>/dev/null | grep -q ":$local_p "; then
                occupied_ports+=("$local_p")
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -tlnp 2>/dev/null | grep -q ":$local_p "; then
                occupied_ports+=("$local_p")
            fi
        fi
    done
    
    if [ ${#occupied_ports[@]} -gt 0 ]; then
        echo -e "${YELLOW}⚠️  警告: 以下端口已被占用: ${occupied_ports[*]}${NC}"
        read -p "$(echo -e ${YELLOW}是否继续? [y/N]: ${NC})" CONTINUE_PORT
        if [[ ! $CONTINUE_PORT =~ ^[Yy]$ ]]; then
            continue
        fi
    fi
    
    break
done

# 选择转发方案
echo ""
echo -e "${CYAN}${BOLD}========== 转发方案对比 ==========${NC}"
echo ""

# 检测本机网络环境
detect_local_network

# 判断公网情况
HAS_PUBLIC_V4=false
HAS_PUBLIC_V6=false
[ "$LOCAL_IPV4_TYPE" = "public" ] && HAS_PUBLIC_V4=true
[ "$LOCAL_IPV6_TYPE" = "public" ] && HAS_PUBLIC_V6=true

# 显示本机网络状态
echo -e "${CYAN}本机网络环境:${NC}"
if [ "$LOCAL_HAS_IPV4" = true ]; then
    if [ "$LOCAL_IPV4_TYPE" = "public" ]; then
        echo -e "  IPv4: ${GREEN}✓ $LOCAL_IPV4 (公网)${NC}"
    else
        echo -e "  IPv4: ${YELLOW}✓ $LOCAL_IPV4 (内网)${NC}"
    fi
else
    echo -e "  IPv4: ${RED}✗ 无${NC}"
fi
if [ "$LOCAL_HAS_IPV6" = true ]; then
    if [ "$LOCAL_IPV6_TYPE" = "public" ]; then
        echo -e "  IPv6: ${GREEN}✓ $LOCAL_IPV6 (公网)${NC}"
    else
        echo -e "  IPv6: ${YELLOW}✓ $LOCAL_IPV6 (内网)${NC}"
    fi
else
    echo -e "  IPv6: ${DIM}✗ 无${NC}"
fi
echo ""

# 判断本机是否只有 IPv6 公网
LOCAL_ONLY_IPV6=false
if [ "$HAS_PUBLIC_V6" = true ] && [ "$HAS_PUBLIC_V4" = false ]; then
    LOCAL_ONLY_IPV6=true
    echo -e "${YELLOW}⚠️  本机仅有 IPv6 公网出口${NC}"
    echo ""
fi

# 根据目标地址类型和本机网络显示方案
echo -e "${YELLOW}方案选择：${NC}"
echo ""

# 判断各方案的可用性
# iptables: 本机需要对应的公网 IP 版本
if [ "$IS_IPV6" = true ]; then
    if [ "$HAS_PUBLIC_V6" = true ]; then
        echo -e "1) ${GREEN}iptables DNAT${NC}   - 延迟: 低  | ${GREEN}✓ 支持 (ip6tables)${NC}"
        IPTABLES_OK=true
    else
        echo -e "1) ${DIM}iptables DNAT${NC}   - ${RED}✗ 本机无公网 IPv6${NC}"
        IPTABLES_OK=false
    fi
else
    if [ "$HAS_PUBLIC_V4" = true ]; then
        echo -e "1) ${GREEN}iptables DNAT${NC}   - 延迟: 低  | ${GREEN}✓ 支持${NC}"
        IPTABLES_OK=true
    elif [ "$LOCAL_HAS_IPV4" = true ]; then
        echo -e "1) ${YELLOW}iptables DNAT${NC}   - 延迟: 低  | ${YELLOW}⚠ 内网可用${NC}"
        IPTABLES_OK=true
    else
        echo -e "1) ${DIM}iptables DNAT${NC}   - ${RED}✗ 本机无 IPv4${NC}"
        IPTABLES_OK=false
    fi
fi

# nftables: 支持双栈
echo -e "2) ${MAGENTA}nftables DNAT${NC}   - 延迟: 低  | ${GREEN}✓ 支持${NC}"
NFTABLES_OK=true

# HAProxy: 支持双栈
echo -e "3) ${BLUE}HAProxy${NC}         - 延迟: 较低 | ${GREEN}✓ 支持${NC}"
HAPROXY_OK=true

# socat: 支持双栈
echo -e "4) ${CYAN}socat${NC}           - 延迟: 较低 | ${GREEN}✓ 支持${NC}"
SOCAT_OK=true

# gost: 支持双栈
echo -e "5) ${YELLOW}gost${NC}            - 延迟: 中等 | ${GREEN}✓ 支持${NC}"
GOST_OK=true

# realm: 支持双栈
echo -e "6) ${MAGENTA}realm${NC}           - 延迟: 较低 | ${GREEN}✓ 支持${NC}"
REALM_OK=true

# rinetd: 不支持 IPv6
if [ "$IS_IPV6" = true ]; then
    echo -e "7) ${DIM}rinetd${NC}          - ${RED}✗ 不支持 IPv6 目标${NC}"
    RINETD_OK=false
else
    echo -e "7) ${BLUE}rinetd${NC}          - 延迟: 较低 | ${GREEN}✓ 支持${NC}"
    RINETD_OK=true
fi

# nginx stream: 支持双栈
echo -e "8) ${CYAN}nginx stream${NC}    - 延迟: 较低 | ${GREEN}✓ 支持${NC}"
NGINX_OK=true

echo ""
echo -e "${DIM}所有方案均支持流量统计 (菜单选项 6)${NC}"
echo -e "${CYAN}性能: ${GREEN}iptables/nftables${NC} > ${MAGENTA}realm${NC} > ${BLUE}HAProxy/nginx${NC} > ${CYAN}socat/rinetd${NC} > ${YELLOW}gost${NC}"
echo ""

# 构建可用方案列表
AVAILABLE_METHODS=""
[ "$IPTABLES_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}1"
[ "$NFTABLES_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}2"
[ "$HAPROXY_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}3"
[ "$SOCAT_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}4"
[ "$GOST_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}5"
[ "$REALM_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}6"
[ "$RINETD_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}7"
[ "$NGINX_OK" = true ] && AVAILABLE_METHODS="${AVAILABLE_METHODS}8"

# 默认选择
if [ "$NFTABLES_OK" = true ]; then
    DEFAULT_METHOD=2
elif [ "$IPTABLES_OK" = true ]; then
    DEFAULT_METHOD=1
else
    DEFAULT_METHOD=4  # socat 作为备选
fi

while true; do
    read -p "$(echo -e ${YELLOW}请选择方案 [$DEFAULT_METHOD]: ${NC})" FORWARD_METHOD
    FORWARD_METHOD=${FORWARD_METHOD:-$DEFAULT_METHOD}
    
    # 检查选择是否有效
    if [[ ! $FORWARD_METHOD =~ ^[1-8]$ ]]; then
        echo -e "${RED}请输入 1-8 之间的数字${NC}"
        continue
    fi
    
    # 检查选择的方案是否可用
    case $FORWARD_METHOD in
        1) [ "$IPTABLES_OK" = false ] && echo -e "${RED}iptables 不可用，请选择其他方案${NC}" && continue ;;
        7) [ "$RINETD_OK" = false ] && echo -e "${RED}rinetd 不支持 IPv6 目标，请选择其他方案${NC}" && continue ;;
    esac
    
    break
done

echo ""
echo -e "${CYAN}配置确认：${NC}"
echo -e "目标服务器: ${BOLD}$TARGET_IP${NC}"
echo -e "端口映射: ${BOLD}${#PORT_MAPPINGS[@]} 条规则${NC}"
for mapping in "${PORT_MAPPINGS[@]}"; do
    local_p=$(echo "$mapping" | cut -d: -f1)
    target_p=$(echo "$mapping" | cut -d: -f2)
    echo -e "  本地 :$local_p -> 目标 $TARGET_IP:$target_p"
done
case $FORWARD_METHOD in
    1) echo -e "转发方案: ${BOLD}iptables DNAT${NC}" ;;
    2) echo -e "转发方案: ${BOLD}nftables DNAT${NC}" ;;
    3) echo -e "转发方案: ${BOLD}HAProxy${NC}" ;;
    4) echo -e "转发方案: ${BOLD}socat${NC}" ;;
    5) echo -e "转发方案: ${BOLD}gost${NC}" ;;
    6) echo -e "转发方案: ${BOLD}realm${NC}" ;;
    7) echo -e "转发方案: ${BOLD}rinetd${NC}" ;;
    8) echo -e "转发方案: ${BOLD}nginx stream${NC}" ;;
esac
echo ""

read -p "$(echo -e ${YELLOW}确认配置并开始部署? [Y/n]: ${NC})" CONFIRM
CONFIRM=${CONFIRM:-Y}
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}部署已取消${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}[步骤1/4] 系统内核参数优化...${NC}"

# 备份当前配置 - 使用统一的备份目录
BACKUP_BASE_DIR="/root/.port_forward_backups"
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_BASE_DIR/$BACKUP_TIMESTAMP"
mkdir -p "$BACKUP_DIR"
cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
iptables-save > "$BACKUP_DIR/iptables_backup.txt" 2>/dev/null || true

# 获取转发方案名称
case $FORWARD_METHOD in
    1) METHOD_NAME="iptables DNAT" ;;
    2) METHOD_NAME="nftables DNAT" ;;
    3) METHOD_NAME="HAProxy" ;;
    4) METHOD_NAME="socat" ;;
    5) METHOD_NAME="gost" ;;
    6) METHOD_NAME="realm" ;;
    7) METHOD_NAME="rinetd" ;;
    8) METHOD_NAME="nginx stream" ;;
    *) METHOD_NAME="未知" ;;
esac

# 创建备份说明文件
PORTS_INFO=""
for mapping in "${PORT_MAPPINGS[@]}"; do
    local_p=$(echo "$mapping" | cut -d: -f1)
    target_p=$(echo "$mapping" | cut -d: -f2)
    PORTS_INFO="$PORTS_INFO\n  :$local_p -> :$target_p"
done

cat > "$BACKUP_DIR/backup_info.txt" << EOF
备份时间: $(date)
转发方案: $METHOD_NAME
目标地址: $TARGET_IP
端口映射: ${#PORT_MAPPINGS[@]} 条规则
$(echo -e "$PORTS_INFO")
EOF

# 应用网络性能优化内核参数
echo -e "${YELLOW}应用内核参数优化...${NC}"
cat >> /etc/sysctl.conf << EOF

# 网络性能TCP优化 - $(date)
# BBR拥塞控制 + 公平队列
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Fast Open - 减少握手延迟
net.ipv4.tcp_fastopen = 3

# 早期重传和瘦流优化
net.ipv4.tcp_early_retrans = 1
net.ipv4.tcp_thin_dupack = 1
net.ipv4.tcp_thin_linear_timeouts = 1

# 低延迟模式
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# 禁用延迟ACK，立即确认
net.ipv4.tcp_delack_min = 1

# 优化缓冲区大小 - 256MB
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = "8192 262144 268435456"
net.ipv4.tcp_wmem = "8192 262144 268435456"

# 网络队列优化
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535

# 连接跟踪优化
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_loose = 1

# DNAT性能优化
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# TCP保活优化
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3

# 快速回收和重用
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
EOF

# 立即应用优化
sysctl -p >/dev/null 2>&1
echo -e "${GREEN}内核优化完成${NC}"

echo -e "${BLUE}[步骤2/4] 清理同类型服务...${NC}"
# 只清理当前选择的方案类型中相同端口的规则，不影响其他端口
case $FORWARD_METHOD in
    1)
        # iptables - 只清理相同端口的规则
        IPTABLES_CMD=$(get_iptables_cmd)
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LP=$(echo "$mapping" | cut -d: -f1)
            $IPTABLES_CMD -t nat -S PREROUTING 2>/dev/null | grep "\-\-dport $LP " | sed 's/-A/-D/' | while read rule; do
                $IPTABLES_CMD -t nat $rule 2>/dev/null || true
            done
        done
        echo -e "${YELLOW}已清理 iptables 相关端口的旧规则${NC}"
        ;;
    2)
        # nftables - 清理相同端口的规则
        if command -v nft >/dev/null 2>&1; then
            for mapping in "${PORT_MAPPINGS[@]}"; do
                LP=$(echo "$mapping" | cut -d: -f1)
                # 删除包含该端口的规则
                nft -a list chain inet port_forward prerouting 2>/dev/null | grep "dport $LP " | while read line; do
                    HANDLE=$(echo "$line" | grep -oE 'handle [0-9]+' | awk '{print $2}')
                    if [ -n "$HANDLE" ]; then
                        nft delete rule inet port_forward prerouting handle $HANDLE 2>/dev/null || true
                    fi
                done
            done
        fi
        echo -e "${YELLOW}已清理 nftables 相关端口的旧规则${NC}"
        ;;
    3)
        # HAProxy - 不停止服务，只更新配置（追加模式）
        echo -e "${YELLOW}HAProxy 将追加新规则${NC}"
        ;;
    4)
        # socat - 只停止相同端口的服务
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LP=$(echo "$mapping" | cut -d: -f1)
            systemctl stop port-forward-${LP} 2>/dev/null || true
        done
        echo -e "${YELLOW}已停止相关端口的 socat 服务${NC}"
        ;;
    5)
        # gost - 追加模式，不停止现有服务
        echo -e "${YELLOW}gost 将追加新规则${NC}"
        ;;
    6)
        # realm - 追加模式，不停止现有服务
        echo -e "${YELLOW}realm 将追加新规则${NC}"
        ;;
    7)
        # rinetd - 追加模式（注意：rinetd 不支持 IPv6）
        echo -e "${YELLOW}rinetd 将追加新规则${NC}"
        ;;
    8)
        # nginx - 只移除当前端口的 stream 配置
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LP=$(echo "$mapping" | cut -d: -f1)
            rm -f /etc/nginx/stream.d/port-forward-${LP}.conf 2>/dev/null || true
        done
        echo -e "${YELLOW}已清理 nginx stream 相关端口配置${NC}"
        ;;
esac

echo -e "${BLUE}[步骤3/4] 部署转发服务...${NC}"

case $FORWARD_METHOD in
    1)
        # iptables/ip6tables DNAT - 支持 IPv4 和 IPv6
        echo -e "${YELLOW}配置 iptables DNAT 转发...${NC}"
        echo ""
        
        # 识别系统类型
        if [ -f /etc/debian_version ]; then
            OS_TYPE="Ubuntu/Debian"
        elif [ -f /etc/redhat-release ]; then
            OS_TYPE="CentOS/RHEL"
        else
            OS_TYPE="Unknown"
        fi
        
        echo -e "${CYAN}检测到系统: ${BOLD}$OS_TYPE${NC}"
        
        # 根据目标地址类型选择命令
        if [ "$IS_IPV6" = true ]; then
            echo -e "${CYAN}目标类型: ${BOLD}IPv6${NC}"
            IPTABLES_CMD="ip6tables"
            # 检查 ip6tables 是否可用
            if ! command -v ip6tables >/dev/null 2>&1; then
                echo -e "${RED}ip6tables 未安装，请先安装 iptables${NC}"
                exit 1
            fi
        else
            echo -e "${CYAN}目标类型: ${BOLD}IPv4${NC}"
            IPTABLES_CMD=$(get_iptables_cmd)
        fi
        echo ""
        
        # Ubuntu: 先安装 iptables-persistent
        if [ -f /etc/debian_version ]; then
            if ! dpkg -l | grep -q iptables-persistent 2>/dev/null; then
                echo -e "${YELLOW}安装 iptables-persistent...${NC}"
                DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1
                echo -e "${GREEN}✓ 安装完成${NC}"
                echo ""
            fi
        fi
        
        # 1. 启用IP转发
        echo -e "${CYAN}[1/6] 启用IP转发${NC}"
        if [ "$IS_IPV6" = true ]; then
            echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
            if ! grep -q "^net.ipv6.conf.all.forwarding = 1" /etc/sysctl.conf; then
                echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
            fi
        else
            echo 1 > /proc/sys/net/ipv4/ip_forward
            if ! grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
                echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
            fi
        fi
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 2. 添加DNAT规则（外部访问）
        echo -e "${CYAN}[2/6] 添加DNAT规则（外部访问）${NC}"
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            if [ "$IS_IPV6" = true ]; then
                $IPTABLES_CMD -t nat -A PREROUTING -p tcp --dport $LOCAL_PORT -j DNAT --to-destination [$TARGET_IP]:$TARGET_PORT
            else
                $IPTABLES_CMD -t nat -A PREROUTING -p tcp --dport $LOCAL_PORT -j DNAT --to-destination $TARGET_IP:$TARGET_PORT
            fi
            echo -e "  ✓ :$LOCAL_PORT -> $TARGET_IP:$TARGET_PORT"
        done
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 3. 添加MASQUERADE规则
        echo -e "${CYAN}[3/6] 添加MASQUERADE规则${NC}"
        for mapping in "${PORT_MAPPINGS[@]}"; do
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            $IPTABLES_CMD -t nat -A POSTROUTING -p tcp -d $TARGET_IP --dport $TARGET_PORT -j MASQUERADE
        done
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 4. 添加OUTPUT规则（本地访问支持）
        echo -e "${CYAN}[4/6] 添加OUTPUT规则（本地访问支持）${NC}"
        if [ "$IS_IPV6" = true ]; then
            LOCAL_IP=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -1)
        else
            LOCAL_IP=$(hostname -I | awk '{print $1}')
        fi
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            if [ "$IS_IPV6" = true ]; then
                $IPTABLES_CMD -t nat -A OUTPUT -p tcp --dport $LOCAL_PORT -d $LOCAL_IP -j DNAT --to-destination [$TARGET_IP]:$TARGET_PORT 2>/dev/null || true
                $IPTABLES_CMD -t nat -A OUTPUT -p tcp --dport $LOCAL_PORT -d ::1 -j DNAT --to-destination [$TARGET_IP]:$TARGET_PORT 2>/dev/null || true
            else
                $IPTABLES_CMD -t nat -A OUTPUT -p tcp --dport $LOCAL_PORT -d $LOCAL_IP -j DNAT --to-destination $TARGET_IP:$TARGET_PORT 2>/dev/null || true
                $IPTABLES_CMD -t nat -A OUTPUT -p tcp --dport $LOCAL_PORT -d 127.0.0.1 -j DNAT --to-destination $TARGET_IP:$TARGET_PORT 2>/dev/null || true
            fi
            $IPTABLES_CMD -t nat -A POSTROUTING -p tcp -d $TARGET_IP --dport $TARGET_PORT -j MASQUERADE 2>/dev/null || true
            $IPTABLES_CMD -t nat -A OUTPUT -p tcp --dport $LOCAL_PORT -d 127.0.0.1 -j DNAT --to-destination $TARGET_IP:$TARGET_PORT 2>/dev/null || true
            $IPTABLES_CMD -t nat -A POSTROUTING -p tcp -d $TARGET_IP --dport $TARGET_PORT -s $LOCAL_IP -j MASQUERADE 2>/dev/null || true
        done
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 5. 添加FORWARD规则（连接跟踪优化）
        echo -e "${CYAN}[5/6] 添加FORWARD规则${NC}"
        for mapping in "${PORT_MAPPINGS[@]}"; do
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            $IPTABLES_CMD -A FORWARD -p tcp -d $TARGET_IP --dport $TARGET_PORT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
            $IPTABLES_CMD -A FORWARD -p tcp -s $TARGET_IP --sport $TARGET_PORT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        done
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 6. 关闭反向路径过滤
        echo -e "${CYAN}[6/6] 优化系统参数${NC}"
        echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
        echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null || true
        echo -e "${GREEN}✓ 完成${NC}"
        echo ""
        
        # 保存规则（根据系统）
        echo -e "${CYAN}保存规则（重启后生效）${NC}"
        if [ -f /etc/debian_version ]; then
            # Ubuntu: netfilter-persistent save
            netfilter-persistent save >/dev/null 2>&1
            echo -e "${GREEN}✓ Ubuntu 规则已保存${NC}"
            
        elif [ -f /etc/redhat-release ]; then
            # CentOS: service iptables save
            service iptables save >/dev/null 2>&1
            echo -e "${GREEN}✓ CentOS 规则已保存${NC}"
        fi
        
        # 备份规则到固定位置（供开机恢复使用）
        IPTABLES_RUNNING_BACKUP="/root/.port_forward_iptables_running.txt"
        if command -v iptables-save >/dev/null 2>&1; then
            if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                iptables-legacy-save > "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
            else
                iptables-save > "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
            fi
            iptables-save > "$BACKUP_DIR/iptables_current.txt" 2>/dev/null || true
        fi
        
        # 设置开机自启
        setup_autostart "iptables"
        
        echo ""
        echo -e "${GREEN}${BOLD}===========================================${NC}"
        echo -e "${GREEN}${BOLD}  iptables DNAT 配置完成！${NC}"
        echo -e "${GREEN}${BOLD}===========================================${NC}"
        echo -e "${CYAN}已配置 ${#PORT_MAPPINGS[@]} 条转发规则${NC}"
        for mapping in "${PORT_MAPPINGS[@]}"; do
            local_p=$(echo "$mapping" | cut -d: -f1)
            target_p=$(echo "$mapping" | cut -d: -f2)
            echo -e "  :$local_p -> $TARGET_IP:$target_p"
        done
        echo -e "${GREEN}✓ 已设置开机自启${NC}"
        echo -e "${GREEN}${BOLD}===========================================${NC}"
        ;;
        
    2)
        # nftables DNAT - 现代防火墙方案
        echo -e "${YELLOW}配置nftables DNAT转发...${NC}"
        echo ""
        
        # 检查 nftables 是否可用
        if ! command -v nft >/dev/null 2>&1; then
            echo -e "${YELLOW}安装 nftables...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update -qq && apt-get install -y nftables >/dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                yum install -y nftables >/dev/null 2>&1
            fi
        fi
        
        if ! command -v nft >/dev/null 2>&1; then
            echo -e "${RED}nftables 安装失败，请手动安装${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}✓ nftables 已安装${NC}"
        
        # 1. 启用IP转发
        echo -e "${CYAN}[1/4] 启用IP转发${NC}"
        echo 1 > /proc/sys/net/ipv4/ip_forward
        if ! grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
            echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        fi
        # 如果是 IPv6，也启用 IPv6 转发
        if [ "$IS_IPV6" = true ]; then
            echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
            if ! grep -q "^net.ipv6.conf.all.forwarding = 1" /etc/sysctl.conf; then
                echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
            fi
        fi
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 2. 创建 nftables 表和链（如果不存在）
        echo -e "${CYAN}[2/4] 创建 nftables 表和链${NC}"
        
        # 创建表
        nft add table inet port_forward 2>/dev/null || true
        
        # 创建 prerouting 链 (DNAT)
        nft add chain inet port_forward prerouting '{ type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true
        
        # 创建 postrouting 链 (SNAT/MASQUERADE)
        nft add chain inet port_forward postrouting '{ type nat hook postrouting priority srcnat; policy accept; }' 2>/dev/null || true
        
        # 创建 forward 链
        nft add chain inet port_forward forward '{ type filter hook forward priority filter; policy accept; }' 2>/dev/null || true
        
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 3. 添加转发规则（带流量统计）
        echo -e "${CYAN}[3/4] 添加转发规则${NC}"
        
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            
            if [ "$IS_IPV6" = true ]; then
                # IPv6 DNAT 规则
                nft add rule inet port_forward prerouting ip6 nexthdr tcp tcp dport $LOCAL_PORT counter dnat ip6 to [$TARGET_IP]:$TARGET_PORT
                
                # IPv6 MASQUERADE 规则
                nft add rule inet port_forward postrouting ip6 daddr $TARGET_IP tcp dport $TARGET_PORT counter masquerade
                
                # IPv6 FORWARD 规则
                nft add rule inet port_forward forward ip6 daddr $TARGET_IP tcp dport $TARGET_PORT ct state new,established,related counter accept 2>/dev/null || true
                nft add rule inet port_forward forward ip6 saddr $TARGET_IP tcp sport $TARGET_PORT ct state established,related counter accept 2>/dev/null || true
            else
                # IPv4 DNAT 规则 (带 counter 用于流量统计)
                nft add rule inet port_forward prerouting ip protocol tcp tcp dport $LOCAL_PORT counter dnat ip to $TARGET_IP:$TARGET_PORT
                
                # IPv4 MASQUERADE 规则
                nft add rule inet port_forward postrouting ip daddr $TARGET_IP tcp dport $TARGET_PORT counter masquerade
                
                # IPv4 FORWARD 规则
                nft add rule inet port_forward forward ip daddr $TARGET_IP tcp dport $TARGET_PORT ct state new,established,related counter accept 2>/dev/null || true
                nft add rule inet port_forward forward ip saddr $TARGET_IP tcp sport $TARGET_PORT ct state established,related counter accept 2>/dev/null || true
            fi
            echo -e "  ✓ :$LOCAL_PORT -> $TARGET_IP:$TARGET_PORT"
        done
        
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 4. 保存规则
        echo -e "${CYAN}[4/4] 保存规则${NC}"
        
        # 保存到配置文件
        mkdir -p /etc/nftables.d
        nft list table inet port_forward > /etc/nftables.d/port_forward.nft 2>/dev/null || true
        
        # 确保 nftables 服务启用
        systemctl enable nftables 2>/dev/null || true
        
        # 备份规则
        nft list ruleset > "$BACKUP_DIR/nftables_current.txt" 2>/dev/null || true
        
        echo -e "${GREEN}✓ 完成${NC}"
        
        # 设置开机自启
        setup_autostart "nftables"
        
        echo ""
        echo -e "${GREEN}${BOLD}===========================================${NC}"
        echo -e "${GREEN}${BOLD}  nftables DNAT 配置完成！${NC}"
        echo -e "${GREEN}${BOLD}===========================================${NC}"
        echo -e "${CYAN}已配置 ${#PORT_MAPPINGS[@]} 条转发规则${NC}"
        for mapping in "${PORT_MAPPINGS[@]}"; do
            local_p=$(echo "$mapping" | cut -d: -f1)
            target_p=$(echo "$mapping" | cut -d: -f2)
            echo -e "  :$local_p -> $TARGET_IP:$target_p"
        done
        echo -e "${YELLOW}查看规则: nft list table inet port_forward${NC}"
        echo -e "${YELLOW}流量统计: 选择菜单选项 6${NC}"
        echo -e "${GREEN}✓ 已设置开机自启${NC}"
        echo -e "${GREEN}${BOLD}===========================================${NC}"
        ;;
        
    3)
        # HAProxy优化版 - 支持追加模式
        echo -e "${YELLOW}配置HAProxy优化转发...${NC}"
        
        # 检查并安装HAProxy
        if ! command -v haproxy >/dev/null 2>&1; then
            if [ -f /etc/debian_version ]; then
                apt-get update -qq && apt-get install -y --no-install-recommends haproxy
            elif [ -f /etc/redhat-release ]; then
                yum install -y haproxy
            fi
        fi
        
        # 检查是否已有配置文件
        HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
        if [ -f "$HAPROXY_CONFIG" ] && grep -q "port_frontend_" "$HAPROXY_CONFIG"; then
            echo -e "${GREEN}检测到现有 HAProxy 配置，将追加新规则${NC}"
            HAPROXY_APPEND_MODE=true
        else
            HAPROXY_APPEND_MODE=false
            # 询问是否启用Web管理界面
            echo ""
            read -p "$(echo -e ${YELLOW}是否启用Web统计页面? [y/N]: ${NC})" ENABLE_WEB
            ENABLE_WEB=${ENABLE_WEB:-N}
            
            # 只有启用Web界面时才生成随机密码
            if [[ $ENABLE_WEB =~ ^[Yy]$ ]]; then
                HAPROXY_PASSWORD=$(generate_password 16)
            fi
            
            # 创建HAProxy基础配置
            cat > "$HAPROXY_CONFIG" << EOF
global
    daemon
    maxconn 65535
    tune.rcvbuf.client 4194304
    tune.rcvbuf.server 4194304
    tune.sndbuf.client 4194304
    tune.sndbuf.server 4194304
    tune.bufsize 65536
    tune.maxaccept 1024

defaults
    mode tcp
    timeout connect 500ms
    timeout client 3600s
    timeout server 3600s
    option tcplog
    option tcp-smart-accept
    option tcp-smart-connect
    option dontlognull
    retries 1
    option clitcpka
    option srvtcpka
EOF
        fi

        # 为每个端口添加 frontend 和 backend（先删除同端口的旧配置）
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            
            # 删除该端口的旧配置块
            if [ "$HAPROXY_APPEND_MODE" = true ]; then
                sed -i "/^# 端口转发: $LOCAL_PORT ->/,/^# 端口转发:/{ /^# 端口转发: $LOCAL_PORT ->/d; /^frontend port_frontend_$LOCAL_PORT/,/^$/d; /^backend port_backend_$LOCAL_PORT/,/^$/d; }" "$HAPROXY_CONFIG"
            fi
            
            # IPv6 地址需要用方括号包裹
            if [ "$IS_IPV6" = true ]; then
                HAPROXY_TARGET="[$TARGET_IP]:$TARGET_PORT"
            else
                HAPROXY_TARGET="$TARGET_IP:$TARGET_PORT"
            fi
            
            cat >> "$HAPROXY_CONFIG" << EOF

# 端口转发: $LOCAL_PORT -> $TARGET_IP:$TARGET_PORT
frontend port_frontend_$LOCAL_PORT
    bind *:$LOCAL_PORT
    bind [::]:$LOCAL_PORT
    mode tcp
    default_backend port_backend_$LOCAL_PORT

backend port_backend_$LOCAL_PORT
    mode tcp
    balance first
    option tcp-check
    tcp-check connect port $TARGET_PORT
    server target_server_$LOCAL_PORT $HAPROXY_TARGET check inter 30s rise 1 fall 1 weight 100 maxconn 32768
EOF
            echo -e "  ✓ :$LOCAL_PORT -> $TARGET_IP:$TARGET_PORT (IPv4+IPv6)"
        done

        # 根据用户选择添加统计页面
        if [[ $ENABLE_WEB =~ ^[Yy]$ ]]; then
            cat >> /etc/haproxy/haproxy.cfg << EOF

# 统计页面
listen stats
    bind *:8888
    mode http
    stats enable
    stats uri /haproxy-stats
    stats refresh 30s
    stats realm HAProxy\ Statistics
    stats auth admin:$HAPROXY_PASSWORD
    stats admin if TRUE
EOF
        fi
        
        systemctl enable haproxy
        if systemctl restart haproxy 2>&1; then
            echo -e "${GREEN}HAProxy启动成功${NC}"
        else
            echo -e "${RED}HAProxy启动失败${NC}"
            echo -e "${YELLOW}查看错误日志: journalctl -u haproxy -n 20${NC}"
            echo -e "${YELLOW}测试配置: haproxy -c -f /etc/haproxy/haproxy.cfg${NC}"
        fi
        
        # 获取本机IP (智能选择 IPv4 或 IPv6)
        LOCAL_IP=$(get_local_ip)
        
        echo -e "${GREEN}HAProxy配置完成${NC}"
        
        # 如果启用了Web界面，显示凭据信息
        if [[ $ENABLE_WEB =~ ^[Yy]$ ]]; then
            # 保存密码到文件
            echo "HAProxy Web管理界面" > /root/haproxy_credentials.txt
            echo "访问地址: http://$LOCAL_IP:8888/haproxy-stats" >> /root/haproxy_credentials.txt
            echo "用户名: admin" >> /root/haproxy_credentials.txt
            echo "密码: $HAPROXY_PASSWORD" >> /root/haproxy_credentials.txt
            echo "配置时间: $(date)" >> /root/haproxy_credentials.txt
            chmod 600 /root/haproxy_credentials.txt
            
            echo ""
            echo -e "${CYAN}${BOLD}========== Web管理界面 ==========${NC}"
            echo -e "${CYAN}访问地址: ${BOLD}http://$LOCAL_IP:8888/haproxy-stats${NC}"
            echo -e "${CYAN}用户名: ${BOLD}admin${NC}"
            echo -e "${CYAN}密码: ${BOLD}$HAPROXY_PASSWORD${NC}"
            echo -e "${YELLOW}密码已保存到: /root/haproxy_credentials.txt${NC}"
            echo -e "${CYAN}====================================${NC}"
            echo ""
        else
            echo -e "${YELLOW}Web统计页面未启用${NC}"
        fi
        ;;
        
    4)
        # socat轻量版 - 支持多端口
        echo -e "${YELLOW}配置socat轻量转发...${NC}"
        
        # 检查并安装socat
        if ! command -v socat >/dev/null 2>&1; then
            if [ -f /etc/debian_version ]; then
                apt-get update -qq && apt-get install -y --no-install-recommends socat
            elif [ -f /etc/redhat-release ]; then
                yum install -y socat
            fi
        fi
        
        # 为每个端口创建单独的 systemd 服务
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            
            # IPv6 地址需要用方括号包裹
            if [ "$IS_IPV6" = true ]; then
                SOCAT_TARGET="TCP6:[$TARGET_IP]:$TARGET_PORT"
            else
                SOCAT_TARGET="TCP:$TARGET_IP:$TARGET_PORT"
            fi
            
            SERVICE_NAME="port-forward-${LOCAL_PORT}"
            
            cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Port Forward Service (Port $LOCAL_PORT)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/socat TCP6-LISTEN:$LOCAL_PORT,fork,reuseaddr,nodelay,keepalive,ipv6only=0 $SOCAT_TARGET
Restart=always
RestartSec=3
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF
            
            systemctl daemon-reload
            systemctl enable ${SERVICE_NAME}
            if systemctl start ${SERVICE_NAME} 2>&1; then
                echo -e "  ${GREEN}✓${NC} :$LOCAL_PORT -> $TARGET_IP:$TARGET_PORT"
            else
                echo -e "  ${RED}✗${NC} :$LOCAL_PORT 启动失败"
            fi
        done
        
        echo -e "${GREEN}socat 配置完成，共 ${#PORT_MAPPINGS[@]} 条规则${NC}"
        ;;
        
    5)
        # gost代理转发
        echo -e "${YELLOW}配置gost代理转发...${NC}"
        
        # 询问是否启用Web API
        echo ""
        read -p "$(echo -e ${YELLOW}是否启用Web API? [y/N]: ${NC})" ENABLE_API
        ENABLE_API=${ENABLE_API:-N}
        
        # 只有启用Web API时才生成随机密码
        if [[ $ENABLE_API =~ ^[Yy]$ ]]; then
            GOST_API_USER="admin"
            GOST_API_PASSWORD=$(generate_password 16)
        fi
        
        # 检查并安装gost (确保安装在正确位置)
        if [ ! -f /usr/local/bin/gost ] || [ ! -x /usr/local/bin/gost ]; then
            # 安装前检测网络环境，纯 IPv6 可能需要 DNS64
            setup_dns64
            
            echo "安装gost最新版本..."
            
            # 创建临时目录并切换
            GOST_TEMP_DIR=$(mktemp -d)
            cd "$GOST_TEMP_DIR"
            
            # 使用官方安装脚本 (通过智能下载函数)
            INSTALL_SUCCESS=false
            
            # 方法1: 使用智能远程执行
            echo "使用官方安装脚本..."
            if smart_bash_remote "https://github.com/go-gost/gost/raw/master/install.sh" --install 2>/dev/null; then
                INSTALL_SUCCESS=true
                echo -e "${GREEN}✅ gost安装成功${NC}"
            fi
            
            # 方法2: 如果官方脚本失败，尝试包管理器
            if [ "$INSTALL_SUCCESS" = false ]; then
                echo "官方脚本安装失败，尝试包管理器..."
                if [ -f /etc/debian_version ]; then
                    if apt-get update -qq && apt-get install -y gost 2>/dev/null; then
                        INSTALL_SUCCESS=true
                        echo -e "${GREEN}✅ 通过apt安装成功${NC}"
                    fi
                elif [ -f /etc/redhat-release ]; then
                    if yum install -y gost 2>/dev/null; then
                        INSTALL_SUCCESS=true
                        echo -e "${GREEN}✅ 通过yum安装成功${NC}"
                    fi
                fi
            fi
            
            # 切换回原目录并清理临时目录
            cd /root
            rm -rf "$GOST_TEMP_DIR" 2>/dev/null
            
            # 如果所有方法都失败
            if [ "$INSTALL_SUCCESS" = false ]; then
                echo -e "${RED}❌ gost自动安装失败${NC}"
                echo "手动安装方法："
                echo "1. 运行: bash <(curl -fsSL https://ghproxy.com/https://github.com/go-gost/gost/raw/master/install.sh) --install"
                echo "2. 或访问: https://github.com/go-gost/gost/releases"
                echo "3. 下载适合您系统的版本并解压到 /usr/local/bin/gost"
                echo ""
                echo "国内镜像下载:"
                echo "  https://ghproxy.com/https://github.com/go-gost/gost/releases/download/v3.x.x/gost_3.x.x_linux_amd64.tar.gz"
                exit 1
            fi
            
            # 验证安装
            if [ -f /usr/local/bin/gost ] && [ -x /usr/local/bin/gost ]; then
                GOST_INSTALLED_VERSION=$(/usr/local/bin/gost -V 2>/dev/null | head -1 || echo "unknown")
                echo -e "${GREEN}gost安装完成: $GOST_INSTALLED_VERSION${NC}"
                echo "安装路径: /usr/local/bin/gost"
            else
                echo -e "${RED}gost安装失败 - 文件不存在或不可执行${NC}"
                exit 1
            fi
        else
            # 验证现有安装
            if [ -f /usr/local/bin/gost ] && [ -x /usr/local/bin/gost ]; then
                GOST_EXISTING_VERSION=$(/usr/local/bin/gost -V 2>/dev/null | head -1 || echo "unknown")
                echo -e "${GREEN}gost已安装: $GOST_EXISTING_VERSION${NC}"
            else
                echo -e "${RED}gost文件存在但不可执行，尝试修复...${NC}"
                rm -f /usr/local/bin/gost
                echo -e "${YELLOW}请重新运行脚本并选择gost转发方案${NC}"
                exit 1
            fi
        fi
        
        # 创建 gost 配置文件 - 支持追加模式
        mkdir -p /etc/gost
        GOST_CONFIG="/etc/gost/config.yaml"
        
        # 检查是否已有配置
        if [ -f "$GOST_CONFIG" ] && grep -q "^services:" "$GOST_CONFIG"; then
            echo -e "${GREEN}检测到现有 gost 配置，将追加新规则${NC}"
            # 获取现有最大 service index
            service_index=$(grep -oE "service-[0-9]+" "$GOST_CONFIG" | grep -oE "[0-9]+" | sort -n | tail -1)
            service_index=$((service_index + 1))
        else
            # 写入配置头部
            cat > "$GOST_CONFIG" << EOF
services:
EOF
            service_index=0
        fi
        
        # 为每个端口添加 service
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            
            # 先删除该端口的旧配置
            if grep -q "addr: :$LOCAL_PORT$" "$GOST_CONFIG"; then
                # 使用 sed 删除该 service 块
                sed -i "/- name: .*\n.*addr: :$LOCAL_PORT$/,/^- name:/{ /^- name: .*addr: :$LOCAL_PORT/,/^- name:/d }" "$GOST_CONFIG" 2>/dev/null || true
            fi
            
            # IPv6 地址需要用方括号包裹
            if [ "$IS_IPV6" = true ]; then
                GOST_TARGET="[$TARGET_IP]:$TARGET_PORT"
            else
                GOST_TARGET="$TARGET_IP:$TARGET_PORT"
            fi
            
            # 在 api: 之前插入，或者追加到文件末尾
            if grep -q "^api:" "$GOST_CONFIG"; then
                sed -i "/^api:/i\\
- name: service-${service_index}\\
  addr: :$LOCAL_PORT\\
  handler:\\
    type: tcp\\
  listener:\\
    type: tcp\\
  forwarder:\\
    nodes:\\
    - name: target-${service_index}\\
      addr: $GOST_TARGET\\
" "$GOST_CONFIG"
            else
                cat >> "$GOST_CONFIG" << EOF
- name: service-${service_index}
  addr: :$LOCAL_PORT
  handler:
    type: tcp
  listener:
    type: tcp
  forwarder:
    nodes:
    - name: target-${service_index}
      addr: $GOST_TARGET
EOF
            fi
            echo -e "  ✓ :$LOCAL_PORT -> $GOST_TARGET"
            service_index=$((service_index + 1))
        done
        
        # 如果启用 API，添加 API 配置
        if [[ $ENABLE_API =~ ^[Yy]$ ]]; then
            cat >> /etc/gost/config.yaml << EOF

api:
  addr: :9999
  pathPrefix: /api
  accesslog: true
  auth:
    username: $GOST_API_USER
    password: $GOST_API_PASSWORD
EOF
        fi
        
        # 创建 systemd 服务
        cat > /etc/systemd/system/gost-forward.service << EOF
[Unit]
Description=Gost Port Forward
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/gost -C /etc/gost/config.yaml
Restart=always
RestartSec=5
StartLimitBurst=3
StandardOutput=journal
StandardError=journal
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
MemoryMax=512M
TasksMax=1024

[Install]
WantedBy=multi-user.target
EOF
        
        # 先测试gost命令是否能正常启动
        echo -e "${YELLOW}测试gost命令...${NC}"
        timeout 3 /usr/local/bin/gost -C /etc/gost/config.yaml &
        GOST_PID=$!
        sleep 2
        
        if kill -0 $GOST_PID 2>/dev/null; then
            echo -e "${GREEN}✅ gost命令测试成功${NC}"
            kill $GOST_PID 2>/dev/null
            wait $GOST_PID 2>/dev/null
        else
            echo -e "${RED}❌ gost命令测试失败${NC}"
            echo -e "${YELLOW}尝试检查系统资源...${NC}"
            free -h
            echo -e "${YELLOW}检查进程限制...${NC}"
            ulimit -a | grep -E "(processes|memory|files)"
        fi
        
        systemctl daemon-reload
        systemctl enable gost-forward
        if systemctl start gost-forward 2>&1; then
            echo -e "${GREEN}gost 配置完成，共 ${#PORT_MAPPINGS[@]} 条规则${NC}"
        else
            echo -e "${RED}gost启动失败${NC}"
            echo -e "${YELLOW}查看错误日志: journalctl -u gost-forward -n 20${NC}"
            echo -e "${YELLOW}手动测试: /usr/local/bin/gost -V${NC}"
        fi
        
        # 获取本机IP (智能选择 IPv4 或 IPv6)
        LOCAL_IP=$(get_local_ip)
        
        echo -e "${GREEN}gost代理配置完成${NC}"
        
        # 如果启用了API，显示凭据信息
        if [[ $ENABLE_API =~ ^[Yy]$ ]]; then
            # 保存密码到文件
            echo "Gost Web API" > /root/gost_credentials.txt
            echo "API地址: http://$LOCAL_IP:9999/api/config" >> /root/gost_credentials.txt
            echo "用户名: $GOST_API_USER" >> /root/gost_credentials.txt
            echo "密码: $GOST_API_PASSWORD" >> /root/gost_credentials.txt
            echo "配置时间: $(date)" >> /root/gost_credentials.txt
            echo "" >> /root/gost_credentials.txt
            echo "API使用示例:" >> /root/gost_credentials.txt
            echo "curl -u $GOST_API_USER:$GOST_API_PASSWORD http://$LOCAL_IP:9999/api/config" >> /root/gost_credentials.txt
            chmod 600 /root/gost_credentials.txt
            
            echo ""
            echo "========== Web API =========="
            echo "API地址: http://$LOCAL_IP:9999/api/config"
            echo "用户名: $GOST_API_USER"
            echo "密码: $GOST_API_PASSWORD"
            echo "密码已保存到: /root/gost_credentials.txt"
            echo -e "${CYAN}====================================${NC}"
            echo ""
        else
            echo -e "${YELLOW}Web API未启用${NC}"
        fi
        ;;
        
    6)
        # realm转发
        echo -e "${YELLOW}配置realm转发...${NC}"
        
        # 检查并安装realm
        if ! command -v realm >/dev/null 2>&1; then
            # 安装前检测网络环境，纯 IPv6 可能需要 DNS64
            setup_dns64
            
            echo -e "${YELLOW}安装realm...${NC}"
            
            # 确定系统架构
            ARCH=$(uname -m)
            case $ARCH in
                x86_64) REALM_ARCH="x86_64" ;;
                aarch64) REALM_ARCH="aarch64" ;;
                *) REALM_ARCH="x86_64" ;;
            esac
            
            # 尝试获取最新版本号 (使用智能 API 获取)
            echo -e "${YELLOW}正在获取realm最新版本...${NC}"
            REALM_VERSION=""
            
            API_RESPONSE=$(smart_api_get "https://api.github.com/repos/zhboner/realm/releases/latest" 15)
            if [ -n "$API_RESPONSE" ]; then
                REALM_VERSION=$(echo "$API_RESPONSE" | grep '"tag_name"' | cut -d '"' -f 4 2>/dev/null)
            fi
            
            # 如果无法获取版本号，退出
            if [ -z "$REALM_VERSION" ]; then
                echo -e "${RED}无法获取realm最新版本${NC}"
                echo "请检查网络连接或手动安装"
                exit 1
            fi
            echo "找到最新版本: $REALM_VERSION"
            
            # 尝试下载realm (使用智能下载函数)
            DOWNLOAD_SUCCESS=false
            DOWNLOAD_URL="https://github.com/zhboner/realm/releases/download/${REALM_VERSION}/realm-${REALM_ARCH}-unknown-linux-gnu.tar.gz"
            
            echo "正在下载realm..."
            
            if smart_download "$DOWNLOAD_URL" "/tmp/realm.tar.gz" 60; then
                DOWNLOAD_SUCCESS=true
                echo -e "${GREEN}下载成功${NC}"
            fi
            
            # 验证下载的文件
            if [ "$DOWNLOAD_SUCCESS" = true ] && [ -f /tmp/realm.tar.gz ]; then
                FILE_SIZE=$(stat -c%s /tmp/realm.tar.gz 2>/dev/null || echo 0)
                if [ "$FILE_SIZE" -lt 100000 ]; then
                    echo -e "${RED}下载的文件太小，可能下载失败${NC}"
                    DOWNLOAD_SUCCESS=false
                    rm -f /tmp/realm.tar.gz
                fi
            fi
            
            # 如果下载成功，解压安装
            if [ "$DOWNLOAD_SUCCESS" = true ] && [ -f /tmp/realm.tar.gz ]; then
                echo -e "${YELLOW}正在安装realm...${NC}"
                if tar -xzf /tmp/realm.tar.gz -C /tmp 2>/dev/null && [ -f /tmp/realm ]; then
                    chmod +x /tmp/realm
                    mv /tmp/realm /usr/local/bin/realm
                    echo -e "${GREEN}realm安装成功${NC}"
                else
                    echo -e "${RED}realm解压失败${NC}"
                    DOWNLOAD_SUCCESS=false
                fi
            fi
            
            # 如果下载失败，提供手动安装指导
            if [ "$DOWNLOAD_SUCCESS" = false ]; then
                echo -e "${RED}realm下载失败，请手动安装${NC}"
                echo -e "${YELLOW}手动安装方法：${NC}"
                echo -e "1. 访问 https://github.com/zhboner/realm/releases"
                echo -e "2. 或使用国内镜像: https://ghproxy.com/https://github.com/zhboner/realm/releases/download/${REALM_VERSION}/realm-${REALM_ARCH}-unknown-linux-gnu.tar.gz"
                echo -e "3. 下载后解压并复制到 /usr/local/bin/realm"
                exit 1
            fi
            
            # 清理临时文件
            rm -f /tmp/realm.tar.gz 2>/dev/null || true
            
            # 验证安装
            if command -v realm >/dev/null 2>&1; then
                REALM_INSTALLED_VERSION=$(realm --version 2>/dev/null | head -1 || echo "unknown")
                echo -e "${GREEN}realm安装完成: $REALM_INSTALLED_VERSION${NC}"
            else
                echo -e "${RED}realm安装失败${NC}"
                exit 1
            fi
        else
            echo -e "${GREEN}realm已安装${NC}"
        fi
        
        # 创建realm配置文件 - 支持追加模式
        mkdir -p /etc/realm
        REALM_CONFIG="/etc/realm/config.toml"
        
        # 检查是否已有配置
        if [ -f "$REALM_CONFIG" ] && grep -q "^\[\[endpoints\]\]" "$REALM_CONFIG"; then
            echo -e "${GREEN}检测到现有 realm 配置，将追加新规则${NC}"
        else
            # 写入配置头部
            cat > "$REALM_CONFIG" << EOF
[network]
use_udp = false
zero_copy = true

EOF
        fi
        
        # 为每个端口添加 endpoint
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            
            # 先删除该端口的旧配置 (兼容旧的 0.0.0.0 和新的 [::] 格式)
            if grep -qE "listen = \"(0\.0\.0\.0|\[::\]):$LOCAL_PORT\"" "$REALM_CONFIG"; then
                # 删除该 endpoint 块
                sed -i "/^\[\[endpoints\]\]/{N;/listen = \".*:$LOCAL_PORT\"/,/^$/d}" "$REALM_CONFIG" 2>/dev/null || true
            fi
            
            if [ "$IS_IPV6" = true ]; then
                REALM_TARGET="[$TARGET_IP]:$TARGET_PORT"
            else
                REALM_TARGET="$TARGET_IP:$TARGET_PORT"
            fi
            
            # 使用 [::] 监听，同时支持 IPv4 和 IPv6 入站
            cat >> "$REALM_CONFIG" << EOF
[[endpoints]]
listen = "[::]:$LOCAL_PORT"
remote = "$REALM_TARGET"

EOF
            echo -e "  ✓ :$LOCAL_PORT -> $REALM_TARGET (IPv4+IPv6)"
        done
        
        # 创建systemd服务
        cat > /etc/systemd/system/realm-forward.service << EOF
[Unit]
Description=Realm Port Forward
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/realm -c /etc/realm/config.toml
Restart=always
RestartSec=3
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable realm-forward
        if systemctl start realm-forward 2>&1; then
            echo -e "${GREEN}realm 配置完成，共 ${#PORT_MAPPINGS[@]} 条规则${NC}"
        else
            echo -e "${RED}realm启动失败${NC}"
            echo -e "${YELLOW}查看错误日志: journalctl -u realm-forward -n 20${NC}"
            echo -e "${YELLOW}手动测试: realm -c /etc/realm/config.toml${NC}"
        fi
        ;;
        
    7)
        # rinetd转发
        echo -e "${YELLOW}配置rinetd转发...${NC}"
        
        # 检查并安装rinetd
        if ! command -v rinetd >/dev/null 2>&1; then
            echo -e "${YELLOW}安装rinetd...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update -qq && apt-get install -y --no-install-recommends rinetd
            elif [ -f /etc/redhat-release ]; then
                yum install -y rinetd
            fi
        fi
        
        # rinetd 配置 - 支持追加模式
        RINETD_CONFIG="/etc/rinetd.conf"
        
        # 检查是否已有配置
        if [ -f "$RINETD_CONFIG" ] && grep -q "^0.0.0.0" "$RINETD_CONFIG"; then
            echo -e "${GREEN}检测到现有 rinetd 配置，将追加新规则${NC}"
        else
            # 创建新配置文件
            cat > "$RINETD_CONFIG" << EOF
# rinetd配置文件 - 由端口转发脚本生成
# 格式: bindaddress bindport connectaddress connectport

# 日志文件
logfile /var/log/rinetd.log
EOF
        fi
        
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            
            # 先删除该端口的旧配置
            sed -i "/^0.0.0.0 $LOCAL_PORT /d" "$RINETD_CONFIG" 2>/dev/null || true
            
            # 在 logfile 行之前插入新规则
            sed -i "/^logfile/i 0.0.0.0 $LOCAL_PORT $TARGET_IP $TARGET_PORT" "$RINETD_CONFIG"
            echo -e "  ✓ :$LOCAL_PORT -> $TARGET_IP:$TARGET_PORT"
        done
        
        # 检测rinetd路径
        RINETD_BIN="/usr/sbin/rinetd"
        if [ ! -f "$RINETD_BIN" ]; then
            if [ -f /usr/bin/rinetd ]; then
                RINETD_BIN="/usr/bin/rinetd"
            elif command -v rinetd >/dev/null 2>&1; then
                RINETD_BIN=$(which rinetd)
            else
                echo -e "${RED}rinetd可执行文件未找到${NC}"
                exit 1
            fi
        fi
        echo -e "${GREEN}rinetd路径: $RINETD_BIN${NC}"
        
        # 删除可能冲突的自定义服务文件
        rm -f /etc/systemd/system/rinetd.service 2>/dev/null || true
        systemctl daemon-reload
        
        # 使用系统自带的服务
        systemctl enable rinetd
        systemctl restart rinetd
        
        # 等待服务启动
        sleep 2
        
        if systemctl is-active rinetd >/dev/null 2>&1; then
            echo -e "${GREEN}rinetd 配置完成，共 $(grep -c "^0.0.0.0" "$RINETD_CONFIG") 条规则${NC}"
        else
            echo -e "${RED}rinetd启动失败，查看日志...${NC}"
            journalctl -u rinetd -n 10 --no-pager
        fi
        ;;
        
    8)
        # nginx stream转发
        echo -e "${YELLOW}配置nginx stream转发...${NC}"
        
        # 检查是否已有nginx运行（可能是用户自己的服务）
        NGINX_ALREADY_RUNNING=false
        if systemctl is-active nginx >/dev/null 2>&1; then
            NGINX_ALREADY_RUNNING=true
            echo -e "${YELLOW}检测到nginx已在运行${NC}"
        fi
        
        # 先清理可能存在的错误stream配置（防止安装失败）
        if [ -f /etc/nginx/nginx.conf ]; then
            if grep -q "^stream {" /etc/nginx/nginx.conf 2>/dev/null; then
                echo -e "${YELLOW}清理旧的stream配置...${NC}"
                sed -i '/^# Stream模块配置/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
                sed -i '/^stream {/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
            fi
        fi
        
        # 检查并安装支持stream模块的nginx
        NEED_INSTALL=false
        if ! command -v nginx >/dev/null 2>&1; then
            NEED_INSTALL=true
        elif ! nginx -V 2>&1 | grep -q "with-stream"; then
            echo -e "${YELLOW}当前nginx不支持stream模块，需要升级...${NC}"
            NEED_INSTALL=true
        fi
        
        if [ "$NEED_INSTALL" = true ]; then
            echo -e "${YELLOW}安装nginx-full (含stream模块)...${NC}"
            if [ -f /etc/debian_version ]; then
                # 停止现有nginx
                systemctl stop nginx 2>/dev/null || true
                # 清理可能损坏的nginx配置
                if [ -f /etc/nginx/nginx.conf ]; then
                    sed -i '/^# Stream模块配置/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
                    sed -i '/^stream {/,/^}$/d' /etc/nginx/nginx.conf 2>/dev/null || true
                fi
                # 卸载旧版nginx并安装nginx-full
                apt-get update -qq
                apt-get remove -y --purge nginx nginx-common nginx-core 2>/dev/null || true
                apt-get autoremove -y 2>/dev/null || true
                # 修复可能损坏的包
                dpkg --configure -a 2>/dev/null || true
                apt-get install -y -f 2>/dev/null || true
                apt-get install -y nginx-full
                NGINX_ALREADY_RUNNING=false
            elif [ -f /etc/redhat-release ]; then
                yum install -y nginx-mod-stream || yum install -y nginx
            fi
        fi
        
        # 再次检查stream模块
        if ! nginx -V 2>&1 | grep -q "with-stream"; then
            echo -e "${RED}nginx stream模块不可用${NC}"
            echo -e "${YELLOW}请手动执行: apt remove nginx && apt install nginx-full${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}nginx stream模块可用${NC}"
        
        # 创建stream配置目录
        mkdir -p /etc/nginx/stream.d
        
        # 备份当前nginx配置
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%s) 2>/dev/null || true
        
        # Debian/Ubuntu 需要先加载 stream 模块
        if [ -f /etc/debian_version ]; then
            # 检查是否已加载stream模块
            if ! grep -q "load_module.*ngx_stream_module" /etc/nginx/nginx.conf; then
                # 检查模块文件是否存在
                if [ -f /usr/lib/nginx/modules/ngx_stream_module.so ]; then
                    echo -e "${YELLOW}加载nginx stream模块...${NC}"
                    # 在文件开头添加load_module指令
                    sed -i '1i load_module /usr/lib/nginx/modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
                elif [ -f /usr/share/nginx/modules/ngx_stream_module.so ]; then
                    sed -i '1i load_module /usr/share/nginx/modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
                fi
            fi
        fi
        
        # 检查nginx主配置是否包含stream块
        if ! grep -q "^stream {" /etc/nginx/nginx.conf && ! grep -q "include.*stream" /etc/nginx/nginx.conf; then
            echo -e "${YELLOW}添加stream配置块...${NC}"
            # 在文件末尾添加stream块（不影响http块）
            cat >> /etc/nginx/nginx.conf << 'EOF'

# Stream模块配置 - 端口转发
stream {
    include /etc/nginx/stream.d/*.conf;
}
EOF
        fi
        
        # 为每个端口创建 stream 转发配置
        for mapping in "${PORT_MAPPINGS[@]}"; do
            LOCAL_PORT=$(echo "$mapping" | cut -d: -f1)
            TARGET_PORT=$(echo "$mapping" | cut -d: -f2)
            
            # IPv6 地址需要用方括号包裹
            if [ "$IS_IPV6" = true ]; then
                NGINX_TARGET="[$TARGET_IP]:$TARGET_PORT"
            else
                NGINX_TARGET="$TARGET_IP:$TARGET_PORT"
            fi
            
            cat > /etc/nginx/stream.d/port-forward-${LOCAL_PORT}.conf << EOF
# Nginx Stream 端口转发配置 - 端口 $LOCAL_PORT
upstream backend_$LOCAL_PORT {
    server $NGINX_TARGET max_fails=3 fail_timeout=30s;
}

server {
    listen $LOCAL_PORT;
    listen [::]:$LOCAL_PORT;
    proxy_pass backend_$LOCAL_PORT;
    
    # 性能优化
    proxy_connect_timeout 1s;
    proxy_timeout 3600s;
    proxy_buffer_size 16k;
    
    # TCP优化
    tcp_nodelay on;
}
EOF
            echo -e "  ✓ :$LOCAL_PORT -> $TARGET_IP:$TARGET_PORT (IPv4+IPv6)"
        done
        
        # 测试nginx配置
        echo -e "${YELLOW}测试nginx配置...${NC}"
        if nginx -t 2>&1; then
            systemctl enable nginx
            if [ "$NGINX_ALREADY_RUNNING" = true ]; then
                # 已有nginx运行，只reload不restart
                nginx -s reload 2>&1 && echo -e "${GREEN}nginx配置已重载${NC}"
            else
                systemctl restart nginx 2>&1 && echo -e "${GREEN}nginx已启动${NC}"
            fi
            echo -e "${GREEN}nginx stream 配置完成，共 ${#PORT_MAPPINGS[@]} 条规则${NC}"
        else
            echo -e "${RED}nginx配置测试失败${NC}"
            echo -e "${YELLOW}详细错误信息:${NC}"
            nginx -t
        fi
        ;;
esac

echo -e "${BLUE}[步骤4/4] 验证配置...${NC}"
echo ""

# 检查服务状态
case $FORWARD_METHOD in
    1)
        # iptables DNAT - 详细验证
        IPTABLES_CMD=$(get_iptables_cmd)
        
        echo -e "${CYAN}验证 iptables 规则:${NC}"
        
        # 检查DNAT规则（使用更准确的检测）
        DNAT_CHECK=$($IPTABLES_CMD -t nat -L PREROUTING -n -v 2>/dev/null | grep "dpt:$LOCAL_PORT")
        if [ -n "$DNAT_CHECK" ]; then
            echo -e "${GREEN}✓ DNAT规则已生效${NC}"
            echo -e "  ${YELLOW}$DNAT_CHECK${NC}"
        else
            echo -e "${RED}✗ DNAT规则未找到${NC}"
        fi
        
        # 检查MASQUERADE规则
        MASQ_CHECK=$($IPTABLES_CMD -t nat -L POSTROUTING -n 2>/dev/null | grep MASQUERADE | head -1)
        if [ -n "$MASQ_CHECK" ]; then
            echo -e "${GREEN}✓ MASQUERADE规则已生效${NC}"
        fi
        
        # 检查IP转发
        if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
            echo -e "${GREEN}✓ IP转发已启用${NC}"
        else
            echo -e "${RED}✗ IP转发未启用${NC}"
        fi
        ;;
    2)
        # nftables DNAT - 详细验证
        echo -e "${CYAN}验证 nftables 规则:${NC}"
        
        # 检查DNAT规则
        DNAT_CHECK=$(nft list chain inet port_forward prerouting 2>/dev/null | grep "dport $LOCAL_PORT")
        if [ -n "$DNAT_CHECK" ]; then
            echo -e "${GREEN}✓ DNAT规则已生效${NC}"
            echo -e "  ${YELLOW}$DNAT_CHECK${NC}"
        else
            echo -e "${RED}✗ DNAT规则未找到${NC}"
        fi
        
        # 检查MASQUERADE规则
        MASQ_CHECK=$(nft list chain inet port_forward postrouting 2>/dev/null | grep "masquerade")
        if [ -n "$MASQ_CHECK" ]; then
            echo -e "${GREEN}✓ MASQUERADE规则已生效${NC}"
        fi
        
        # 检查IP转发
        if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
            echo -e "${GREEN}✓ IP转发已启用${NC}"
        else
            echo -e "${RED}✗ IP转发未启用${NC}"
        fi
        ;;
    3)
        # HAProxy - 检查服务状态
        if systemctl is-active haproxy >/dev/null 2>&1; then
            echo -e "${GREEN}✅ HAProxy服务运行正常${NC}"
        else
            echo -e "${RED}❌ HAProxy服务异常${NC}"
        fi
        ;;
    4)
        # socat - 检查服务状态
        if systemctl is-active port-forward >/dev/null 2>&1; then
            echo -e "${GREEN}✅ socat服务运行正常${NC}"
        else
            echo -e "${RED}❌ socat服务异常${NC}"
        fi
        ;;
    5)
        # gost - 检查服务状态
        if systemctl is-active gost-forward >/dev/null 2>&1; then
            echo -e "${GREEN}✅ gost服务运行正常${NC}"
        else
            echo -e "${RED}❌ gost服务异常${NC}"
        fi
        ;;
    6)
        # realm - 检查服务状态
        if systemctl is-active realm-forward >/dev/null 2>&1; then
            echo -e "${GREEN}✅ realm服务运行正常${NC}"
        else
            echo -e "${RED}❌ realm服务异常${NC}"
        fi
        ;;
    7)
        # rinetd - 检查服务状态
        if systemctl is-active rinetd >/dev/null 2>&1; then
            echo -e "${GREEN}✅ rinetd服务运行正常${NC}"
        else
            echo -e "${RED}❌ rinetd服务异常${NC}"
        fi
        ;;
    8)
        # nginx - 检查服务状态
        if systemctl is-active nginx >/dev/null 2>&1; then
            echo -e "${GREEN}✅ nginx服务运行正常${NC}"
        else
            echo -e "${RED}❌ nginx服务异常${NC}"
        fi
        ;;
esac

# 对于用户态服务，检查端口监听（等待服务启动）
if [[ $FORWARD_METHOD =~ ^[3-8]$ ]]; then
    sleep 2  # 等待服务完全启动
    if ss -tlnp 2>/dev/null | grep ":${LOCAL_PORT}" >/dev/null; then
        echo -e "${GREEN}✅ 端口 $LOCAL_PORT 监听正常${NC}"
    else
        echo -e "${RED}❌ 端口 $LOCAL_PORT 监听异常${NC}"
    fi
fi

# 测试目标服务器和延迟（所有转发方式都显示）
echo ""
echo "测试目标服务器:"

# 测试连接和延迟
if command -v ping >/dev/null 2>&1; then
    PING_RESULT=$(ping -c 3 -W 2 $TARGET_IP 2>/dev/null | grep 'avg' | awk -F'/' '{print $5}')
    if [ -n "$PING_RESULT" ]; then
        echo -e "${GREEN}✓ 目标服务器 $TARGET_IP 可达${NC}"
        echo "  网络延迟: ${PING_RESULT}ms"
    else
        echo "  无法获取延迟信息"
    fi
fi

# 测试目标端口
if command -v nc >/dev/null 2>&1; then
    if nc -z -w 2 $TARGET_IP $TARGET_PORT 2>/dev/null; then
        echo -e "${GREEN}✓ 目标端口 $TARGET_IP:$TARGET_PORT 可达${NC}"
    else
        echo -e "${RED}✗ 目标端口 $TARGET_IP:$TARGET_PORT 不可达${NC}"
    fi
elif command -v timeout >/dev/null 2>&1; then
    if timeout 2 bash -c "echo >/dev/tcp/$TARGET_IP/$TARGET_PORT" 2>/dev/null; then
        echo -e "${GREEN}✓ 目标端口 $TARGET_IP:$TARGET_PORT 可达${NC}"
    fi
fi

# iptables DNAT 额外验证
if [ "$FORWARD_METHOD" = "1" ]; then
    echo ""
    echo "验证 iptables 规则:"
    IPTABLES_CMD=$(get_iptables_cmd)
    if $IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -q "dpt:$LOCAL_PORT"; then
        echo -e "${GREEN}✓ DNAT规则已生效${NC}"
    else
        echo -e "${RED}✗ DNAT规则未找到${NC}"
    fi
    
    IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [ "$IP_FORWARD" = "1" ]; then
        echo -e "${GREEN}✓ IP转发已启用${NC}"
    else
        echo -e "${RED}✗ IP转发未启用${NC}"
    fi
fi

echo ""
echo "=========================================="
echo "           部署完成！"
echo "=========================================="

echo ""
echo "🚀 端口转发服务已启动！"
echo ""
echo "连接信息："
echo "本地地址: $(get_local_ip):$LOCAL_PORT"
echo "目标地址: $TARGET_IP:$TARGET_PORT"
case $FORWARD_METHOD in
    1) echo "转发方式: iptables DNAT" ;;
    2) echo "转发方式: nftables DNAT" ;;
    3) echo "转发方式: HAProxy" ;;
    4) echo "转发方式: socat" ;;
    5) echo "转发方式: gost" ;;
    6) echo "转发方式: realm" ;;
    7) echo "转发方式: rinetd" ;;
    8) echo "转发方式: nginx stream" ;;
esac

# 显示延迟信息
if [ -n "$PING_RESULT" ]; then
    echo "网络延迟: ${PING_RESULT}ms"
fi

echo ""
echo "性能优化特性："
echo "✅ BBR拥塞控制算法"
echo "✅ TCP Fast Open"
echo "✅ 256MB缓冲区优化"
echo "✅ 早期重传机制"
echo "✅ 瘦流优化"
echo "✅ 禁用延迟ACK"
echo "✅ 连接跟踪优化"

echo ""
echo "测试方法："
case $FORWARD_METHOD in
    1) 
        IPTABLES_CMD=$(get_iptables_cmd)
        LOCAL_IP=$(get_local_ip)
        echo "从其他机器测试:"
        echo "  telnet $LOCAL_IP $LOCAL_PORT"
        echo ""
        echo "查看规则:"
        echo "  $IPTABLES_CMD -t nat -L -n -v"
        ;;
    2)
        LOCAL_IP=$(get_local_ip)
        echo "从其他机器测试:"
        echo "  telnet $LOCAL_IP $LOCAL_PORT"
        echo ""
        echo "查看规则:"
        echo "  nft list table inet port_forward"
        echo ""
        echo "流量统计:"
        echo "  运行 pf 选择菜单选项 6"
        ;;
    3) 
        echo "服务状态: systemctl status haproxy"
        echo "重启服务: systemctl restart haproxy"
        echo "查看日志: journalctl -u haproxy -f"
        echo -e "查看配置: cat /etc/haproxy/haproxy.cfg"
        echo -e "Web凭据: cat /root/haproxy_credentials.txt"
        if [ -f /root/haproxy_credentials.txt ]; then
            echo -e "统计页面: http://$(get_local_ip):8888/haproxy-stats"
        fi
        ;;
    4) 
        echo -e "服务状态: systemctl status port-forward"
        echo -e "重启服务: systemctl restart port-forward"
        echo -e "查看日志: journalctl -u port-forward -f"
        ;;
    5)
        echo -e "服务状态: systemctl status gost-forward"
        echo -e "重启服务: systemctl restart gost-forward"
        echo -e "查看日志: journalctl -u gost-forward -f"
        echo -e "查看服务配置: systemctl cat gost-forward"
        if [ -f /etc/gost/config.yaml ]; then
            echo -e "查看配置: cat /etc/gost/config.yaml"
            echo -e "测试gost: gost -C /etc/gost/config.yaml"
        else
            echo -e "测试gost: gost -L tcp://:$LOCAL_PORT/$TARGET_IP:$TARGET_PORT"
        fi
        echo "API凭据: cat /root/gost_credentials.txt"
        if [ -f /root/gost_credentials.txt ]; then
            echo "Web API: http://$(get_local_ip):9999/api/config"
        fi
        ;;
    6)
        echo -e "服务状态: systemctl status realm-forward"
        echo -e "重启服务: systemctl restart realm-forward"
        echo -e "查看日志: journalctl -u realm-forward -f"
        echo -e "查看配置: cat /etc/realm/config.toml"
        echo -e "测试realm: realm -c /etc/realm/config.toml"
        ;;
    7)
        echo -e "服务状态: systemctl status rinetd"
        echo -e "重启服务: systemctl restart rinetd"
        echo -e "查看日志: journalctl -u rinetd -f"
        echo -e "查看配置: cat /etc/rinetd.conf"
        echo -e "查看转发日志: tail -f /var/log/rinetd.log"
        ;;
    8)
        # 检测nginx状态页面端口
        if [ -f /etc/nginx/sites-available/status ]; then
            NGINX_STATUS_PORT=$(grep "listen" /etc/nginx/sites-available/status | grep -oP '\d+' || echo "8080")
        elif [ -f /etc/nginx/conf.d/status.conf ]; then
            NGINX_STATUS_PORT=$(grep "listen" /etc/nginx/conf.d/status.conf | grep -oP '\d+' || echo "8080")
        else
            NGINX_STATUS_PORT="8080"
        fi
        
        echo -e "服务状态: systemctl status nginx"
        echo -e "重启服务: systemctl restart nginx"
        echo -e "查看日志: journalctl -u nginx -f"
        echo -e "查看配置: ls /etc/nginx/stream.d/"
        echo -e "测试配置: nginx -t"
        echo -e "重载配置: nginx -s reload"
        echo -e "状态页面: http://$(get_local_ip):$NGINX_STATUS_PORT/nginx-status"
        ;;
esac

echo -e "测试连接: telnet $(get_local_ip) $LOCAL_PORT"
echo -e "配置备份: $BACKUP_DIR"

echo ""
echo -e "${CYAN}${BOLD}🎯 端口转发配置完成！${NC}"
echo -e "${CYAN}==========================================${NC}"
