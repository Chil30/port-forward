#!/bin/bash
# 通用端口转发管理工具
# 支持多种转发方案，适用于各种网络服务

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# 生成随机密码函数
generate_password() {
    local length=${1:-16}
    # 使用/dev/urandom生成随机密码，包含大小写字母、数字和特殊字符
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c $length
}

# 智能选择 iptables 命令（避免 nftables 兼容性问题）
get_iptables_cmd() {
    # 优先使用 iptables-legacy
    if command -v iptables-legacy >/dev/null 2>&1; then
        echo "iptables-legacy"
    else
        echo "iptables"
    fi
}

echo -e "${CYAN}${BOLD}=========================================="
echo -e "        端口转发管理工具"
echo -e "==========================================${NC}"

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}需要root权限运行此脚本${NC}"
    echo -e "${YELLOW}请使用: sudo $0${NC}"
    exit 1
fi

# 自动删除脚本（避免重复下载产生 .1 .2 等文件）
SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_NAME="$(basename "$SCRIPT_PATH")"

# 如果脚本名是 port-forward.sh 或 port_forward.sh，且在当前目录或临时目录，则在退出时删除
if [[ "$SCRIPT_NAME" == "port-forward.sh" || "$SCRIPT_NAME" == "port_forward.sh" ]]; then
    trap 'rm -f "$SCRIPT_PATH" 2>/dev/null' EXIT
fi

# 主菜单
echo -e "${YELLOW}请选择操作：${NC}"
echo -e "1) 配置新的端口转发"
echo -e "2) 查看当前转发状态"
echo -e "3) 查看运行日志"
echo -e "4) 停止转发服务"
echo -e "5) 卸载转发服务"
echo -e "6) 恢复原始配置"
echo -e "7) 启动转发服务"
echo -e "8) 清理备份文件"
echo -e "9) 退出"
echo ""

while true; do
    read -p "$(echo -e ${YELLOW}请选择操作 [1]: ${NC})" MAIN_ACTION
    MAIN_ACTION=${MAIN_ACTION:-1}
    if [[ $MAIN_ACTION =~ ^[1-9]$ ]]; then
        break
    else
        echo -e "${RED}请输入 1-9 之间的数字${NC}"
    fi
done

case $MAIN_ACTION in
    2)
        echo -e "${BLUE}${BOLD}===========================================${NC}"
        echo -e "${BLUE}${BOLD}      当前转发服务状态${NC}"
        echo -e "${BLUE}${BOLD}===========================================${NC}"
        echo ""
        
        # 检查各种服务状态
        echo -e "${CYAN}${BOLD}=== 服务运行状态 ===${NC}"
        ACTIVE_COUNT=0
        services=("haproxy" "port-forward" "gost-forward" "realm-forward" "rinetd" "nginx")
        for service in "${services[@]}"; do
            if systemctl is-active $service >/dev/null 2>&1; then
                echo -e "${GREEN}✅ $service 运行中${NC}"
                ACTIVE_COUNT=$((ACTIVE_COUNT+1))
                if command -v ss >/dev/null 2>&1; then
                    ports=$(ss -tlnp | grep $service | awk '{print $4}' | cut -d':' -f2 | tr '\n' ' ')
                    if [ -n "$ports" ]; then
                        echo -e "   ${YELLOW}监听端口:${NC} $ports"
                    fi
                fi
            fi
        done
        
        # 检查防火墙规则（使用正确的命令）
        IPTABLES_CMD=$(get_iptables_cmd)
        if $IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -q DNAT; then
            echo -e "${GREEN}✅ iptables DNAT 规则活跃${NC}"
            ACTIVE_COUNT=$((ACTIVE_COUNT+1))
            DNAT_RULES=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep DNAT | wc -l)
            echo -e "   ${YELLOW}规则数量:${NC} $DNAT_RULES 条"
        fi
        
        if [ $ACTIVE_COUNT -eq 0 ]; then
            echo -e "${YELLOW}⚠️  没有运行中的转发服务${NC}"
        else
            echo -e "${GREEN}共 $ACTIVE_COUNT 个服务正在运行${NC}"
        fi
        
        # 显示配置信息
        echo ""
        echo -e "${CYAN}${BOLD}=== 配置信息 ===${NC}"
        
        # 检查备份目录
        BACKUP_BASE_DIR="/root/.port_forward_backups"
        if [ -d "$BACKUP_BASE_DIR" ]; then
            BACKUP_COUNT=$(ls -d "$BACKUP_BASE_DIR"/* 2>/dev/null | wc -l)
            echo -e "${YELLOW}配置备份:${NC} $BACKUP_COUNT 个备份"
            LATEST_BACKUP=$(ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -1)
            if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/backup_info.txt" ]; then
                echo -e "${YELLOW}最近备份:${NC}"
                cat "$LATEST_BACKUP/backup_info.txt" | sed 's/^/  /'
            fi
        else
            echo -e "${YELLOW}配置备份:${NC} 无"
        fi
        
        # 检查凭据文件
        echo ""
        if [ -f /root/haproxy_credentials.txt ]; then
            echo -e "${CYAN}HAProxy 管理界面:${NC} /root/haproxy_credentials.txt"
        fi
        if [ -f /root/gost_credentials.txt ]; then
            echo -e "${CYAN}Gost API 凭据:${NC} /root/gost_credentials.txt"
        fi
        
        # 显示当前监听的端口
        echo ""
        echo -e "${CYAN}${BOLD}=== 当前监听端口 ===${NC}"
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | grep -E 'haproxy|socat|gost|realm|rinetd|nginx' | awk '{print $4, $6}' | column -t | sed 's/^/  /'
        fi
        
        # IP转发状态
        echo ""
        echo -e "${CYAN}${BOLD}=== 系统配置 ===${NC}"
        IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
        if [ "$IP_FORWARD" = "1" ]; then
            echo -e "${GREEN}IP转发: 已启用${NC}"
        else
            echo -e "${RED}IP转发: 已禁用${NC}"
        fi
        
        # BBR状态
        BBR_STATUS=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
        if [ "$BBR_STATUS" = "bbr" ]; then
            echo -e "${GREEN}BBR拥塞控制: 已启用${NC}"
        else
            echo -e "${YELLOW}BBR拥塞控制: $BBR_STATUS${NC}"
        fi
        
        echo ""
        echo -e "${BLUE}${BOLD}===========================================${NC}"
        echo -e "${YELLOW}按回车键返回主菜单...${NC}"
        read
        exec $0
        ;;
    3)
        echo -e "${BLUE}查看运行日志：${NC}"
        echo ""
        echo -e "${YELLOW}请选择要查看的服务日志：${NC}"
        echo -e "1) iptables 规则和连接"
        echo -e "2) HAProxy 日志"
        echo -e "3) socat (port-forward) 日志"
        echo -e "4) gost 日志"
        echo -e "5) realm 日志"
        echo -e "6) rinetd 日志"
        echo -e "7) nginx stream 日志"
        echo -e "8) 系统网络日志"
        echo -e "0) 返回主菜单"
        echo ""
        read -p "$(echo -e ${YELLOW}请选择 [1]: ${NC})" LOG_CHOICE
        LOG_CHOICE=${LOG_CHOICE:-1}
        
        case $LOG_CHOICE in
            1)
                echo -e "${GREEN}iptables 规则和连接状态:${NC}"
                echo ""
                echo -e "${YELLOW}=== NAT 转发规则 ===${NC}"
                # 优先使用 iptables-legacy，避免 nftables 兼容性问题
                if command -v iptables-legacy >/dev/null 2>&1; then
                    iptables-legacy -t nat -L -n -v --line-numbers
                elif iptables -t nat -L -n -v --line-numbers 2>&1 | grep -q "incompatible"; then
                    echo -e "${YELLOW}检测到系统使用 nftables 后端，尝试使用 iptables-legacy...${NC}"
                    if command -v iptables-legacy >/dev/null 2>&1; then
                        iptables-legacy -t nat -L -n -v --line-numbers
                    else
                        echo -e "${RED}请安装 iptables-legacy: apt install iptables${NC}"
                        echo -e "${YELLOW}或使用 nft 命令查看规则: nft list ruleset${NC}"
                    fi
                else
                    iptables -t nat -L -n -v --line-numbers
                fi
                echo ""
                echo -e "${YELLOW}=== 当前监听端口 ===${NC}"
                ss -tlnp 2>/dev/null | grep -v "127.0.0" | head -20 || netstat -tlnp 2>/dev/null | grep -v "127.0.0" | head -20
                echo ""
                echo -e "${YELLOW}=== 活跃连接 (最近20条) ===${NC}"
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
                if systemctl is-active haproxy >/dev/null 2>&1; then
                    echo -e "${GREEN}HAProxy 实时日志 (Ctrl+C 退出):${NC}"
                    journalctl -u haproxy -f --no-pager -n 50
                else
                    echo -e "${RED}HAProxy 服务未运行${NC}"
                fi
                ;;
            3)
                if systemctl is-active port-forward >/dev/null 2>&1; then
                    echo -e "${GREEN}socat 实时日志 (Ctrl+C 退出):${NC}"
                    journalctl -u port-forward -f --no-pager -n 50
                else
                    echo -e "${RED}port-forward 服务未运行${NC}"
                fi
                ;;
            4)
                if systemctl is-active gost-forward >/dev/null 2>&1; then
                    echo -e "${GREEN}gost 实时日志 (Ctrl+C 退出):${NC}"
                    journalctl -u gost-forward -f --no-pager -n 50
                else
                    echo -e "${RED}gost-forward 服务未运行${NC}"
                fi
                ;;
            5)
                if systemctl is-active realm-forward >/dev/null 2>&1; then
                    echo -e "${GREEN}realm 实时日志 (Ctrl+C 退出):${NC}"
                    journalctl -u realm-forward -f --no-pager -n 50
                else
                    echo -e "${RED}realm-forward 服务未运行${NC}"
                fi
                ;;
            6)
                if systemctl is-active rinetd >/dev/null 2>&1; then
                    echo -e "${GREEN}rinetd 实时日志 (Ctrl+C 退出):${NC}"
                    journalctl -u rinetd -f --no-pager -n 50
                else
                    echo -e "${RED}rinetd 服务未运行${NC}"
                fi
                ;;
            7)
                if systemctl is-active nginx >/dev/null 2>&1; then
                    echo -e "${GREEN}nginx 实时日志 (Ctrl+C 退出):${NC}"
                    if [ -f /var/log/nginx/stream.log ]; then
                        tail -f /var/log/nginx/stream.log
                    else
                        journalctl -u nginx -f --no-pager -n 50
                    fi
                else
                    echo -e "${RED}nginx 服务未运行${NC}"
                fi
                ;;
            8)
                echo -e "${GREEN}系统网络日志 (Ctrl+C 退出):${NC}"
                journalctl -k -f --no-pager -n 50 | grep -i "net\|tcp\|udp\|port"
                ;;
            0)
                exec $0
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                ;;
        esac
        echo ""
        echo -e "${YELLOW}按回车键返回主菜单...${NC}"
        read
        exec $0
        ;;
    4)
        echo -e "${BLUE}停止转发服务${NC}"
        echo ""
        echo -e "${YELLOW}请选择要停止的服务：${NC}"
        echo -e "1) iptables DNAT 规则"
        echo -e "2) HAProxy"
        echo -e "3) socat (port-forward)"
        echo -e "4) gost"
        echo -e "5) realm"
        echo -e "6) rinetd"
        echo -e "7) nginx"
        echo -e "8) 停止所有服务"
        echo -e "0) 返回主菜单"
        echo ""
        read -p "$(echo -e ${YELLOW}请选择 [8]: ${NC})" STOP_CHOICE
        STOP_CHOICE=${STOP_CHOICE:-8}
        
        case $STOP_CHOICE in
            1)
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
                # 禁用IP转发（可选，如果不需要其他转发功能）
                # echo 0 > /proc/sys/net/ipv4/ip_forward
                echo -e "${GREEN}iptables DNAT 规则已清理${NC}"
                echo -e "${YELLOW}提示：IP转发仍然启用，如需禁用请手动执行: echo 0 > /proc/sys/net/ipv4/ip_forward${NC}"
                ;;
            2)
                systemctl stop haproxy 2>/dev/null && echo -e "${GREEN}HAProxy已停止${NC}" || echo -e "${YELLOW}HAProxy未运行${NC}"
                ;;
            3)
                systemctl stop port-forward 2>/dev/null && echo -e "${GREEN}socat已停止${NC}" || echo -e "${YELLOW}socat未运行${NC}"
                ;;
            4)
                systemctl stop gost-forward 2>/dev/null && echo -e "${GREEN}gost已停止${NC}" || echo -e "${YELLOW}gost未运行${NC}"
                ;;
            5)
                systemctl stop realm-forward 2>/dev/null && echo -e "${GREEN}realm已停止${NC}" || echo -e "${YELLOW}realm未运行${NC}"
                ;;
            6)
                systemctl stop rinetd 2>/dev/null && echo -e "${GREEN}rinetd已停止${NC}" || echo -e "${YELLOW}rinetd未运行${NC}"
                ;;
            7)
                systemctl stop nginx 2>/dev/null && echo -e "${GREEN}nginx已停止${NC}" || echo -e "${YELLOW}nginx未运行${NC}"
                ;;
            8)
                echo -e "${YELLOW}停止所有转发服务...${NC}"
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
                
                echo -e "${GREEN}所有转发服务已停止${NC}"
                echo -e "${YELLOW}提示：IP转发仍然启用，如需禁用请手动执行: echo 0 > /proc/sys/net/ipv4/ip_forward${NC}"
                ;;
            0)
                exec $0
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                ;;
        esac
        echo ""
        echo -e "${YELLOW}按回车键返回主菜单...${NC}"
        read
        exec $0
        ;;
    5)
        echo -e "${RED}卸载转发服务${NC}"
        echo ""
        echo -e "${YELLOW}请选择要卸载的服务：${NC}"
        echo -e "1) iptables DNAT 规则"
        echo -e "2) HAProxy"
        echo -e "3) socat (port-forward)"
        echo -e "4) gost"
        echo -e "5) realm"
        echo -e "6) rinetd"
        echo -e "7) nginx stream配置"
        echo -e "8) 卸载所有服务"
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
                    $IPTABLES_CMD-save > /tmp/iptables_before_clean.txt 2>/dev/null || true
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    echo -e "${GREEN}iptables DNAT 规则已清理${NC}"
                    ;;
                2)
                    echo -e "${YELLOW}卸载HAProxy...${NC}"
                    systemctl stop haproxy 2>/dev/null || true
                    systemctl disable haproxy 2>/dev/null || true
                    echo -e "${GREEN}HAProxy已停止和禁用${NC}"
                    echo -e "${YELLOW}注意：HAProxy软件包未删除，如需完全删除请手动执行: apt/yum remove haproxy${NC}"
                    ;;
                3)
                    echo -e "${YELLOW}卸载socat...${NC}"
                    systemctl stop port-forward 2>/dev/null || true
                    systemctl disable port-forward 2>/dev/null || true
                    rm -f /etc/systemd/system/port-forward.service
                    systemctl daemon-reload
                    echo -e "${GREEN}socat转发服务已卸载${NC}"
                    ;;
                4)
                    echo -e "${YELLOW}卸载gost...${NC}"
                    systemctl stop gost-forward 2>/dev/null || true
                    systemctl disable gost-forward 2>/dev/null || true
                    rm -f /etc/systemd/system/gost-forward.service
                    rm -f /usr/local/bin/gost
                    rm -f /root/gost_credentials.txt
                    rm -rf /etc/gost
                    systemctl daemon-reload
                    echo -e "${GREEN}gost已卸载${NC}"
                    ;;
                5)
                    echo -e "${YELLOW}卸载realm...${NC}"
                    systemctl stop realm-forward 2>/dev/null || true
                    systemctl disable realm-forward 2>/dev/null || true
                    rm -f /etc/systemd/system/realm-forward.service
                    rm -rf /etc/realm
                    rm -f /usr/local/bin/realm
                    systemctl daemon-reload
                    echo -e "${GREEN}realm已卸载${NC}"
                    ;;
                6)
                    echo -e "${YELLOW}卸载rinetd...${NC}"
                    systemctl stop rinetd 2>/dev/null || true
                    systemctl disable rinetd 2>/dev/null || true
                    rm -f /etc/rinetd.conf
                    echo -e "${GREEN}rinetd已停止和禁用${NC}"
                    echo -e "${YELLOW}注意：rinetd软件包未删除，如需完全删除请手动执行: apt/yum remove rinetd${NC}"
                    ;;
                7)
                    echo -e "${YELLOW}卸载nginx stream配置...${NC}"
                    if [ -f /etc/nginx/stream.d/port-forward.conf ]; then
                        rm -f /etc/nginx/stream.d/port-forward.conf
                        nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
                        echo -e "${GREEN}nginx stream配置已删除${NC}"
                    else
                        echo -e "${YELLOW}未找到nginx stream配置${NC}"
                    fi
                    ;;
                8)
                    echo -e "${YELLOW}卸载所有转发服务...${NC}"
                    
                    # 停止所有服务
                    echo -e "${YELLOW}停止服务...${NC}"
                    systemctl stop haproxy port-forward gost-forward realm-forward rinetd nginx 2>/dev/null || true
                    systemctl disable haproxy port-forward gost-forward realm-forward rinetd 2>/dev/null || true
                    
                    # 删除服务文件（只删除脚本创建的）
                    echo -e "${YELLOW}删除服务文件...${NC}"
                    rm -f /etc/systemd/system/port-forward.service
                    rm -f /etc/systemd/system/gost-forward.service
                    rm -f /etc/systemd/system/realm-forward.service
                    
                    # 删除配置文件
                    echo -e "${YELLOW}删除配置文件...${NC}"
                    rm -rf /etc/realm
                    rm -rf /etc/gost
                    rm -f /root/haproxy_credentials.txt
                    rm -f /root/gost_credentials.txt
                    if [ -d /etc/nginx/stream.d ]; then
                        rm -f /etc/nginx/stream.d/port-forward.conf
                    fi
                    
                    # 清理 iptables 规则
                    echo -e "${YELLOW}清理 iptables 规则...${NC}"
                    IPTABLES_CMD=$(get_iptables_cmd)
                    $IPTABLES_CMD-save > /tmp/iptables_before_clean.txt 2>/dev/null || true
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    echo -e "${GREEN}iptables 规则已清理${NC}"
                    
                    # 清理下载的二进制文件（只删除脚本安装的）
                    echo -e "${YELLOW}清理二进制文件...${NC}"
                    rm -f /usr/local/bin/gost
                    rm -f /usr/local/bin/realm
                    
                    systemctl daemon-reload
                    echo -e "${GREEN}所有服务已卸载！${NC}"
                    echo -e "${YELLOW}注意：系统内核参数优化已保留，如需恢复请使用'恢复原始配置'功能${NC}"
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
    6)
        echo -e "${YELLOW}恢复原始配置...${NC}"
        # 查找备份文件
        BACKUP_BASE_DIR="/root/.port_forward_backups"
        if [ -d "$BACKUP_BASE_DIR" ]; then
            BACKUP_DIRS=$(ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -10)
            if [ -n "$BACKUP_DIRS" ]; then
                echo -e "${YELLOW}找到以下备份（最近10个）：${NC}"
                echo ""
                i=1
                while IFS= read -r backup_dir; do
                    timestamp=$(basename "$backup_dir")
                    if [ -f "$backup_dir/backup_info.txt" ]; then
                        echo -e "${CYAN}[$i]${NC} 备份时间: $timestamp"
                        cat "$backup_dir/backup_info.txt" | grep -v "备份时间" | sed 's/^/    /'
                        echo ""
                    else
                        echo -e "${CYAN}[$i]${NC} $timestamp"
                    fi
                    i=$((i+1))
                done <<< "$BACKUP_DIRS"
                
                read -p "$(echo -e ${YELLOW}选择要恢复的备份编号: ${NC})" BACKUP_NUM
                SELECTED_BACKUP=$(echo "$BACKUP_DIRS" | sed -n "${BACKUP_NUM}p")
                
                if [ -n "$SELECTED_BACKUP" ] && [ -d "$SELECTED_BACKUP" ]; then
                    if [ -f "$SELECTED_BACKUP/sysctl.conf" ]; then
                        cp "$SELECTED_BACKUP/sysctl.conf" /etc/sysctl.conf
                        sysctl -p
                        echo -e "${GREEN}系统参数已恢复${NC}"
                    fi
                    if [ -f "$SELECTED_BACKUP/iptables_backup.txt" ]; then
                        iptables-restore < "$SELECTED_BACKUP/iptables_backup.txt"
                        echo -e "${GREEN}iptables规则已恢复${NC}"
                    fi
                    echo -e "${GREEN}配置恢复完成${NC}"
                else
                    echo -e "${RED}无效的备份选择${NC}"
                fi
            else
                echo -e "${RED}未找到备份文件${NC}"
            fi
        else
            echo -e "${RED}备份目录不存在${NC}"
        fi
        exit 0
        ;;
    7)
        echo -e "${BLUE}启动转发服务${NC}"
        echo ""
        echo -e "${YELLOW}请选择要启动的服务：${NC}"
        echo -e "1) iptables DNAT 规则"
        echo -e "2) HAProxy"
        echo -e "3) socat (port-forward)"
        echo -e "4) gost"
        echo -e "5) realm"
        echo -e "6) rinetd"
        echo -e "7) nginx"
        echo -e "8) 启动所有已配置服务"
        echo -e "0) 返回主菜单"
        echo ""
        read -p "$(echo -e ${YELLOW}请选择 [8]: ${NC})" START_CHOICE
        START_CHOICE=${START_CHOICE:-8}
        
        case $START_CHOICE in
            1)
                echo -e "${YELLOW}启动 iptables DNAT 规则...${NC}"
                IPTABLES_CMD=$(get_iptables_cmd)
                IPTABLES_RUNNING_BACKUP="/root/.port_forward_iptables_running.txt"
                
                # 优先从运行时备份恢复
                if [ -f "$IPTABLES_RUNNING_BACKUP" ]; then
                    echo -e "${YELLOW}从运行时备份恢复规则...${NC}"
                    
                    # 先清理现有规则
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    
                    # 使用正确的restore命令，添加 --noflush 参数
                    if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                        RESTORE_CMD="iptables-legacy-restore"
                    else
                        RESTORE_CMD="iptables-restore"
                    fi
                    
                    # 使用 --noflush 参数保留其他规则
                    if $RESTORE_CMD --noflush < "$IPTABLES_RUNNING_BACKUP" 2>/dev/null; then
                        echo -e "${GREEN}iptables DNAT 规则已恢复${NC}"
                        # 确保IP转发已启用
                        echo 1 > /proc/sys/net/ipv4/ip_forward
                        # 验证规则
                        sleep 1
                        if $IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -q DNAT; then
                            DNAT_COUNT=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep DNAT | wc -l)
                            echo -e "${GREEN}✅ 规则验证成功，检测到 $DNAT_COUNT 条DNAT规则${NC}"
                        else
                            echo -e "${YELLOW}⚠️  规则恢复但未检测到DNAT，尝试手动验证${NC}"
                            $IPTABLES_CMD -t nat -L PREROUTING -n -v 2>/dev/null | head -20
                        fi
                    else
                        echo -e "${RED}规则恢复失败，尝试查看错误${NC}"
                        $RESTORE_CMD --noflush < "$IPTABLES_RUNNING_BACKUP" 2>&1 | head -10
                    fi
                # 如果运行时备份不存在，尝试从配置备份恢复
                elif [ -d "/root/.port_forward_backups" ]; then
                    BACKUP_BASE_DIR="/root/.port_forward_backups"
                    LATEST_BACKUP=$(ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -1)
                    if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/iptables_current.txt" ]; then
                        echo -e "${YELLOW}从配置备份恢复规则...${NC}"
                        
                        # 先清理现有规则
                        $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                            $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                        done
                        $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                            $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                        done
                        
                        # 使用正确的restore命令，添加 --noflush 参数
                        if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                            RESTORE_CMD="iptables-legacy-restore"
                        else
                            RESTORE_CMD="iptables-restore"
                        fi
                        
                        # 使用 --noflush 参数保留其他规则
                        if $RESTORE_CMD --noflush < "$LATEST_BACKUP/iptables_current.txt" 2>/dev/null; then
                            echo -e "${GREEN}iptables DNAT 规则已恢复${NC}"
                            # 确保IP转发已启用
                            echo 1 > /proc/sys/net/ipv4/ip_forward
                            # 同时保存为运行时备份
                            cp "$LATEST_BACKUP/iptables_current.txt" "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
                            # 验证规则
                            sleep 1
                            if $IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep -q DNAT; then
                                DNAT_COUNT=$($IPTABLES_CMD -t nat -L PREROUTING -n 2>/dev/null | grep DNAT | wc -l)
                                echo -e "${GREEN}✅ 规则验证成功，检测到 $DNAT_COUNT 条DNAT规则${NC}"
                            else
                                echo -e "${YELLOW}⚠️  规则恢复但未检测到DNAT，尝试手动验证${NC}"
                                $IPTABLES_CMD -t nat -L PREROUTING -n -v 2>/dev/null | head -20
                            fi
                        else
                            echo -e "${RED}规则恢复失败，尝试查看错误${NC}"
                            $RESTORE_CMD --noflush < "$LATEST_BACKUP/iptables_current.txt" 2>&1 | head -10
                        fi
                    else
                        echo -e "${RED}未找到iptables备份配置，请先配置服务${NC}"
                    fi
                else
                    echo -e "${RED}未找到备份文件，请先配置服务${NC}"
                fi
                ;;
            2)
                if systemctl is-enabled haproxy >/dev/null 2>&1; then
                    systemctl start haproxy 2>/dev/null && \
                        echo -e "${GREEN}HAProxy已启动${NC}" || \
                        echo -e "${RED}HAProxy启动失败${NC}"
                else
                    echo -e "${RED}HAProxy未配置，请先配置服务${NC}"
                fi
                ;;
            3)
                if [ -f /etc/systemd/system/port-forward.service ]; then
                    systemctl start port-forward 2>/dev/null && \
                        echo -e "${GREEN}socat已启动${NC}" || \
                        echo -e "${RED}socat启动失败${NC}"
                else
                    echo -e "${RED}socat未配置，请先配置服务${NC}"
                fi
                ;;
            4)
                if [ -f /etc/systemd/system/gost-forward.service ]; then
                    systemctl start gost-forward 2>/dev/null && \
                        echo -e "${GREEN}gost已启动${NC}" || \
                        echo -e "${RED}gost启动失败${NC}"
                else
                    echo -e "${RED}gost未配置，请先配置服务${NC}"
                fi
                ;;
            5)
                if [ -f /etc/systemd/system/realm-forward.service ]; then
                    systemctl start realm-forward 2>/dev/null && \
                        echo -e "${GREEN}realm已启动${NC}" || \
                        echo -e "${RED}realm启动失败${NC}"
                else
                    echo -e "${RED}realm未配置，请先配置服务${NC}"
                fi
                ;;
            6)
                if systemctl is-enabled rinetd >/dev/null 2>&1; then
                    systemctl start rinetd 2>/dev/null && \
                        echo -e "${GREEN}rinetd已启动${NC}" || \
                        echo -e "${RED}rinetd启动失败${NC}"
                else
                    echo -e "${RED}rinetd未配置，请先配置服务${NC}"
                fi
                ;;
            7)
                if systemctl is-enabled nginx >/dev/null 2>&1; then
                    systemctl start nginx 2>/dev/null && \
                        echo -e "${GREEN}nginx已启动${NC}" || \
                        echo -e "${RED}nginx启动失败${NC}"
                else
                    echo -e "${RED}nginx未配置，请先配置服务${NC}"
                fi
                ;;
            8)
                echo -e "${YELLOW}启动所有已配置的服务...${NC}"
                STARTED_COUNT=0
                
                # iptables DNAT
                IPTABLES_CMD=$(get_iptables_cmd)
                IPTABLES_RUNNING_BACKUP="/root/.port_forward_iptables_running.txt"
                
                # 优先从运行时备份恢复
                if [ -f "$IPTABLES_RUNNING_BACKUP" ]; then
                    # 先清理
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                        $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                    done
                    # 恢复
                    if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                        RESTORE_CMD="iptables-legacy-restore"
                    else
                        RESTORE_CMD="iptables-restore"
                    fi
                    if $RESTORE_CMD --noflush < "$IPTABLES_RUNNING_BACKUP" 2>/dev/null; then
                        echo -e "${GREEN}✓ iptables DNAT 规则已恢复${NC}"
                        echo 1 > /proc/sys/net/ipv4/ip_forward
                        STARTED_COUNT=$((STARTED_COUNT+1))
                    fi
                # 如果没有运行时备份，尝试从配置备份恢复
                elif [ -d "/root/.port_forward_backups" ]; then
                    BACKUP_BASE_DIR="/root/.port_forward_backups"
                    LATEST_BACKUP=$(ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -1)
                    if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/iptables_current.txt" ]; then
                        # 先清理
                        $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*DNAT" | sed 's/-A/-D/' | while read rule; do
                            $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                        done
                        $IPTABLES_CMD -t nat -S 2>/dev/null | grep "\-A.*MASQUERADE" | sed 's/-A/-D/' | while read rule; do
                            $IPTABLES_CMD -t nat $rule 2>/dev/null || true
                        done
                        # 恢复
                        if [[ "$IPTABLES_CMD" == "iptables-legacy" ]]; then
                            RESTORE_CMD="iptables-legacy-restore"
                        else
                            RESTORE_CMD="iptables-restore"
                        fi
                        if $RESTORE_CMD --noflush < "$LATEST_BACKUP/iptables_current.txt" 2>/dev/null; then
                            echo -e "${GREEN}✓ iptables DNAT 规则已恢复${NC}"
                            echo 1 > /proc/sys/net/ipv4/ip_forward
                            # 同时保存为运行时备份
                            cp "$LATEST_BACKUP/iptables_current.txt" "$IPTABLES_RUNNING_BACKUP" 2>/dev/null || true
                            STARTED_COUNT=$((STARTED_COUNT+1))
                        fi
                    fi
                fi
                
                # HAProxy
                if systemctl is-enabled haproxy >/dev/null 2>&1; then
                    if systemctl start haproxy 2>/dev/null; then
                        echo -e "${GREEN}✓ HAProxy已启动${NC}"
                        STARTED_COUNT=$((STARTED_COUNT+1))
                    fi
                fi
                
                # socat
                if [ -f /etc/systemd/system/port-forward.service ]; then
                    if systemctl start port-forward 2>/dev/null; then
                        echo -e "${GREEN}✓ socat已启动${NC}"
                        STARTED_COUNT=$((STARTED_COUNT+1))
                    fi
                fi
                
                # gost
                if [ -f /etc/systemd/system/gost-forward.service ]; then
                    if systemctl start gost-forward 2>/dev/null; then
                        echo -e "${GREEN}✓ gost已启动${NC}"
                        STARTED_COUNT=$((STARTED_COUNT+1))
                    fi
                fi
                
                # realm
                if [ -f /etc/systemd/system/realm-forward.service ]; then
                    if systemctl start realm-forward 2>/dev/null; then
                        echo -e "${GREEN}✓ realm已启动${NC}"
                        STARTED_COUNT=$((STARTED_COUNT+1))
                    fi
                fi
                
                # rinetd
                if systemctl is-enabled rinetd >/dev/null 2>&1; then
                    if systemctl start rinetd 2>/dev/null; then
                        echo -e "${GREEN}✓ rinetd已启动${NC}"
                        STARTED_COUNT=$((STARTED_COUNT+1))
                    fi
                fi
                
                # nginx
                if systemctl is-enabled nginx >/dev/null 2>&1; then
                    if systemctl start nginx 2>/dev/null; then
                        echo -e "${GREEN}✓ nginx已启动${NC}"
                        STARTED_COUNT=$((STARTED_COUNT+1))
                    fi
                fi
                
                if [ $STARTED_COUNT -eq 0 ]; then
                    echo -e "${RED}未找到已配置的服务，请先配置服务${NC}"
                else
                    echo -e "${GREEN}共启动了 $STARTED_COUNT 个服务${NC}"
                fi
                ;;
            0)
                exec $0
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                ;;
        esac
        echo ""
        echo -e "${YELLOW}按回车键返回主菜单...${NC}"
        read
        exec $0
        ;;
    8)
        echo -e "${BLUE}清理备份文件${NC}"
        echo ""
        BACKUP_BASE_DIR="/root/.port_forward_backups"
        if [ ! -d "$BACKUP_BASE_DIR" ]; then
            echo -e "${YELLOW}备份目录不存在${NC}"
        else
            BACKUP_COUNT=$(ls -d "$BACKUP_BASE_DIR"/* 2>/dev/null | wc -l)
            if [ $BACKUP_COUNT -eq 0 ]; then
                echo -e "${YELLOW}没有备份文件${NC}"
            else
                echo -e "${YELLOW}当前有 $BACKUP_COUNT 个备份文件${NC}"
                echo ""
                echo -e "${YELLOW}请选择清理方式：${NC}"
                echo -e "1) 保留最近5个备份，删除其他"
                echo -e "2) 保留最近10个备份，删除其他"
                echo -e "3) 保留最近20个备份，删除其他"
                echo -e "4) 删除所有备份"
                echo -e "5) 手动选择删除"
                echo -e "0) 返回主菜单"
                echo ""
                read -p "$(echo -e ${YELLOW}请选择 [1]: ${NC})" CLEAN_CHOICE
                CLEAN_CHOICE=${CLEAN_CHOICE:-1}
                
                case $CLEAN_CHOICE in
                    1|2|3)
                        if [ "$CLEAN_CHOICE" = "1" ]; then KEEP=5; fi
                        if [ "$CLEAN_CHOICE" = "2" ]; then KEEP=10; fi
                        if [ "$CLEAN_CHOICE" = "3" ]; then KEEP=20; fi
                        
                        echo -e "${YELLOW}保留最近 $KEEP 个备份...${NC}"
                        DELETED=0
                        ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | tail -n +$((KEEP+1)) | while read backup; do
                            rm -rf "$backup"
                            DELETED=$((DELETED+1))
                        done
                        REMAINING=$(ls -d "$BACKUP_BASE_DIR"/* 2>/dev/null | wc -l)
                        echo -e "${GREEN}清理完成，保留 $REMAINING 个备份${NC}"
                        ;;
                    4)
                        echo -e "${RED}警告：此操作将删除所有备份文件！${NC}"
                        read -p "$(echo -e ${YELLOW}确认删除所有备份? [y/N]: ${NC})" CONFIRM_DELETE
                        if [[ $CONFIRM_DELETE =~ ^[Yy]$ ]]; then
                            rm -rf "$BACKUP_BASE_DIR"/*
                            echo -e "${GREEN}所有备份已删除${NC}"
                        else
                            echo -e "${YELLOW}已取消${NC}"
                        fi
                        ;;
                    5)
                        echo -e "${YELLOW}备份列表（最近20个）：${NC}"
                        echo ""
                        i=1
                        ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -20 | while read backup; do
                            timestamp=$(basename "$backup")
                            size=$(du -sh "$backup" 2>/dev/null | awk '{print $1}')
                            echo -e "${CYAN}[$i]${NC} $timestamp (大小: $size)"
                            if [ -f "$backup/backup_info.txt" ]; then
                                cat "$backup/backup_info.txt" | grep -v "备份时间" | sed 's/^/    /'
                            fi
                            echo ""
                            i=$((i+1))
                        done
                        
                        echo -e "${YELLOW}输入要删除的备份编号（多个用空格分隔，如: 1 3 5）${NC}"
                        read -p "$(echo -e ${YELLOW}编号: ${NC})" DELETE_NUMS
                        
                        if [ -n "$DELETE_NUMS" ]; then
                            BACKUP_ARRAY=($(ls -dt "$BACKUP_BASE_DIR"/* 2>/dev/null | head -20))
                            for num in $DELETE_NUMS; do
                                if [[ $num =~ ^[0-9]+$ ]] && [ $num -ge 1 ] && [ $num -le ${#BACKUP_ARRAY[@]} ]; then
                                    idx=$((num-1))
                                    backup="${BACKUP_ARRAY[$idx]}"
                                    rm -rf "$backup"
                                    echo -e "${GREEN}已删除: $(basename "$backup")${NC}"
                                fi
                            done
                        fi
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
    9)
        echo -e "${YELLOW}退出程序${NC}"
        exit 0
        ;;
esac

echo -e "${BLUE}请输入转发配置信息：${NC}"
echo ""

# 获取目标IP
while true; do
    read -p "$(echo -e "${YELLOW}目标服务器IP/域名: ${NC}")" TARGET_IP
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}请输入目标服务器IP或域名${NC}"
        continue
    fi
    
    # 检查是否为有效的IP地址
    if [[ $TARGET_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
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
            echo -e "${GREEN}✅ 有效的IP地址: $TARGET_IP${NC}"
            break
        else
            echo -e "${RED}❌ IP地址格式错误，每段应在0-255范围内${NC}"
        fi
    # 检查是否为有效的域名
    elif [[ $TARGET_IP =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo -e "${GREEN}✅ 有效的域名: $TARGET_IP${NC}"
        # 尝试解析域名
        if command -v nslookup >/dev/null 2>&1; then
            echo -e "${YELLOW}正在解析域名...${NC}"
            RESOLVED_IP=$(nslookup "$TARGET_IP" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | head -1 | awk '{print $2}' || echo "")
            if [ -n "$RESOLVED_IP" ]; then
                echo -e "${GREEN}✅ 域名解析成功: $TARGET_IP -> $RESOLVED_IP${NC}"
            else
                echo -e "${YELLOW}⚠️  域名解析失败，但将继续使用域名${NC}"
            fi
        fi
        break
    else
        echo -e "${RED}❌ 请输入有效的IP地址或域名${NC}"
        echo -e "${YELLOW}IP地址示例: 192.168.1.100${NC}"
        echo -e "${YELLOW}域名示例: example.com${NC}"
    fi
done

# 获取目标端口
while true; do
    read -p "$(echo -e "${YELLOW}目标端口 [3389]: ${NC}")" TARGET_PORT
    TARGET_PORT=${TARGET_PORT:-3389}
    if [[ $TARGET_PORT =~ ^[0-9]+$ ]] && [ $TARGET_PORT -ge 1 ] && [ $TARGET_PORT -le 65535 ]; then
        break
    else
        echo -e "${RED}请输入有效的端口号 (1-65535)${NC}"
    fi
done

# 获取本地监听端口
while true; do
    read -p "$(echo -e ${YELLOW}本地监听端口 [$TARGET_PORT]: ${NC})" LOCAL_PORT
    LOCAL_PORT=${LOCAL_PORT:-$TARGET_PORT}
    if [[ $LOCAL_PORT =~ ^[0-9]+$ ]] && [ $LOCAL_PORT -ge 1 ] && [ $LOCAL_PORT -le 65535 ]; then
        break
    else
        echo -e "${RED}请输入有效的端口号 (1-65535)${NC}"
    fi
done

# 选择转发方案
echo ""
echo -e "${CYAN}${BOLD}========== 转发方案对比 ==========${NC}"
echo ""
echo -e "${YELLOW}方案选择：${NC}"
echo -e "1) ${GREEN}iptables DNAT${NC}   - 延迟: 低      | 适用: ${BOLD}游戏/RDP/VNC${NC}"
echo -e "2) ${BLUE}HAProxy${NC}         - 延迟: 较低    | 适用: ${BOLD}Web服务/负载均衡${NC}"
echo -e "3) ${CYAN}socat${NC}           - 延迟: 较低    | 适用: ${BOLD}通用TCP转发${NC}"
echo -e "4) ${YELLOW}gost${NC}            - 延迟: 中等    | 适用: ${BOLD}加密代理/多协议${NC}"
echo -e "5) ${MAGENTA}realm${NC}           - 延迟: 较低    | 适用: ${BOLD}高并发场景${NC}"
echo -e "6) ${BLUE}rinetd${NC}          - 延迟: 较低    | 适用: ${BOLD}多端口转发${NC}"
echo -e "7) ${CYAN}nginx stream${NC}    - 延迟: 较低    | 适用: ${BOLD}Web场景/SSL${NC}"
echo ""
echo -e "${CYAN}性能: ${GREEN}iptables${NC} > ${MAGENTA}realm${NC} > ${BLUE}HAProxy/nginx${NC} > ${CYAN}socat/rinetd${NC} > ${YELLOW}gost${NC}"
echo -e "${CYAN}功能: ${YELLOW}gost${NC} > ${BLUE}nginx/HAProxy${NC} > ${MAGENTA}realm${NC} > ${CYAN}socat/rinetd${NC} > ${GREEN}iptables${NC}"
echo ""

while true; do
    read -p "$(echo -e ${YELLOW}请选择方案 [1]: ${NC})" FORWARD_METHOD
    FORWARD_METHOD=${FORWARD_METHOD:-1}
    if [[ $FORWARD_METHOD =~ ^[1-7]$ ]]; then
        break
    else
        echo -e "${RED}请输入 1-7 之间的数字${NC}"
    fi
done

echo ""
echo -e "${CYAN}配置确认：${NC}"
echo -e "目标服务器: ${BOLD}$TARGET_IP:$TARGET_PORT${NC}"
echo -e "本地监听: ${BOLD}0.0.0.0:$LOCAL_PORT${NC}"
case $FORWARD_METHOD in
    1) echo -e "转发方案: ${BOLD}iptables DNAT (内核级转发)${NC}" ;;
    2) echo -e "转发方案: ${BOLD}HAProxy (负载均衡)${NC}" ;;
    3) echo -e "转发方案: ${BOLD}socat (轻量级转发)${NC}" ;;
    4) echo -e "转发方案: ${BOLD}gost (代理转发)${NC}" ;;
    5) echo -e "转发方案: ${BOLD}realm (高性能转发)${NC}" ;;
    6) echo -e "转发方案: ${BOLD}rinetd (多端口转发)${NC}" ;;
    7) echo -e "转发方案: ${BOLD}nginx stream (流式转发)${NC}" ;;
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

# 创建备份说明文件
cat > "$BACKUP_DIR/backup_info.txt" << EOF
备份时间: $(date)
转发方案: 方案$FORWARD_METHOD
目标地址: $TARGET_IP:$TARGET_PORT
本地端口: $LOCAL_PORT
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

echo -e "${BLUE}[步骤2/4] 清理现有服务...${NC}"
# 停止可能冲突的服务
systemctl stop haproxy 2>/dev/null || true
systemctl stop mumbai-forward 2>/dev/null || true
systemctl stop port-forward 2>/dev/null || true
systemctl stop gost-forward 2>/dev/null || true
systemctl stop realm-forward 2>/dev/null || true
pkill -f "socat.*$LOCAL_PORT" 2>/dev/null || true
pkill -f "gost.*$LOCAL_PORT" 2>/dev/null || true
pkill -f "realm.*$LOCAL_PORT" 2>/dev/null || true

# 清理现有iptables规则（使用正确的命令）
IPTABLES_CMD=$(get_iptables_cmd)
$IPTABLES_CMD -t nat -D PREROUTING -p tcp --dport $LOCAL_PORT -j DNAT --to-destination $TARGET_IP:$TARGET_PORT 2>/dev/null || true
$IPTABLES_CMD -t nat -D POSTROUTING -p tcp -d $TARGET_IP --dport $TARGET_PORT -j MASQUERADE 2>/dev/null || true
# 清理OUTPUT链的旧规则
LOCAL_IP=$(hostname -I | awk '{print $1}')
$IPTABLES_CMD -t nat -D OUTPUT -p tcp --dport $LOCAL_PORT -d $LOCAL_IP -j DNAT --to-destination $TARGET_IP:$TARGET_PORT 2>/dev/null || true
$IPTABLES_CMD -t nat -D OUTPUT -p tcp --dport $LOCAL_PORT -d 127.0.0.1 -j DNAT --to-destination $TARGET_IP:$TARGET_PORT 2>/dev/null || true
$IPTABLES_CMD -t nat -D POSTROUTING -p tcp -d $TARGET_IP --dport $TARGET_PORT -s $LOCAL_IP -j MASQUERADE 2>/dev/null || true

echo -e "${BLUE}[步骤3/4] 部署转发服务...${NC}"

case $FORWARD_METHOD in
    1)
        # iptables DNAT - 极致性能方案
        echo -e "${YELLOW}配置iptables DNAT转发...${NC}"
        
        # 获取正确的 iptables 命令
        IPTABLES_CMD=$(get_iptables_cmd)
        echo -e "${YELLOW}使用命令: $IPTABLES_CMD${NC}"
        
        # 启用IP转发
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        
        # 添加DNAT规则
        $IPTABLES_CMD -t nat -A PREROUTING -p tcp --dport $LOCAL_PORT -j DNAT --to-destination $TARGET_IP:$TARGET_PORT
        $IPTABLES_CMD -t nat -A POSTROUTING -p tcp -d $TARGET_IP --dport $TARGET_PORT -j MASQUERADE
        
        # 修复本地回环访问问题（关键修复）
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        $IPTABLES_CMD -t nat -A OUTPUT -p tcp --dport $LOCAL_PORT -d $LOCAL_IP -j DNAT --to-destination $TARGET_IP:$TARGET_PORT
        $IPTABLES_CMD -t nat -A OUTPUT -p tcp --dport $LOCAL_PORT -d 127.0.0.1 -j DNAT --to-destination $TARGET_IP:$TARGET_PORT
        $IPTABLES_CMD -t nat -A POSTROUTING -p tcp -d $TARGET_IP --dport $TARGET_PORT -s $LOCAL_IP -j MASQUERADE
        
        # 关闭反向路径过滤，解决回环问题
        echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
        echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null || true
        
        # 优化连接跟踪
        $IPTABLES_CMD -A FORWARD -p tcp -d $TARGET_IP --dport $TARGET_PORT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        $IPTABLES_CMD -A FORWARD -p tcp -s $TARGET_IP --sport $TARGET_PORT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # 保存规则 - 兼容不同系统
        if command -v iptables-save >/dev/null 2>&1; then
            # Debian/Ubuntu系统
            if [ -d /etc/iptables ]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            elif [ ! -d /etc/iptables ] && [ -f /etc/debian_version ]; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
            
            # CentOS/RHEL系统
            if [ -d /etc/sysconfig ]; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
            
            # 通用备份位置
            iptables-save > "$BACKUP_DIR/iptables_current.txt" 2>/dev/null || true
        fi
        
        echo -e "${GREEN}iptables DNAT配置完成${NC}"
        ;;
        
    2)
        # HAProxy优化版
        echo -e "${YELLOW}配置HAProxy优化转发...${NC}"
        
        # 询问是否启用Web管理界面
        echo ""
        read -p "$(echo -e ${YELLOW}是否启用Web统计页面? [y/N]: ${NC})" ENABLE_WEB
        ENABLE_WEB=${ENABLE_WEB:-N}
        
        # 只有启用Web界面时才生成随机密码
        if [[ $ENABLE_WEB =~ ^[Yy]$ ]]; then
            HAPROXY_PASSWORD=$(generate_password 16)
        fi
        
        # 检查并安装HAProxy
        if ! command -v haproxy >/dev/null 2>&1; then
            if [ -f /etc/debian_version ]; then
                apt-get update -qq && apt-get install -y --no-install-recommends haproxy
            elif [ -f /etc/redhat-release ]; then
                yum install -y haproxy
            fi
        fi
        
        # 创建HAProxy配置
        cat > /etc/haproxy/haproxy.cfg << EOF
global
    daemon
    maxconn 65535
    # 性能优化
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
    
    # TCP优化
    option clitcpka
    option srvtcpka

# 高性能转发
frontend port_frontend
    bind *:$LOCAL_PORT
    mode tcp
    default_backend port_backend

backend port_backend
    mode tcp
    balance first
    option tcp-check
    tcp-check connect port $TARGET_PORT
    
    server target_server $TARGET_IP:$TARGET_PORT check inter 30s rise 1 fall 1 weight 100 maxconn 32768
EOF

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
        systemctl restart haproxy
        
        # 获取本机IP
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        
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
        
    3)
        # socat轻量版
        echo -e "${YELLOW}配置socat轻量转发...${NC}"
        
        # 检查并安装socat
        if ! command -v socat >/dev/null 2>&1; then
            if [ -f /etc/debian_version ]; then
                apt-get update -qq && apt-get install -y --no-install-recommends socat
            elif [ -f /etc/redhat-release ]; then
                yum install -y socat
            fi
        fi
        
        # 创建systemd服务
        cat > /etc/systemd/system/port-forward.service << EOF
[Unit]
Description=Port Forward Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/socat TCP-LISTEN:$LOCAL_PORT,fork,reuseaddr,nodelay,keepalive TCP:$TARGET_IP:$TARGET_PORT
Restart=always
RestartSec=3
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable port-forward
        systemctl start port-forward
        echo -e "${GREEN}socat轻量配置完成${NC}"
        ;;
        
    4)
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
            echo -e "${YELLOW}安装gost最新版本...${NC}"
            
            # 使用官方安装脚本
            INSTALL_SUCCESS=false
            
            # 方法1: 使用curl安装
            if command -v curl >/dev/null 2>&1; then
                echo -e "${YELLOW}使用官方安装脚本 (curl)...${NC}"
                if bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install 2>/dev/null; then
                    INSTALL_SUCCESS=true
                    echo -e "${GREEN}✅ gost安装成功${NC}"
                fi
            fi
            
            # 方法2: 如果curl失败，尝试wget
            if [ "$INSTALL_SUCCESS" = false ] && command -v wget >/dev/null 2>&1; then
                echo -e "${YELLOW}使用官方安装脚本 (wget)...${NC}"
                if bash <(wget -qO- https://github.com/go-gost/gost/raw/master/install.sh) --install 2>/dev/null; then
                    INSTALL_SUCCESS=true
                    echo -e "${GREEN}✅ gost安装成功${NC}"
                fi
            fi
            
            # 方法3: 如果官方脚本失败，尝试包管理器
            if [ "$INSTALL_SUCCESS" = false ]; then
                echo -e "${YELLOW}官方脚本安装失败，尝试包管理器...${NC}"
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
            
            # 如果所有方法都失败
            if [ "$INSTALL_SUCCESS" = false ]; then
                echo -e "${RED}❌ gost自动安装失败${NC}"
                echo -e "${YELLOW}手动安装方法：${NC}"
                echo -e "1. 运行: bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install"
                echo -e "2. 或访问: https://github.com/go-gost/gost/releases"
                echo -e "3. 下载适合您系统的版本并解压到 /usr/local/bin/gost"
                exit 1
            fi
            
            # 验证安装
            if [ -f /usr/local/bin/gost ] && [ -x /usr/local/bin/gost ]; then
                GOST_INSTALLED_VERSION=$(/usr/local/bin/gost -V 2>/dev/null | head -1 || echo "unknown")
                echo -e "${GREEN}gost安装完成: $GOST_INSTALLED_VERSION${NC}"
                echo -e "${GREEN}安装路径: /usr/local/bin/gost${NC}"
                
                # 清理所有临时文件和目录
                echo -e "${YELLOW}清理临时文件...${NC}"
                rm -f ~/gost.tar.gz ~/gost*.tar.gz 2>/dev/null
                rm -f /tmp/gost.tar.gz /tmp/gost*.tar.gz 2>/dev/null
                rm -rf /tmp/gost_extract 2>/dev/null
                rm -f gost.tar.gz gost*.tar.gz 2>/dev/null
                echo -e "${GREEN}临时文件已清理${NC}"
            else
                echo -e "${RED}gost安装失败 - 文件不存在或不可执行${NC}"
                echo -e "${YELLOW}检查文件状态:${NC}"
                ls -la /usr/local/bin/gost 2>/dev/null || echo "文件不存在"
                # 清理失败的临时文件
                rm -f ~/gost.tar.gz ~/gost*.tar.gz /tmp/gost.tar.gz /tmp/gost*.tar.gz gost.tar.gz gost*.tar.gz 2>/dev/null
                rm -rf /tmp/gost_extract 2>/dev/null
                exit 1
            fi
        else
            # 验证现有安装
            if [ -f /usr/local/bin/gost ] && [ -x /usr/local/bin/gost ]; then
                GOST_EXISTING_VERSION=$(/usr/local/bin/gost -V 2>/dev/null | head -1 || echo "unknown")
                echo -e "${GREEN}gost已安装: $GOST_EXISTING_VERSION${NC}"
            else
                echo -e "${RED}gost文件存在但不可执行，重新安装...${NC}"
                rm -f /usr/local/bin/gost
                # 递归调用安装逻辑
                exec $0
            fi
        fi
        
        # 创建systemd服务（gost v3.x使用配置文件方式）
        if [[ $ENABLE_API =~ ^[Yy]$ ]]; then
            # 启用API - 创建配置文件
            mkdir -p /etc/gost
            cat > /etc/gost/config.yaml << EOF
services:
- name: service-0
  addr: :$LOCAL_PORT
  handler:
    type: tcp
  listener:
    type: tcp
  forwarder:
    nodes:
    - name: target-0
      addr: $TARGET_IP:$TARGET_PORT

api:
  addr: :9999
  pathPrefix: /api
  accesslog: true
  auth:
    username: $GOST_API_USER
    password: $GOST_API_PASSWORD
EOF
            
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
        else
            # 不启用API - 使用简单命令行
            cat > /etc/systemd/system/gost-forward.service << EOF
[Unit]
Description=Gost Port Forward
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/gost -L tcp://:$LOCAL_PORT/$TARGET_IP:$TARGET_PORT
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
        fi
        
        # 先测试gost命令是否能正常启动
        echo -e "${YELLOW}测试gost命令...${NC}"
        if [[ $ENABLE_API =~ ^[Yy]$ ]]; then
            # 测试配置文件方式
            timeout 3 /usr/local/bin/gost -C /etc/gost/config.yaml &
        else
            # 测试命令行方式
            timeout 3 /usr/local/bin/gost -L tcp://:$LOCAL_PORT/$TARGET_IP:$TARGET_PORT &
        fi
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
        systemctl start gost-forward
        
        # 获取本机IP
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        
        echo -e "${GREEN}gost代理配置完成${NC}"
        
        # 如果启用了API，显示凭据信息
        if [[ $ENABLE_API =~ ^[Yy]$ ]]; then
            # 保存密码到文件
            echo "Gost Web API" > /root/gost_credentials.txt
            echo "API地址: http://$LOCAL_IP:9999" >> /root/gost_credentials.txt
            echo "用户名: $GOST_API_USER" >> /root/gost_credentials.txt
            echo "密码: $GOST_API_PASSWORD" >> /root/gost_credentials.txt
            echo "配置时间: $(date)" >> /root/gost_credentials.txt
            echo "" >> /root/gost_credentials.txt
            echo "API使用示例:" >> /root/gost_credentials.txt
            echo "curl -u $GOST_API_USER:$GOST_API_PASSWORD http://$LOCAL_IP:9999/config" >> /root/gost_credentials.txt
            chmod 600 /root/gost_credentials.txt
            
            echo ""
            echo -e "${CYAN}${BOLD}========== Web API ==========${NC}"
            echo -e "${CYAN}API地址: ${BOLD}http://$LOCAL_IP:9999${NC}"
            echo -e "${CYAN}用户名: ${BOLD}$GOST_API_USER${NC}"
            echo -e "${CYAN}密码: ${BOLD}$GOST_API_PASSWORD${NC}"
            echo -e "${YELLOW}密码已保存到: /root/gost_credentials.txt${NC}"
            echo -e "${CYAN}API文档: https://github.com/go-gost/gost${NC}"
            echo -e "${CYAN}====================================${NC}"
            echo ""
        else
            echo -e "${YELLOW}Web API未启用${NC}"
        fi
        ;;
        
    5)
        # realm转发
        echo -e "${YELLOW}配置realm转发...${NC}"
        
        # 检查并安装realm
        if ! command -v realm >/dev/null 2>&1; then
            echo -e "${YELLOW}安装realm...${NC}"
            
            # 确定系统架构
            ARCH=$(uname -m)
            case $ARCH in
                x86_64) REALM_ARCH="x86_64" ;;
                aarch64) REALM_ARCH="aarch64" ;;
                *) REALM_ARCH="x86_64" ;;
            esac
            
            # 尝试获取最新版本号
            echo -e "${YELLOW}正在获取realm最新版本...${NC}"
            REALM_VERSION=""
            
            if command -v curl >/dev/null 2>&1; then
                REALM_VERSION=$(curl -s --connect-timeout 10 https://api.github.com/repos/zhboner/realm/releases/latest | grep '"tag_name"' | cut -d '"' -f 4 2>/dev/null)
            fi
            
            if [ -z "$REALM_VERSION" ] && command -v wget >/dev/null 2>&1; then
                REALM_VERSION=$(wget -qO- --timeout=10 https://api.github.com/repos/zhboner/realm/releases/latest | grep '"tag_name"' | cut -d '"' -f 4 2>/dev/null)
            fi
            
            # 如果无法获取版本号，使用固定版本
            if [ -z "$REALM_VERSION" ]; then
                echo -e "${YELLOW}无法获取最新版本，使用固定版本 v2.9.2${NC}"
                REALM_VERSION="v2.9.2"
            else
                echo -e "${GREEN}找到最新版本: $REALM_VERSION${NC}"
            fi
            
            # 尝试下载realm
            DOWNLOAD_SUCCESS=false
            DOWNLOAD_URL="https://github.com/zhboner/realm/releases/download/${REALM_VERSION}/realm-${REALM_ARCH}-unknown-linux-gnu.tar.gz"
            
            echo -e "${YELLOW}正在下载realm...${NC}"
            
            # 尝试使用wget下载
            if command -v wget >/dev/null 2>&1; then
                if wget --timeout=30 -q -O /tmp/realm.tar.gz "$DOWNLOAD_URL"; then
                    DOWNLOAD_SUCCESS=true
                    echo -e "${GREEN}wget下载成功${NC}"
                fi
            fi
            
            # 如果wget失败，尝试curl
            if [ "$DOWNLOAD_SUCCESS" = false ] && command -v curl >/dev/null 2>&1; then
                if curl -L --connect-timeout 30 -s -o /tmp/realm.tar.gz "$DOWNLOAD_URL"; then
                    DOWNLOAD_SUCCESS=true
                    echo -e "${GREEN}curl下载成功${NC}"
                fi
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
                echo -e "2. 下载适合您系统的版本"
                echo -e "3. 解压并复制到 /usr/local/bin/realm"
                exit 1
            fi
            
            # 清理临时文件
            rm -f /tmp/realm.tar.gz /tmp/realm
            
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
        
        # 创建realm配置文件
        mkdir -p /etc/realm
        cat > /etc/realm/config.toml << EOF
[network]
use_udp = false
zero_copy = true

[[endpoints]]
listen = "0.0.0.0:$LOCAL_PORT"
remote = "$TARGET_IP:$TARGET_PORT"
EOF
        
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
        systemctl start realm-forward
        echo -e "${GREEN}realm转发配置完成${NC}"
        ;;
        
    6)
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
        
        # 创建rinetd配置文件
        cat > /etc/rinetd.conf << EOF
# rinetd配置文件 - 由端口转发脚本生成
# 格式: bindaddress bindport connectaddress connectport
0.0.0.0 $LOCAL_PORT $TARGET_IP $TARGET_PORT

# 日志文件
logfile /var/log/rinetd.log
EOF
        
        # 创建systemd服务
        cat > /etc/systemd/system/rinetd.service << EOF
[Unit]
Description=Rinetd Port Forwarding
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/rinetd -f -c /etc/rinetd.conf
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable rinetd
        systemctl start rinetd
        echo -e "${GREEN}rinetd配置完成${NC}"
        ;;
        
    7)
        # nginx stream转发
        echo -e "${YELLOW}配置nginx stream转发...${NC}"
        
        # 检查并安装nginx
        if ! command -v nginx >/dev/null 2>&1; then
            echo -e "${YELLOW}安装nginx...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update -qq && apt-get install -y --no-install-recommends nginx
            elif [ -f /etc/redhat-release ]; then
                yum install -y nginx
            fi
        fi
        
        # 停止nginx服务
        systemctl stop nginx 2>/dev/null || true
        
        # 清理可能存在的错误配置
        echo -e "${YELLOW}清理nginx配置...${NC}"
        # 备份当前nginx配置
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%s) 2>/dev/null || true
        
        # 检查nginx.conf是否损坏，如果损坏则恢复默认配置
        if ! nginx -t 2>/dev/null; then
            echo -e "${YELLOW}检测到nginx配置损坏，尝试修复...${NC}"
            
            # 尝试从备份恢复
            if [ -f /etc/nginx/nginx.conf.bak.* ]; then
                LATEST_BACKUP=$(ls -t /etc/nginx/nginx.conf.bak.* 2>/dev/null | head -1)
                if [ -n "$LATEST_BACKUP" ]; then
                    cp "$LATEST_BACKUP" /etc/nginx/nginx.conf
                    echo -e "${YELLOW}已从备份恢复: $LATEST_BACKUP${NC}"
                fi
            fi
            
            # 如果还是失败，使用系统默认配置
            if ! nginx -t 2>/dev/null; then
                if [ -f /etc/debian_version ]; then
                    # Debian/Ubuntu系统
                    apt-get install --reinstall -y nginx-common 2>/dev/null || true
                elif [ -f /etc/redhat-release ]; then
                    # CentOS/RHEL系统
                    yum reinstall -y nginx 2>/dev/null || true
                fi
                echo -e "${YELLOW}已重新安装nginx默认配置${NC}"
            fi
        fi
        
        # 删除所有可能错误添加的location指令（包括各种缩进格式）
        sed -i '/^location \/nginx-status/,/^}/d' /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '/^[[:space:]]*location \/nginx-status/,/^[[:space:]]*}/d' /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '/^    # 状态页面/d' /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '/^# 状态页面/d' /etc/nginx/nginx.conf 2>/dev/null || true
        
        # 删除可能在文件开头的location指令
        sed -i '1,10{/location/d}' /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '1,10{/stub_status/d}' /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '1,10{/access_log off/d}' /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '1,10{/allow all/d}' /etc/nginx/nginx.conf 2>/dev/null || true
        
        # 创建stream配置目录
        mkdir -p /etc/nginx/stream.d
        
        # 清理旧的stream配置文件
        rm -f /etc/nginx/stream.d/port-forward.conf 2>/dev/null || true
        
        # 检查nginx主配置是否包含stream块
        if ! grep -q "stream {" /etc/nginx/nginx.conf; then
            # 在http块之前添加stream块
            sed -i '/^http {/i\
stream {\
    include /etc/nginx/stream.d/*.conf;\
}\
' /etc/nginx/nginx.conf
        fi
        
        # 创建stream转发配置
        cat > /etc/nginx/stream.d/port-forward.conf << EOF
# Nginx Stream 端口转发配置
upstream backend_$LOCAL_PORT {
    server $TARGET_IP:$TARGET_PORT max_fails=3 fail_timeout=30s;
}

server {
    listen $LOCAL_PORT;
    proxy_pass backend_$LOCAL_PORT;
    
    # 性能优化
    proxy_connect_timeout 1s;
    proxy_timeout 3600s;
    proxy_buffer_size 16k;
    
    # TCP优化 (兼容nginx 1.18)
    tcp_nodelay on;
}
EOF
        
        # 配置nginx状态页面（在http块中）
        NGINX_STATUS_PORT=8080
        
        # 检查是否存在sites-enabled目录（Debian/Ubuntu）
        if [ -d /etc/nginx/sites-available ]; then
            # 创建独立的状态页面配置文件
            cat > /etc/nginx/sites-available/status << EOF
server {
    listen $NGINX_STATUS_PORT;
    server_name _;
    
    location /nginx-status {
        stub_status on;
        access_log off;
        allow all;
    }
}
EOF
            # 启用配置
            mkdir -p /etc/nginx/sites-enabled
            ln -sf /etc/nginx/sites-available/status /etc/nginx/sites-enabled/status 2>/dev/null || true
            
            # 确保nginx.conf包含sites-enabled
            if ! grep -q "include /etc/nginx/sites-enabled/\*" /etc/nginx/nginx.conf; then
                sed -i '/http {/a\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
            fi
        else
            # CentOS/RHEL - 直接在conf.d目录创建
            cat > /etc/nginx/conf.d/status.conf << EOF
server {
    listen $NGINX_STATUS_PORT;
    server_name _;
    
    location /nginx-status {
        stub_status on;
        access_log off;
        allow all;
    }
}
EOF
        fi
        
        # 测试nginx配置
        if nginx -t 2>/dev/null; then
            systemctl enable nginx
            systemctl restart nginx
            
            # 获取本机IP
            LOCAL_IP=$(hostname -I | awk '{print $1}')
            
            echo -e "${GREEN}nginx stream配置完成${NC}"
            echo -e "${CYAN}状态页面: ${BOLD}http://$LOCAL_IP:$NGINX_STATUS_PORT/nginx-status${NC}"
        else
            echo -e "${RED}nginx配置测试失败${NC}"
            nginx -t
        fi
        ;;
esac

echo -e "${BLUE}[步骤4/4] 验证服务状态...${NC}"

# 等待服务启动
sleep 3

# 检查服务状态
echo -e "${YELLOW}检查转发服务状态...${NC}"
case $FORWARD_METHOD in
    1)
        # iptables DNAT - 检查规则是否存在
        if iptables -t nat -C PREROUTING -p tcp --dport $LOCAL_PORT -j DNAT --to-destination $TARGET_IP:$TARGET_PORT 2>/dev/null; then
            echo -e "${GREEN}✅ iptables DNAT规则已生效${NC}"
        else
            echo -e "${RED}❌ iptables DNAT规则配置失败${NC}"
        fi
        
        # 检查IP转发是否启用
        if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
            echo -e "${GREEN}✅ IP转发已启用${NC}"
        else
            echo -e "${RED}❌ IP转发未启用${NC}"
        fi
        ;;
    2)
        # HAProxy - 检查服务状态
        if systemctl is-active haproxy >/dev/null 2>&1; then
            echo -e "${GREEN}✅ HAProxy服务运行正常${NC}"
        else
            echo -e "${RED}❌ HAProxy服务异常${NC}"
        fi
        ;;
    3)
        # socat - 检查服务状态
        if systemctl is-active port-forward >/dev/null 2>&1; then
            echo -e "${GREEN}✅ socat服务运行正常${NC}"
        else
            echo -e "${RED}❌ socat服务异常${NC}"
        fi
        ;;
    4)
        # gost - 检查服务状态
        if systemctl is-active gost-forward >/dev/null 2>&1; then
            echo -e "${GREEN}✅ gost服务运行正常${NC}"
        else
            echo -e "${RED}❌ gost服务异常${NC}"
        fi
        ;;
    5)
        # realm - 检查服务状态
        if systemctl is-active realm-forward >/dev/null 2>&1; then
            echo -e "${GREEN}✅ realm服务运行正常${NC}"
        else
            echo -e "${RED}❌ realm服务异常${NC}"
        fi
        ;;
    6)
        # rinetd - 检查服务状态
        if systemctl is-active rinetd >/dev/null 2>&1; then
            echo -e "${GREEN}✅ rinetd服务运行正常${NC}"
        else
            echo -e "${RED}❌ rinetd服务异常${NC}"
        fi
        ;;
    7)
        # nginx - 检查服务状态
        if systemctl is-active nginx >/dev/null 2>&1; then
            echo -e "${GREEN}✅ nginx服务运行正常${NC}"
        else
            echo -e "${RED}❌ nginx服务异常${NC}"
        fi
        ;;
esac

# 对于用户态服务，检查端口监听
if [[ $FORWARD_METHOD =~ ^[2-7]$ ]]; then
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp | grep ":$LOCAL_PORT " >/dev/null; then
            echo -e "${GREEN}✅ 端口 $LOCAL_PORT 监听正常${NC}"
        else
            echo -e "${RED}❌ 端口 $LOCAL_PORT 监听异常${NC}"
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tlnp | grep ":$LOCAL_PORT " >/dev/null; then
            echo -e "${GREEN}✅ 端口 $LOCAL_PORT 监听正常${NC}"
        else
            echo -e "${RED}❌ 端口 $LOCAL_PORT 监听异常${NC}"
        fi
    fi
fi

# 测试连接
echo -e "${YELLOW}测试目标服务器连接...${NC}"
if timeout 3 bash -c "echo >/dev/tcp/$TARGET_IP/$TARGET_PORT" 2>/dev/null; then
    echo -e "${GREEN}✅ 到目标服务器连接正常${NC}"
    
    # 测试延迟
    if command -v ping >/dev/null 2>&1; then
        PING_RESULT=$(ping -c 3 -W 2 $TARGET_IP 2>/dev/null | tail -1 | awk '{print $4}' | cut -d'/' -f2 2>/dev/null)
        if [ -n "$PING_RESULT" ]; then
            echo -e "${GREEN}网络延迟: ${PING_RESULT}ms${NC}"
        fi
    fi
    
    # 对于iptables DNAT，测试转发是否工作
    if [ "$FORWARD_METHOD" = "1" ]; then
        echo -e "${YELLOW}测试DNAT转发...${NC}"
        # 获取本机IP
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        if [ -n "$LOCAL_IP" ]; then
            # 测试通过本机转发是否正常
            if timeout 3 bash -c "echo >/dev/tcp/$LOCAL_IP/$LOCAL_PORT" 2>/dev/null; then
                echo -e "${GREEN}✅ DNAT转发测试成功${NC}"
            else
                echo -e "${YELLOW}⚠️ DNAT转发测试失败，可能需要调整防火墙规则${NC}"
            fi
        fi
    fi
else
    echo -e "${RED}❌ 到目标服务器连接异常${NC}"
fi

echo ""
echo -e "${CYAN}${BOLD}=========================================="
echo -e "           部署完成！"
echo -e "==========================================${NC}"

echo ""
echo -e "${GREEN}🚀 端口转发服务已启动！${NC}"
echo ""
echo -e "${YELLOW}连接信息：${NC}"
echo -e "本地地址: ${BOLD}$(hostname -I | awk '{print $1}'):$LOCAL_PORT${NC}"
echo -e "目标地址: ${BOLD}$TARGET_IP:$TARGET_PORT${NC}"
case $FORWARD_METHOD in
    1) echo -e "转发方式: ${BOLD}iptables DNAT (内核级，延迟 ~0.01ms)${NC}" ;;
    2) echo -e "转发方式: ${BOLD}HAProxy优化版 (用户态，延迟 ~0.1ms)${NC}" ;;
    3) echo -e "转发方式: ${BOLD}socat轻量版 (用户态，延迟 ~0.2ms)${NC}" ;;
    4) echo -e "转发方式: ${BOLD}gost代理 (用户态，延迟 ~1-3ms)${NC}" ;;
    5) echo -e "转发方式: ${BOLD}realm转发 (用户态，延迟 ~0.1-0.5ms)${NC}" ;;
    6) echo -e "转发方式: ${BOLD}rinetd (用户态，延迟 ~0.2ms)${NC}" ;;
    7) echo -e "转发方式: ${BOLD}nginx stream (用户态，延迟 ~0.1ms)${NC}" ;;
esac

echo ""
echo -e "${YELLOW}性能优化特性：${NC}"
echo -e "✅ BBR拥塞控制算法"
echo -e "✅ TCP Fast Open"
echo -e "✅ 256MB缓冲区优化"
echo -e "✅ 早期重传机制"
echo -e "✅ 瘦流优化"
echo -e "✅ 禁用延迟ACK"
echo -e "✅ 连接跟踪优化"

echo ""
echo -e "${YELLOW}管理命令：${NC}"
case $FORWARD_METHOD in
    1) 
        echo -e "查看NAT规则: iptables -t nat -L -n -v"
        echo -e "查看OUTPUT规则: iptables -t nat -L OUTPUT -n -v"
        echo -e "查看FORWARD规则: iptables -L FORWARD -n -v"
        echo -e "检查连接跟踪: cat /proc/net/nf_conntrack | grep $TARGET_IP"
        echo -e "检查IP转发: cat /proc/sys/net/ipv4/ip_forward"
        echo -e "检查反向过滤: cat /proc/sys/net/ipv4/conf/all/rp_filter"
        echo -e "测试外部访问: telnet $(hostname -I | awk '{print $1}') $LOCAL_PORT"
        echo -e "测试本地访问: telnet 127.0.0.1 $LOCAL_PORT"
        echo -e "删除转发规则: iptables -t nat -F"
        ;;
    2) 
        echo -e "服务状态: systemctl status haproxy"
        echo -e "重启服务: systemctl restart haproxy"
        echo -e "查看日志: journalctl -u haproxy -f"
        echo -e "查看配置: cat /etc/haproxy/haproxy.cfg"
        echo -e "Web凭据: cat /root/haproxy_credentials.txt"
        if [ -f /root/haproxy_credentials.txt ]; then
            echo -e "统计页面: http://$(hostname -I | awk '{print $1}'):8888/haproxy-stats"
        fi
        ;;
    3) 
        echo -e "服务状态: systemctl status port-forward"
        echo -e "重启服务: systemctl restart port-forward"
        echo -e "查看日志: journalctl -u port-forward -f"
        ;;
    4)
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
        echo -e "API凭据: cat /root/gost_credentials.txt"
        if [ -f /root/gost_credentials.txt ]; then
            echo -e "Web API: http://$(hostname -I | awk '{print $1}'):9999/api"
        fi
        ;;
    5)
        echo -e "服务状态: systemctl status realm-forward"
        echo -e "重启服务: systemctl restart realm-forward"
        echo -e "查看日志: journalctl -u realm-forward -f"
        echo -e "查看配置: cat /etc/realm/config.toml"
        echo -e "测试realm: realm -c /etc/realm/config.toml"
        ;;
    6)
        echo -e "服务状态: systemctl status rinetd"
        echo -e "重启服务: systemctl restart rinetd"
        echo -e "查看日志: journalctl -u rinetd -f"
        echo -e "查看配置: cat /etc/rinetd.conf"
        echo -e "查看转发日志: tail -f /var/log/rinetd.log"
        ;;
    7)
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
        echo -e "查看配置: cat /etc/nginx/stream.d/port-forward.conf"
        echo -e "测试配置: nginx -t"
        echo -e "重载配置: nginx -s reload"
        echo -e "状态页面: http://$(hostname -I | awk '{print $1}'):$NGINX_STATUS_PORT/nginx-status"
        ;;
esac

echo -e "测试连接: telnet $(hostname -I | awk '{print $1}') $LOCAL_PORT"
echo -e "配置备份: $BACKUP_DIR"

echo ""
echo -e "${CYAN}${BOLD}🎯 端口转发配置完成！${NC}"
echo -e "${CYAN}==========================================${NC}"
