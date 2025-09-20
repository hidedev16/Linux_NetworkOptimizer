#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Ensure root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root.${NC}"
    exit 1
fi

# Logo
print_logo() {
    echo -e "\n${CYAN}"
    echo "    ___      _       __  ___       __  "
    echo "   /   |____(_)___  /  |/  /___ __/ /__"
    echo "  / /| / ___/ / __ \/ /|_/ / __  / //_/"
    echo " / ___ / /  / / /_/ / /  / / /_/ / ,<   "
    echo "/_/  |_\___/_/ .___/_/  /_/\__,_/_/|_|  "
    echo "            /_/                          "
    echo -e "${NC}"
    echo -e "${BLUE}AdMob Network Optimizer Script v1.0${NC}"
}

# Header
show_header() {
    print_logo
    echo -e "\n${GREEN}Hostname       : $(hostname)${NC}"
    echo -e "${GREEN}OS             : $(grep '^PRETTY_NAME=' /etc/os-release | cut -d '=' -f2 | tr -d '\"')${NC}"
    echo -e "${GREEN}Kernel Version : $(uname -r)${NC}"
    echo -e "${GREEN}IP Address     : $(hostname -I | awk '{print $1}')${NC}"
    echo -e "${GREEN}CPU            : $(grep -m1 'model name' /proc/cpuinfo | cut -d ':' -f2 | xargs)${NC}"
    echo -e "${GREEN}Memory Usage   : $(free -h | awk '/^Mem:/{print $3 " / " $2}')${NC}\n"
}

# Force Google DNS (AdMob safe)
fix_dns() {
    local dns_path=${1:-/etc/resolv.conf}
    echo -e "${YELLOW}Setting Google DNS...${NC}"
    cp "$dns_path" "${dns_path}.bak"
    echo "nameserver 8.8.8.8" > "$dns_path"
    echo "nameserver 8.8.4.4" >> "$dns_path"
    echo -e "${GREEN}Google DNS applied (8.8.8.8 / 8.8.4.4).${NC}"
}

# Disable IPv6
disable_ipv6() {
    echo -e "${YELLOW}Disabling IPv6...${NC}"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    echo -e "${GREEN}IPv6 disabled.${NC}"
}

# Enable BBR
enable_bbr() {
    echo -e "${YELLOW}Enabling BBR congestion control...${NC}"
    modprobe tcp_bbr
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    echo -e "${GREEN}BBR enabled.${NC}"
}

# Find best MTU for Google
find_best_mtu() {
    local server_ip=8.8.8.8
    local low=1200
    local high=1500
    local optimal=0

    echo -e "${YELLOW}Testing MTU with $server_ip...${NC}"

    if ! ping -c 1 -W 1 "$server_ip" &>/dev/null; then
        echo -e "${RED}Google DNS not reachable.${NC}"
        return 1
    fi

    optimal=$low
    while [ $low -le $high ]; do
        local mid=$(( (low + high) / 2 ))
        if ping -M do -s $((mid - 28)) -c 1 "$server_ip" &>/dev/null; then
            optimal=$mid
            low=$(( mid + 1 ))
        else
            high=$(( mid - 1 ))
        fi
    done

    echo -e "${GREEN}Optimal MTU: $optimal${NC}"
    read -p "Set MTU on interface? (Y/n): " ans
    if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then
        read -p "Enter interface (e.g. eth0): " iface
        ip link set dev "$iface" mtu "$optimal" && echo -e "${GREEN}MTU applied to $iface${NC}"
    fi
}

# Restore DNS/sysctl
restore_original() {
    if [ -f /etc/resolv.conf.bak ]; then
        cp /etc/resolv.conf.bak /etc/resolv.conf
        echo -e "${GREEN}DNS restored.${NC}"
    fi
    if [ -f /etc/sysctl.conf.bak ]; then
        cp /etc/sysctl.conf.bak /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}Sysctl restored.${NC}"
    fi
}

# Menu
show_menu() {
    while true; do
        clear
        show_header
        echo -e "${CYAN}Menu:${NC}"
        echo -e "${GREEN}1. Apply AdMob Optimizations (Google DNS + BBR + Disable IPv6)${NC}"
        echo -e "${GREEN}2. Find Best MTU${NC}"
        echo -e "${GREEN}3. Restore Original Settings${NC}"
        echo -e "${GREEN}0. Exit${NC}"
        echo
        read -p "Choose: " choice

        case $choice in
            1) fix_dns; disable_ipv6; enable_bbr; read -n1 -s -r -p "Done. Press any key...";;
            2) find_best_mtu; read -n1 -s -r -p "Press any key...";;
            3) restore_original; read -n1 -s -r -p "Press any key...";;
            0) exit 0;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 2;;
        esac
    done
}

# Start
show_menu
