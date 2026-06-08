#!/bin/bash
# Tor service manager — start, stop, restart, and verify Tor anonymity.
# Author: Ioannis Konstas — IT Solutions USA
#
# Usage: bash tor_service_manager.sh

red() { echo -e "\e[31m$1\e[0m"; }

check_ip_tor() {
    red "IP address over Tor:"
    curl --socks5 127.0.0.1:9050 https://icanhazip.com
}

check_tor_vs_real() {
    red "IP address over Tor:"
    curl --socks5 127.0.0.1:9050 https://icanhazip.com
    red "Real IP address (without Tor):"
    curl -s ifconfig.me
    echo
}

check_tor_status() {
    red "Tor service status:"
    if systemctl is-active --quiet tor; then
        red "Tor is RUNNING"
    else
        red "Tor is NOT running"
    fi
}

start_tor() {
    red "Starting Tor service..."
    sudo systemctl start tor
    sleep 2
    check_tor_status
}

stop_tor() {
    red "Stopping Tor service..."
    sudo systemctl stop tor
    sleep 2
    check_tor_status
}

restart_tor() {
    red "Restarting Tor service..."
    sudo systemctl restart tor
    sleep 2
    check_tor_status
}

check_tor_process() {
    red "Tor process check:"
    if pgrep tor > /dev/null; then
        red "Tor process is RUNNING"
    else
        red "Tor process is NOT running"
    fi
}

while true; do
    echo ""
    red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    red "    Tor Service Manager"
    red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. Check current IP over Tor"
    echo "2. Compare Tor IP vs real IP"
    echo "3. Check Tor service status"
    echo "4. Start Tor"
    echo "5. Stop Tor"
    echo "6. Restart Tor"
    echo "7. Check Tor process"
    echo "8. Exit"
    echo ""
    read -p "Choice (1-8): " choice

    case $choice in
        1) check_ip_tor ;;
        2) check_tor_vs_real ;;
        3) check_tor_status ;;
        4) start_tor ;;
        5) stop_tor ;;
        6) restart_tor ;;
        7) check_tor_process ;;
        8) red "Exiting."; exit 0 ;;
        *) red "Invalid choice. Enter 1–8." ;;
    esac

    red "---"
done
