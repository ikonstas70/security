#!/bin/bash

# Author: Ioannis Konstas — IT Solutions USA
# Monitors OSSEC logs (ossec.log + alerts.log) in real time with formatted output.

OSSEC_LOG="/var/ossec/logs/ossec.log"
ALERTS_LOG="/var/ossec/logs/alerts/alerts.log"

usage() {
    echo "Usage: $0 [mode]"
    echo ""
    echo "  simple    — Compact live tail: [timestamp] type  message"
    echo "  detailed  — Detailed view with last 500 lines history and full field layout"
    echo ""
    echo "If no mode is given, prompts interactively."
}

run_simple() {
    echo "Starting OSSEC live monitor (simple view) — Ctrl+C to exit"
    echo "──────────────────────────────────────────────────────────"
    sudo tail -f "$OSSEC_LOG" "$ALERTS_LOG" | awk '{
        printf "[%s] %-5s %s\n", $1" "$2, $3, substr($0, index($0,$4))
    }'
}

run_detailed() {
    echo "Starting OSSEC live monitor (detailed view, last 500 lines) — Ctrl+C to exit"
    echo "─────────────────────────────────────────────────────────────────────────────"
    sudo tail -n 500 -F "$OSSEC_LOG" "$ALERTS_LOG" | awk '{
        printf "[%s] %s %s[%s] %s %s\n", $1" "$2, $6, $3, $4, substr($0, index($0,$7)), $5
    }'
}

case "$1" in
    simple)   run_simple ;;
    detailed) run_detailed ;;
    -h|--help) usage ;;
    "")
        echo "OSSEC Log Monitor — IT Solutions USA"
        echo "──────────────────────────────────────"
        echo "1. Simple view   — compact live tail"
        echo "2. Detailed view — last 500 lines + full field layout"
        echo ""
        read -p "Select mode (1/2): " choice
        case "$choice" in
            1) run_simple ;;
            2) run_detailed ;;
            *) echo "Invalid choice. Use 1 or 2."; exit 1 ;;
        esac
        ;;
    *)
        echo "Unknown mode: $1"
        usage
        exit 1
        ;;
esac
