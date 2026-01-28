#!/bin/bash
# update-proxies-config.sh
# This script updates the proxy configuration in config.yaml with live proxies from 3proxy

PROXY_FILE="/tmp/3proxy-live-proxies.txt"
CONFIG_FILE="config.yaml"
BACKUP_FILE="config.yaml.bak"

# Check if proxy file exists
if [ ! -f "$PROXY_FILE" ]; then
    echo "ERROR: Proxy list file not found: $PROXY_FILE"
    echo "Make sure 3proxy-rotator service is running: sudo systemctl start 3proxy-rotator.service"
    exit 1
fi

# Count proxies
PROXY_COUNT=$(wc -l < "$PROXY_FILE")
echo "Found $PROXY_COUNT live proxies in $PROXY_FILE"

if [ "$PROXY_COUNT" -lt 1 ]; then
    echo "ERROR: No proxies found in $PROXY_FILE"
    exit 1
fi

# The Go application will read directly from $PROXY_FILE
# No need to update config.yaml anymore

echo "✓ Proxy list updated at $PROXY_FILE"
echo "✓ The application will automatically rotate proxies from this list."
echo ""
echo "Proxy usage is logged to: /tmp/proxy-audit.log"
