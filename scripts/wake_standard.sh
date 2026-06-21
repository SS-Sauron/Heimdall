#!/bin/bash
# wake_standard.sh
# Companion trigger script for Heimdall WoL Relay (STANDARD build).
# Requires: mosquitto_clients

set -e # Exit immediately if a command fails

if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <mqtt_broker> <mqtt_port> <cmd_topic> <target_mac> [username] [password]"
    echo ""
    echo "Examples:"
    echo "  Unencrypted: $0 mqtt.lan 1883 wol/AA:BB:CC:DD:EE:FF AA:BB:CC:DD:EE:FF"
    echo "  HiveMQ TLS:  $0 xxx.eu.hivemq.cloud 8883 wol/AA:BB:CC:DD:EE:FF AA:BB:CC:DD:EE:FF myuser mypass"
    exit 1
fi

BROKER=$1
PORT=$2
TOPIC=$3
MAC=$4
USER=$5
PASS=$6

PAYLOAD="${MAC}"

echo "Broadcasting Wake-on-LAN via MQTT Relay (Standard)..."
echo "  Broker:  ${BROKER}:${PORT}"
echo "  Topic:   ${TOPIC}"
echo "  Target:  ${MAC}"
echo "  Payload: ${PAYLOAD}"
echo ""

# Security Best Practice: Use a bash array instead of string 'eval'
# This prevents shell injection vulnerabilities if variables contain spaces or special chars
CMD=("mosquitto_pub" "-h" "$BROKER" "-p" "$PORT" "-t" "$TOPIC" "-m" "$PAYLOAD" "-q" "1")

if [ "${PORT}" -eq 8883 ]; then
    CMD+=("--tls-use-os-certs")
fi

if [ -n "${USER}" ] && [ -n "${PASS}" ]; then
    # Note: Passing passwords via CLI arguments makes them visible in 'ps aux'
    # For automated production environments, consider using MQTT_PASSWORD env vars
    CMD+=("-u" "$USER" "-P" "$PASS")
fi

# Execute the array securely
"${CMD[@]}"

echo "Message published successfully."
