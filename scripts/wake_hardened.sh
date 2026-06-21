#!/bin/bash
# wake_hardened.sh
# Companion trigger script for Heimdall WoL Relay (HARDENED build).
# Requires: mosquitto_clients, and oathtool (or python3) for TOTP generation.

set -e # Exit immediately if a command fails

if [ "$#" -lt 5 ]; then
    echo "Usage: $0 <mqtt_broker> <mqtt_port> <cmd_topic> <target_mac> <totp_seed_hex> [username] [password]"
    echo ""
    echo "Example HiveMQ TLS:"
    echo "  $0 xxx.eu.hivemq.cloud 8883 a1b2c3d4e5f6g7h8 AA:BB:CC:DD:EE:FF 0123456789ABCDEF myuser mypass"
    exit 1
fi

BROKER=$1
PORT=$2
TOPIC=$3
MAC=$4
SEED_HEX=$5
USER=$6
PASS=$7

# Generate TOTP code (6 digits, 30s step)
if command -v oathtool &> /dev/null; then
    TOTP=$(oathtool --totp --time-step-size=30s --window=0 "${SEED_HEX}")
elif command -v python3 &> /dev/null; then
    TOTP=$(python3 -c "
import hmac, hashlib, time, struct, sys
key = bytes.fromhex(sys.argv[1])
T = int(time.time() / 30)
msg = struct.pack('>Q', T)
h = hmac.new(key, msg, hashlib.sha1).digest()
o = h[19] & 15
h = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
print(f'{h:06d}')
" "${SEED_HEX}")
else
    echo "Error: Neither 'oathtool' nor 'python3' is installed. Cannot generate TOTP."
    exit 1
fi

PAYLOAD="${MAC}:${TOTP}"

echo "Broadcasting Wake-on-LAN via MQTT Relay (Hardened)..."
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
