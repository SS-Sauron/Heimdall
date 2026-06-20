#!/bin/bash
# wake.sh
# Companion trigger script for Heimdall WoL Relay.
# Requires: mosquitto_clients, and oathtool (or python3) for TOTP generation.

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <mqtt_broker> <cmd_topic> <target_mac> <totp_seed_hex>"
    echo ""
    echo "Example:"
    echo "  $0 mqtt.lan d4f3a891c02e57b3 AA:BB:CC:DD:EE:FF 0123456789abcdef0123456789abcdef01234567"
    exit 1
fi

BROKER=$1
TOPIC=$2
MAC=$3
SEED_HEX=$4

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

echo "Broadcasting Wake-on-LAN via MQTT Relay..."
echo "  Broker:  ${BROKER}"
echo "  Topic:   ${TOPIC}"
echo "  Target:  ${MAC}"
echo "  Payload: ${PAYLOAD}"
echo ""

mosquitto_pub -h "${BROKER}" -t "${TOPIC}" -m "${PAYLOAD}"

if [ $? -eq 0 ]; then
    echo "Message published successfully."
else
    echo "Failed to publish message."
    exit 1
fi
