#!/bin/bash
# wake_hardened.sh
# Companion trigger script for Heimdall WoL Relay (HARDENED build).
# Requires: mosquitto_clients and python3 or oathtool for TOTP generation.

set -e # Exit immediately if a command fails

if [ "$#" -lt 5 ]; then
    echo "Usage: $0 <mqtt_broker> <mqtt_port> <cmd_topic> <target_mac> <totp_seed_base32_or_otpauth_uri> [username] [password]"
    echo ""
    echo "Example HiveMQ TLS:"
    echo "  $0 mqtt.example.net 8883 a1b2c3d4e5f6a7b8 AA:BB:CC:DD:EE:FF JBSWY3DPEHPK3PXP myuser mypass"
    exit 1
fi

BROKER=$1
PORT=$2
TOPIC=$3
MAC=$4
SEED_INPUT=$5
USER=$6
PASS=$7

# Generate TOTP code (6 digits, 30s step)
if command -v python3 &> /dev/null; then
    TOTP=$(python3 - "${SEED_INPUT}" <<'PY'
import base64
import binascii
import hashlib
import hmac
import re
import struct
import sys
import time
import urllib.parse

seed = sys.argv[1].strip()
if seed.lower().startswith("otpauth://"):
    parsed = urllib.parse.urlparse(seed)
    seed = urllib.parse.parse_qs(parsed.query).get("secret", [""])[0]

seed = re.sub(r"\s+", "", seed).strip("=")
if not seed:
    print("Error: empty TOTP seed.", file=sys.stderr)
    sys.exit(1)

try:
    if re.fullmatch(r"[0-9a-fA-F]+", seed) and len(seed) % 2 == 0:
        key = bytes.fromhex(seed)
    else:
        normalized = seed.upper()
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized + padding, casefold=True)
except (ValueError, binascii.Error) as exc:
    print(f"Error: invalid TOTP seed: {exc}", file=sys.stderr)
    sys.exit(1)

counter = int(time.time() / 30)
msg = struct.pack(">Q", counter)
digest = hmac.new(key, msg, hashlib.sha1).digest()
offset = digest[19] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print(f"{code:06d}")
PY
)
elif command -v oathtool &> /dev/null; then
    SEED="${SEED_INPUT}"
    if [[ "${SEED,,}" == otpauth://* ]]; then
        SEED="${SEED#*secret=}"
        SEED="${SEED%%&*}"
    fi
    SEED="${SEED// /}"
    SEED="${SEED//=}"
    if [[ "${SEED}" =~ ^[0-9A-Fa-f]+$ ]] && [ $(( ${#SEED} % 2 )) -eq 0 ]; then
        TOTP=$(oathtool --totp --time-step-size=30s --window=0 "${SEED}")
    else
        TOTP=$(oathtool --totp --base32 --time-step-size=30s --window=0 "${SEED}")
    fi
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
