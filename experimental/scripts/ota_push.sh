#!/usr/bin/env bash
# =============================================================================
# ota_push.sh — Heimdall wireless firmware update helper
#
# Uploads a new firmware image to a running Heimdall device over WiFi using
# ESP-IDF's built-in espota.py OTA uploader.
#
# REQUIREMENTS
# ------------
#   • ESP-IDF environment must be sourced in your shell:
#       . $IDF_PATH/export.sh          (Linux / macOS)
#       $IDF_PATH\export.ps1           (Windows PowerShell)
#   • The device must be running and connected to your LAN.
#   • The device IP must be reachable (ping it first to confirm).
#   • CONFIG_OTA_ALLOW_HTTP=y must be set (already in sdkconfig.defaults).
#
# TRANSPORT NOTE
# --------------
# espota.py uploads over plain HTTP on TCP port 3232. This is only intended
# for use on a trusted local network. Never use this across the internet or
# on an untrusted WiFi network — the binary is transmitted in cleartext.
#
# ROLLBACK SAFETY
# ---------------
# Heimdall's firmware calls esp_ota_mark_app_valid_cancel_rollback() when it
# successfully connects to the MQTT broker (in mqtt_relay.c). If the new
# firmware is flashed but cannot reach the broker, the bootloader will
# automatically roll back to the previous firmware slot on the next reboot.
#
# USAGE
# -----
#   ./scripts/ota_push.sh --host <DEVICE_IP> [--bin <path/to/firmware.bin>]
#
# EXAMPLES
#   # Push the default build output to device at 192.168.1.42
#   ./scripts/ota_push.sh --host 192.168.1.42
#
#   # Push a downloaded release binary
#   ./scripts/ota_push.sh --host 192.168.1.42 --bin ~/Downloads/heimdall-standard.bin
#
# NOTE ON BINARY NAME
# -------------------
# The ESP-IDF cmake project is named "wol_relay" (see CMakeLists.txt), so the
# local build output is always build/wol_relay.bin. Downloaded release binaries
# are named heimdall-standard.bin or heimdall-hardened.bin — pass either with --bin.
#
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
DEVICE_HOST=""
FIRMWARE_BIN="build/wol_relay.bin"
OTA_PORT=3232

# ── Argument parsing ───────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 --host <DEVICE_IP> [--bin <firmware.bin>]"
    echo ""
    echo "  --host  <IP>   IP address of the running Heimdall device (required)"
    echo "  --bin   <path> Path to the firmware binary (default: build/wol_relay.bin)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            DEVICE_HOST="$2"; shift 2 ;;
        --bin)
            FIRMWARE_BIN="$2"; shift 2 ;;
        -h|--help)
            usage ;;
        *)
            echo "Unknown argument: $1"
            usage ;;
    esac
done

# ── Validation ────────────────────────────────────────────────────────────────
if [[ -z "$DEVICE_HOST" ]]; then
    echo "ERROR: --host is required."
    usage
fi

if [[ ! -f "$FIRMWARE_BIN" ]]; then
    echo "ERROR: Firmware binary not found: $FIRMWARE_BIN"
    echo ""
    echo "If you haven't built yet, run:  idf.py build"
    echo "The local build output is:      build/wol_relay.bin"
    echo "Or download a release binary from:"
    echo "  https://github.com/SS-Sauron/Heimdall/releases"
    exit 1
fi

if [[ -z "${IDF_PATH:-}" ]]; then
    echo "ERROR: IDF_PATH is not set. Source the ESP-IDF environment first:"
    echo "  . \$IDF_PATH/export.sh"
    exit 1
fi

ESPOTA="$IDF_PATH/components/esptool_py/esptool/espota.py"
if [[ ! -f "$ESPOTA" ]]; then
    echo "ERROR: espota.py not found at: $ESPOTA"
    echo "Make sure ESP-IDF is correctly installed."
    exit 1
fi

# ── Pre-flight info ───────────────────────────────────────────────────────────
FILESIZE=$(du -h "$FIRMWARE_BIN" | cut -f1)
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Heimdall OTA Firmware Push                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Target device  : $DEVICE_HOST:$OTA_PORT"
echo "  Firmware binary: $FIRMWARE_BIN  ($FILESIZE)"
echo ""
echo "  ⚠  Transport is plain HTTP — use on a trusted LAN only."
echo "  ✓  Automatic rollback is active — the previous firmware"
echo "     is preserved and restored if MQTT does not connect."
echo ""
echo "  Uploading..."
echo ""

# ── Upload ────────────────────────────────────────────────────────────────────
python3 "$ESPOTA" \
    --ip "$DEVICE_HOST" \
    --port "$OTA_PORT" \
    --file "$FIRMWARE_BIN" \
    --progress

echo ""
echo "  ✓ Upload complete!"
echo ""
echo "  The device is now rebooting with the new firmware."
echo "  Watch the MQTT status topic for {\"status\":\"online\"} to"
echo "  confirm the update succeeded and rollback was cancelled."
echo ""
echo "  If the device does not reconnect within ~60 seconds, it will"
echo "  automatically roll back to the previous firmware on next boot."
echo ""
