# Heimdall — Technical Documentation

This document explains how Heimdall works internally: its architecture, boot sequence, component responsibilities, configuration system, security model, and operational behaviour. It assumes you have already flashed the firmware and completed provisioning. If you haven't, start with the main [README](../README.md).

Future feature ideas and viability notes live in the [Heimdall Feature Roadmap](heimdall_feature_roadmap.md).

All commands, MAC addresses, broker names, and secrets shown here are placeholders. Do not commit real WiFi credentials, MQTT credentials, HMAC secrets, TOTP seeds, broker hostnames, or device MAC addresses to this repository.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Boot Sequence](#boot-sequence)
3. [Components](#components)
   - [main](#main)
   - [storage](#storage)
   - [identity](#identity)
   - [portal](#portal)
   - [dns_server](#dns_server)
   - [wifi_sta](#wifi_sta)
   - [opsec](#opsec)
   - [mqtt_relay](#mqtt_relay)
   - [wol](#wol)
   - [status_led](#status_led)
4. [Build Profiles](#build-profiles)
5. [Configuration Reference](#configuration-reference)
6. [Network Security Model](#network-security-model)
7. [MQTT Protocol](#mqtt-protocol)
8. [Wake-on-LAN](#wake-on-lan)
9. [Self-Healing & Recovery](#self-healing--recovery)
10. [OTA Updates](#ota-updates)
11. [NVS Storage Schema](#nvs-storage-schema)
12. [Web Flasher & CI/CD Pipeline](#web-flasher--cicd-pipeline)
13. [Development Environment](#development-environment)

---

## Architecture Overview

Heimdall is built as a **component-based embedded application** on top of ESP-IDF and FreeRTOS. Each logical concern lives in its own isolated component under `components/`. Components communicate through direct function calls across clean public APIs defined in their header files — there is no global state shared between components except through the `storage` component, which acts as the single source of truth for all persisted configuration.

The runtime is **event-driven**: WiFi events, IP events, and MQTT events are dispatched by ESP-IDF's event loop to registered callbacks. FreeRTOS tasks handle the MQTT client lifecycle and the DNS server. The main task is used for sequential boot orchestration and then enters the MQTT relay health-monitor loop indefinitely.

```text
┌─────────────────────────────────────────────────────────┐
│                        app_main()                        │
│                    (boot orchestrator)                   │
└──────┬──────────────────────────────────────────────────┘
       │
       ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│   storage    │    │   identity   │    │      portal       │
│  (NVS layer) │    │ (MAC/hostname│    │  (captive portal  │
│              │    │  obfuscation)│    │   provisioning)   │
└──────┬───────┘    └──────┬───────┘    └────────┬─────────┘
       │                   │                     │
       │            ┌──────▼───────┐    ┌────────▼─────────┐
       │            │   wifi_sta   │    │    dns_server     │
       │            │ (STA connect │    │ (DNS redirect for │
       │            │  self-heal)  │    │  captive portal)  │
       │            └──────┬───────┘    └──────────────────┘
       │                   │
       │            ┌──────▼───────┐
       │            │  mqtt_relay  │
       │            │  (MQTT core, │
       │            │  OTA, relay) │
       │            └──────┬───────┘
       │                   │
       │     ┌─────────────┼─────────────┐
       │     │             │             │
       │  ┌──▼──┐      ┌───▼──┐    ┌────▼───┐
       └──► opsec│      │ opsec│    │  wol   │
          │(HMAC)│      │(TOTP)│    │ (magic │
          └──────┘      └──────┘    │ packet)│
                                    └────────┘
```

---

## Boot Sequence

Every boot follows this exact sequence. Ordering is strict — deviating from it causes subtle failures (hostname applied before interface exists, WiFi starts before MAC is spoofed, etc.).

```text
1.  nvs_flash_init()                   Initialize NVS flash partition
2.  Factory reset button check         GPIO0 hold detection (blocking, 5 s)
3.  esp_netif_init()                   Initialize TCP/IP stack
4.  esp_event_loop_create_default()    Create system event loop
5.  mdns_init()                        Start mDNS service (one time only)
6.  identity_apply()                   Spoof MAC, generate/load hostname
7.  storage_is_provisioned()           Check for saved credentials in NVS
    │
    ├── NOT PROVISIONED ──► portal_start()
    │                       SoftAP + DNS + HTTP provisioning UI
    │                       Blocks until the user confirms saved secrets
    │                       via POST /reboot → esp_restart()
    │
    └── PROVISIONED ──────► wifi_sta_connect()
                            Connect to saved WiFi network (blocks until IP)
                            │
                            └──► mqtt_relay_start()
                                 OPSEC init → SNTP → MQTT → health loop
                                 (never returns)
```

---

## Components

### main

**Files:** `main/main.c`, `main/Kconfig.projbuild`

The boot dispatcher. Calls each component in the correct order, handles the provisioned/unprovisioned branch, and contains the crash-loop detection logic. It creates the default STA netif and initializes the WiFi driver exactly once before identity handling; station and portal paths only configure mode, credentials, and start WiFi afterward. After handing off to `mqtt_relay_start()` it never regains control — the MQTT relay runs until a reset.

**Status LED init:** `status_led_init()` is called immediately after the WiFi driver is initialized (before the factory reset task spawns). It configures the GPIO pin as output and starts the blink task. The portal branch calls `status_led_set_state(STATUS_LED_STATE_PORTAL)` before `portal_start()` so the LED begins blinking as soon as provisioning mode is entered.

**Crash loop detection:** On every boot, `esp_reset_reason()` is checked. If the reason is `ESP_RST_PANIC` or `ESP_RST_TASK_WDT` (genuine firmware crashes — not intentional software resets), a counter in NVS is incremented. Once that counter reaches the configured threshold (default: 5 consecutive crashes), `storage_erase_all()` is called and the device reboots into provisioning mode. Any successful WiFi connection resets the counter to zero.

**Factory reset button:** GPIO0 (the BOOT button on most ESP32 dev boards) is sampled at boot. If held for `CONFIG_WOL_FACTORY_RESET_HOLD_MS` (default: 5000 ms), all NVS credentials are erased and the device reboots into the captive portal. The detection uses a blocking polling loop with a 20 ms debounce — the entire rest of boot is paused while the button is held, which is intentional.

---

### storage

**Files:** `components/storage/storage.c`, `components/storage/storage.h`

The single NVS interface for the entire project. Every other component that needs to persist or read data does so through functions defined here — nothing else calls NVS APIs directly. This centralises all key name definitions and ensures consistent error handling across the codebase.

All NVS key names are two characters, opaque by design. A raw NVS dump should not reveal the purpose of any stored field.

**SecureOn support:** The optional SecureOn password is stored under key `"so"` as a 17-character string (`AA:BB:CC:DD:EE:FF` format). The load path does not fail if the key is absent — `nvs_get_str` returning `ESP_ERR_NVS_NOT_FOUND` for this key is treated as "no SecureOn configured" and the standard 102-byte magic packet is sent.

See [NVS Storage Schema](#nvs-storage-schema) for the complete key list.

---

### identity

**Files:** `components/identity/identity.c`, `components/identity/identity.h`

Handles network identity before WiFi starts. Must run after `main` has created `WIFI_STA_DEF` and called `esp_wifi_init()`, but before `esp_wifi_start()`. Identity deliberately does not initialize WiFi itself, which prevents duplicate `esp_wifi_init()` calls when booting into relay or captive portal mode.

**MAC spoofing (HARDENED only):** Derives a locally-administered MAC address from the factory eFuse MAC using `esp_derive_local_mac()`. The result sets the locally-administered bit (bit 1 of byte 0), making it a valid LAA address that does not resolve to Espressif in OUI databases. Applied via `esp_wifi_set_mac()`.

**Hostname generation — precedence (highest to lowest):**
1. User-set hostname loaded from NVS key `"hn"` (if present and RFC 1123 valid)
2. HARDENED fake consumer-device hostname: `CONFIG_OPSEC_IDENTITY_HOSTNAME_PREFIX` + last 3 MAC bytes as hex (e.g. `NETGEAR-A3F19C`)
3. Default: `esp32-XXXXXX` using last 3 eFuse MAC bytes

The effective hostname is cached internally and retrieved by other components via `identity_get_hostname()`. It is applied to the STA netif by `wifi_sta.c` at the correct moment (after netif creation, before WiFi start), and simultaneously pushed to mDNS via `mdns_hostname_set()` and to NetBIOS via `netbiosns_set_name()`.

---

### portal

**Files:** `components/portal/portal.c`, `components/portal/portal.h`, `components/portal/portal_html/index.html`, `components/portal/portal_html/login.html`, `components/portal/portal_html/secrets.html`, `components/portal/portal_html/rebooting.html`

Runs exclusively on the first boot (or after a factory reset). Brings up a WPA2-protected SoftAP in `WIFI_MODE_APSTA` mode (both AP and STA active simultaneously — STA is needed for the WiFi scan feature even though it stays unconnected). The portal password is derived from the factory eFuse MAC with HMAC-SHA256, is not stored in NVS, and remains the same after factory reset.

`index.html` is embedded with `EMBED_FILES`. The smaller login, secrets, and rebooting pages are embedded with `EMBED_TXTFILES`, so their HTTP/template lengths deliberately use `end - start - 1` to exclude the generated null terminator. The secrets page response sets `Cache-Control: no-store` before sending and clears its temporary template buffer after use because it contains the one-time HMAC/TOTP values.

**Captive portal interception uses three complementary mechanisms:**

| Mechanism | Handles |
|---|---|
| DNS redirect (dns_server) | All DNS queries → 192.168.4.1 |
| DHCP Option 114 | Advertises captive portal URI during IP assignment (Chrome, Android) |
| HTTP 303 + body | `handle_captive_redirect` returns 303 with body content (iOS requirement) |

**Provisioning flow:**
1. User connects to the SoftAP using the permanent portal password printed on serial when `CONFIG_WOL_SERIAL_PROVISION_INFO=y`
2. Captive portal popup appears automatically and shows a login form
3. User submits the portal password to `POST /login`; the session unlock flag is RAM-only and resets on reboot
4. Portal scans nearby WiFi networks and presents them as a selectable list
5. User enters: WiFi SSID/password, MQTT broker URL/port/credentials, optional custom hostname
6. The browser posts JSON to `POST /api/provision`; the firmware parses it with `cJSON_Parse()`
7. The portal validates all fields server-side:
   - WiFi SSID: required, 1–32 bytes
   - MQTT broker host: required, 1–128 bytes, no whitespace/control characters
   - MQTT broker scheme prefixes are stripped before storage (`mqtt://`, `mqtts://`, `tcp://`, `ssl://`, `http://`, `https://`)
   - MQTT port: numeric, defaults to 8883 if omitted
   - MQTT username/password: optional strings, max 64 bytes each; overlength values are rejected instead of truncated
   - Hostname: optional RFC 1123 label, 1–32 chars, letters/digits/hyphen, no leading or trailing hyphen
8. Credentials are written to NVS via `storage_save_credentials()`
9. If OPSEC is enabled, HMAC secret and TOTP seed are generated now and shown on a one-time HTML secrets page — **this is the only moment they are visible**
10. The user records any shown secrets and clicks the final **Start Relay** button, which posts to `/reboot` and triggers `esp_restart()`

**HTTP server:** 12 URI handlers registered on port 80. `max_uri_handlers` set to 12. The wildcard catch-all (`/*`) is registered last and handles all OS captive-portal detection URLs.

---

### dns_server

**Files:** `components/dns_server/dns_server.c`, `components/dns_server/dns_server.h`

A minimal UDP DNS server that responds to every A-record query with a single configurable IPv4 address (192.168.4.1 during portal operation).

Runs as a dedicated FreeRTOS task on port 53. A 1-second `SO_RCVTIMEO` on the receive socket allows `dns_server_stop()` to signal a clean exit without force-deleting the task. The socket is recreated automatically on bind or receive errors.

**DNS reply construction:**
- Copies the incoming query into the reply buffer
- Sets the QR flag (response) without byte-swapping — intentional, matches Espressif's official captive portal example
- Appends an A-record answer for each A-type question pointing to the redirect IP
- AAAA and other query types receive a header-only NOERROR response with zero answers
- Reply length is calculated from actual A-record answers written, not the total question count

---

### wifi_sta

**Files:** `components/wifi_sta/wifi_sta.c`, `components/wifi_sta/wifi_sta.h`

Connects the ESP32 to the provisioned WiFi network and manages reconnection across the device's lifetime. Blocks in `wifi_sta_connect()` until an IP address is obtained, then returns `ESP_OK` to allow the MQTT relay to start.

**Disconnect reason discrimination:** Not all WiFi disconnects are equal. The handler reads `wifi_event_sta_disconnected_t.reason` from the event data and splits into two paths:

*Wrong-credential reasons* (count toward portal fallback):
- `WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT`
- `WIFI_REASON_HANDSHAKE_TIMEOUT`
- `WIFI_REASON_802_1X_AUTH_FAILED`
- `WIFI_REASON_IE_IN_4WAY_DIFFERS`

*Transient reasons* (retry indefinitely, reset counter) — everything else, including ESP-IDF v6 additions:
- `WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY`
- `WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD`
- `WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD`

See [Self-Healing & Recovery](#self-healing--recovery) for the full two-path recovery model.

---

### opsec

**Files:** `components/opsec/opsec.c`, `components/opsec/opsec.h`

Active in HARDENED builds only (gated by `CONFIG_OPSEC_HMAC_TOPIC` and `CONFIG_OPSEC_TOTP`). Provides two security services:

**HMAC-derived MQTT topics:**

MQTT topics are derived by computing `HMAC-SHA256(secret, device_MAC)` and hex-encoding portions of the digest:
- Command topic: bytes 0–7 of digest → 16 hex characters
- Status topic: `<command_topic>/s` — retained, machine-readable state
- Log topic: `<command_topic>/l` — unretained, diagnostic heartbeats

The secret is a 32-byte random blob generated once during provisioning and stored in NVS. The same device always produces the same topics (deterministic), but the topics reveal nothing about the device's purpose or MAC address to a broker observer.

**TOTP command authentication (RFC 6238):**

Uses HMAC-SHA1 with the stored 20-byte seed and the current time counter `T = floor(unix_time / step_seconds)` (default step: 30 s). Dynamic truncation produces a 6-digit code. A ±1 window (T-1, T, T+1) accommodates up to 30 seconds of clock drift.

SNTP is required for TOTP. `opsec_sync_clock()` blocks for up to 30 seconds waiting for a successful sync. If sync fails, TOTP validation is unavailable and commands are rejected.

**Payload format with TOTP enabled:**
```text
AA:BB:CC:DD:EE:FF:123456
└─── target MAC ───┘└code┘
```

The companion `scripts/wake_hardened.sh` helper generates the TOTP suffix automatically. It accepts the Base32 seed or quoted `otpauth://` URI shown on the one-time portal secrets page. `scripts/wake_standard.sh` sends the plain MAC payload used by STANDARD builds.

---

### mqtt_relay

**Files:** `components/mqtt_relay/mqtt_relay.c`, `components/mqtt_relay/mqtt_relay.h`

The operational core. Runs indefinitely after WiFi is connected. Uses the `esp-mqtt` managed component (`espressif__mqtt`) with TLS.

**Startup sequence inside `mqtt_relay_start()`:**
1. `opsec_init()` — loads HMAC secret and TOTP seed from NVS
2. `opsec_sync_clock()` — SNTP time sync (no-op in STANDARD builds)
3. `opsec_derive_topics()` — computes command, status (`/s`), and log (`/l`) topic strings
4. `storage_load_credentials()` — reads MQTT broker URL, port, username, password
5. Builds broker URI: `mqtt://` for port 1883, `mqtts://` for 8883
6. Logs broker URI, MQTT username/password lengths, and whether TLS hostname verification/SNI is enabled; raw credentials are never logged
7. `esp_mqtt_client_init()` + `esp_mqtt_client_start()`

**TLS and hosted brokers:** TLS verification uses the ESP x.509 certificate bundle (`esp_crt_bundle_attach`). Hostname verification and SNI are enabled by default through the broker URI hostname. `CONFIG_MQTT_RELAY_SKIP_CERT_CN_CHECK` should stay disabled for hosted brokers such as HiveMQ Cloud because enabling it disables both certificate hostname matching and SNI.

**Event handling:**

| Event | Action |
|---|---|
| `MQTT_EVENT_CONNECTED` | Subscribe to command topic (QoS 1), publish `{"status":"online"}` retained to **status topic** |
| `MQTT_EVENT_SUBSCRIBED` | Call `esp_ota_mark_app_valid_cancel_rollback()` — firmware proven functional |
| `MQTT_EVENT_DATA` | Detect command type (WoL or GPIO) → validate (TOTP if HARDENED) → dispatch → publish result to **status topic** |
| `MQTT_EVENT_DISCONNECTED` | Log only — client auto-reconnects |
| `MQTT_EVENT_ERROR` | Log TLS/TCP details; on `CONNECTION_REFUSED` with bad-credentials code → `storage_erase_all()` + reboot |

**Status topic payload** (retained, QoS 1) — published after each WoL or GPIO command:
```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "status": "sent"
}
```

**Log topic payload** (unretained, QoS 0) — published on connect and periodically by the health monitor:
```json
{
  "free_heap": 187432,
  "uptime_s": 3672
}
```

**GPIO confirmation payload** (status topic, QoS 1):
```json
{"action": "gpio", "pin": 4, "level": 1, "status": "ok"}
```

**Health monitor loop:** Wakes every 5 minutes and publishes a JSON heartbeat to the **log topic** (`/l`). The MQTT client handles reconnection internally.

**Wrong MQTT credential recovery:** If the broker returns `MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED` or `MQTT_CONNECTION_REFUSE_BAD_USERNAME`, retrying forever with the same credentials is pointless. Heimdall erases all stored credentials and reboots into the captive portal, exactly as it does for wrong WiFi passwords.

---

### wol

**Files:** `components/wol/wol.c`, `components/wol/wol.h`

Constructs and broadcasts the Wake-on-LAN magic packet.

**Magic packet structure (102 bytes):**
```text
Bytes  0–5:   FF FF FF FF FF FF          (sync stream)
Bytes  6–101: AA BB CC DD EE FF × 16    (target MAC repeated 16 times)
```

Sent as a UDP broadcast. The broadcast address is computed dynamically at send time from the STA interface's current IP and netmask:

```c
broadcast = ip_info.ip.addr | ~ip_info.netmask.addr
```

This works correctly on any subnet — 192.168.x.x, 10.x.x.x, 172.16.x.x, or any other. The packet is sent `SEND_REPETITIONS` times (default: 3) with a 10 ms gap between transmissions for reliability.

---

### status_led

**Files:** `components/status_led/status_led.c`, `components/status_led/status_led.h`

Provides visual feedback using a single GPIO pin (typically the built-in LED). Runs a low-priority FreeRTOS task that manages blink patterns based on system state:
- **Portal Mode** — toggles every 200ms (fast blink ~2.5Hz)
- **Connecting** — toggles every 1000ms (slow pulse ~0.5Hz)
- **Ready** — solid ON
- **Wake Sent** — 6 rapid toggles at 50ms each, then automatically returns to READY

---

## Build Profiles

Profiles are selected via `idf.py menuconfig` or by setting Kconfig symbols in `sdkconfig.defaults`.

**STANDARD** — Default. No OPSEC features active. MQTT topics are human-readable:
```text
Command topic: wol/AA:BB:CC:DD:EE:FF
Status topic:  wol/AA:BB:CC:DD:EE:FF/s
Log topic:     wol/AA:BB:CC:DD:EE:FF/l
```

**HARDENED** — Enable by setting `CONFIG_WOL_PROFILE_HARDENED=y` or individually enabling the OPSEC Kconfig options. All four OPSEC features activate:
- `CONFIG_OPSEC_IDENTITY_SPOOF_MAC=y`
- `CONFIG_OPSEC_IDENTITY_FAKE_HOSTNAME=y`
- `CONFIG_OPSEC_HMAC_TOPIC=y`
- `CONFIG_OPSEC_TOTP=y`

**CUSTOM** — All features off by default. Configure each option individually via `idf.py menuconfig`. For advanced users who want a specific combination of features without enabling the full HARDENED set.

---

## Configuration Reference

Key Kconfig symbols. All configurable via `idf.py menuconfig`.

| Symbol | Default | Description |
|---|---|---|
| `CONFIG_WOL_FACTORY_RESET_HOLD_MS` | 5000 | Button hold time in ms (range: 3000–15000) |
| `CONFIG_WOL_BROADCAST_PORT` | 9 | UDP port for magic packets |
| `CONFIG_WOL_RESPONSE_CHANNEL` | y | Publish JSON confirmation after each wake |
| `CONFIG_WIFI_STA_MAX_RETRY` | 10 | Wrong-credential strikes before portal fallback |
| `CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES` | 30 | Per-boot WiFi timeout (slow path) |
| `CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MAX_REBOOTS` | 7 | Max slow-path reboots before credential erase |
| `CONFIG_MQTT_RELAY_KEEPALIVE_SEC` | 60 | MQTT keepalive interval |
| `CONFIG_MQTT_RELAY_TASK_STACK_KB` | 8 | MQTT client internal task stack (KB) |
| `CONFIG_MQTT_RELAY_RECONNECT_TIMEOUT_MS` | 5000 | Delay before MQTT reconnect attempt |
| `CONFIG_MQTT_RELAY_SKIP_CERT_CN_CHECK` | n | Debug-only option that disables broker hostname verification and SNI |
| `CONFIG_OPSEC_TOTP_DIGITS` | 6 | TOTP code length |
| `CONFIG_OPSEC_TOTP_STEP_SEC` | 30 | TOTP time step in seconds |
| `CONFIG_OPSEC_SNTP_SERVER` | pool.ntp.org | SNTP server for TOTP clock sync |
| `CONFIG_PORTAL_HTTP_PORT` | 80 | Captive portal HTTP server port |
| `CONFIG_PORTAL_AP_CHANNEL` | 6 | SoftAP WiFi channel |
| `CONFIG_PORTAL_AP_MAX_CONN` | 1 | Maximum simultaneous provisioning clients |
| `CONFIG_PORTAL_TIMEOUT_SEC` | 180 | Portal timeout in seconds (0 = wait forever) |
| `CONFIG_STORAGE_NVS_NAMESPACE` | wol | NVS namespace used for all persisted configuration |
| `CONFIG_WOL_PING_FEEDBACK` | n | Enable ICMP ping after WoL to confirm machine boot |
| `CONFIG_WOL_GPIO_COMMANDS` | n | Enable GPIO pin control via MQTT JSON commands |
| `CONFIG_WOL_GPIO_ALLOWED_PINS` | "4,5" | Comma-separated list of pins that may be driven remotely |
| `CONFIG_WOL_STATUS_LED` | y | Enable visual status LED feedback |
| `CONFIG_WOL_STATUS_LED_PIN` | 2 | GPIO pin used for the status LED |
| `CONFIG_WOL_LEGACY_RSP_TOPIC` | n | Also publish responses to the legacy `/r` topic for backwards compatibility |

---

## Network Security Model

### STANDARD Profile

Topics are predictable and human-readable. Suitable for trusted private MQTT brokers where the broker itself provides access control. Anyone with broker access can trigger a wake command.

### HARDENED Profile

**Topic obfuscation:** Topics are 16-character hex strings derived from `HMAC-SHA256(secret, MAC)`. An observer with full broker read access sees opaque hex strings with no indication of what device is listening or what the commands do. The secret is generated once at provisioning and is never transmitted after that moment.

**TOTP authentication:** Even if an attacker learns the command topic (by capturing a legitimate publish), they cannot replay the command — the TOTP code embedded in the payload is valid for at most 90 seconds (±1 window × 30 s step). A replayed message with an expired code is silently rejected.

**Identity obfuscation:** The device presents a spoofed locally-administered MAC address and a fake consumer-device hostname (e.g. `NETGEAR-A3F19C`) to the local network. Router ARP tables, DHCP lease logs, and network scanners see what appears to be a consumer WiFi device, not an ESP32.

### What HARDENED Does Not Protect Against

- A compromised MQTT broker (the broker sees plaintext even over TLS)
- An attacker who has already obtained the HMAC secret (generated at provisioning time)
- Physical access to the device (NVS contents are readable over USB)

---

## MQTT Protocol

### Connection

Heimdall connects to the configured broker using the native `esp-mqtt` client. TLS is used automatically when the configured port is 8883. Certificate validation uses the ESP x.509 certificate bundle (`esp_crt_bundle_attach`) — standard CA-signed certificates on any major hosting platform (HiveMQ Cloud, EMQX Cloud, AWS IoT, etc.) are validated automatically with no manual certificate management.

For TLS connections, the broker URI hostname is also used for certificate hostname matching and SNI. This matters for cloud brokers that host many customer clusters behind shared infrastructure. Leave `CONFIG_MQTT_RELAY_SKIP_CERT_CN_CHECK` unset unless you are testing against a local/debug broker and intentionally do not need hostname authentication or SNI.

### Last Will & Testament

On connection, Heimdall registers a LWT message:
```text
Topic:   <status_topic>  (e.g. wol/<device-mac>/s)
Payload: {"status":"offline"}
QoS:     1
Retain:  true
```

When the device connects successfully it publishes:
```text
Topic:   <status_topic>
Payload: {"status":"online"}
QoS:     1
Retain:  true
```

This means any MQTT client subscribed to the status topic always knows the current device state without polling.

### Command Format

**STANDARD build — plain WoL:**
```text
AA:BB:CC:DD:EE:FF
```

**STANDARD build — WoL with Ping Feedback:**
```json
{"mac":"AA:BB:CC:DD:EE:FF", "ip":"192.168.1.100"}
```

**STANDARD build — GPIO control:**
```json
{"action":"gpio", "pin":4, "level":1}
```

**HARDENED build with TOTP — WoL:**
```text
AA:BB:CC:DD:EE:FF:123456
```
The payload is a plain string: MAC address, colon separator, 6-digit TOTP code. No JSON wrapper — the format is intentionally compact and non-descriptive.

**HARDENED build with TOTP — WoL with Ping Feedback:**
```text
AA:BB:CC:DD:EE:FF:123456:192.168.1.100
```

**HARDENED build — GPIO control (JSON with TOTP):**
```json
{"action":"gpio", "pin":4, "level":1, "totp":123456}
```

---

## Wake-on-LAN

WoL requires the target machine to have:
1. Wake-on-LAN enabled in BIOS/UEFI settings
2. The network adapter configured to accept magic packets (OS power management settings)
3. The machine connected via Ethernet (WiFi WoL is unreliable and hardware-dependent)

Heimdall broadcasts the magic packet as a UDP datagram to the computed subnet broadcast address on port 9. Three copies are sent 10 ms apart. Most machines that support WoL will wake on the first packet; the repetitions handle rare packet loss on busy networks.

---

## Self-Healing & Recovery

Heimdall implements two independent recovery paths for WiFi failures and one for MQTT credential failures.

### Fast Path — Wrong Credentials

Triggered when the WiFi disconnect reason is definitively a credential failure. A counter (`s_retry_count`) increments on each such event. After `CONFIG_WIFI_STA_MAX_RETRY` consecutive failures: `storage_erase_all()` → `esp_restart()` → captive portal.

This counter does not survive reboots and resets to zero on any successful IP assignment.

### Slow Path — Persistent Network Outage

Triggered when a valid connection cannot be established within `CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES` of a single boot session (not wrong credentials — the router may simply be rebooting). On timeout, the NVS reboot counter (`"rc"`) increments and the device restarts. After `CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MAX_REBOOTS` consecutive cycles (default: 7 × 30 min = 210 minutes total), `storage_erase_all()` → captive portal.

This counter persists across reboots by design. It resets to zero on any successful IP assignment.

```text
WiFi Disconnect
      │
      ├── Wrong credentials? ──► increment fast counter
      │         │                ≥ MAX_RETRY?
      │         │                    │ YES → erase + portal
      │         │                    │ NO  → reconnect
      │         └── NO ──────────────► reset fast counter → reconnect
      │
      └── 30 min timeout? ──────► increment NVS "rc" counter
                                  ≥ MAX_REBOOTS?
                                      │ YES → erase + portal
                                      │ NO  → esp_restart()
```

### MQTT Credential Recovery

If the MQTT broker explicitly rejects the connection (`MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED` or `MQTT_CONNECTION_REFUSE_BAD_USERNAME`), retrying is pointless. Heimdall erases all credentials and reboots into the captive portal, mirroring the WiFi fast-path behaviour.

### Crash Loop Detection

On each boot, if `esp_reset_reason()` is `ESP_RST_PANIC` or `ESP_RST_TASK_WDT`, a crash counter in NVS increments. After the configured threshold of consecutive genuine crashes, credentials are erased and the device falls back to provisioning. This counter resets on any successful WiFi connection. Intentional software resets (`ESP_RST_SW`) — from the portal, factory reset, or recovery paths — do not increment this counter.

---

## OTA Updates

Heimdall supports over-the-air (OTA) updates. The partition table is dual-slot (`ota_0` and `ota_1`).

**Rollback Protection:** When a new firmware is flashed, the bootloader boots from the new slot. The firmware must explicitly prove it is functional before the bootloader makes the change permanent. Heimdall does this in `mqtt_relay.c` by calling `esp_ota_mark_app_valid_cancel_rollback()` *only after* successfully connecting to the MQTT broker and subscribing to the command topic. If the new firmware crashes or cannot reach the broker, the bootloader automatically rolls back to the previous known-good slot on the next reboot.

### How to Update (Current)

> **Note: Wireless OTA push is not yet implemented.** The OTA receiver task (port 3232, `espota.py` transport) is planned for a future release. `CONFIG_OTA_ALLOW_HTTP=y` in `sdkconfig.defaults` enables the *OTA client* to accept HTTP sources but does not start an OTA listener server.

Use one of these methods to update firmware today:

**Option A — Web Flasher (recommended, no tools needed)**
Visit [https://ss-sauron.github.io/Heimdall/](https://ss-sauron.github.io/Heimdall/), connect your ESP32 via USB, and flash directly from the browser.

**Option B — Build from source**
```bash
idf.py build flash
```

### Planned: Wireless OTA Push

A future release will add an OTA receiver task to the firmware, enabling wireless updates over the local network using `espota.py` on port 3232. The rollback guarantee described above will apply to wireless updates as well.


---


## NVS Storage Schema

All data is stored in the `"wol"` NVS namespace. Key names are two characters by design — a raw NVS dump should not reveal field purposes.

| Key | Type | Content |
|---|---|---|
| `pv` | u8 | Provisioned flag |
| `wk` | string | WiFi SSID |
| `wp` | string | WiFi password |
| `mu` | string | MQTT broker URL |
| `mp` | u16 | MQTT broker port |
| `ma` | string | MQTT username |
| `mb` | string | MQTT password |
| `hn` | string | User-set hostname (optional) |
| `so` | string | SecureOn password (optional) |
| `hs` | blob | HMAC secret — 32 random bytes (HARDENED) |
| `ts` | blob | TOTP seed — 20 random bytes (HARDENED) |
| `rc` | u8 | WiFi slow-path reboot strike counter |

Keys `hs` and `ts` are generated once during provisioning and never transmitted after that point. They are displayed on the one-time HTML secrets page and never again — if lost, they can only be regenerated by factory-resetting and reprovisioning.

---

## Web Flasher & CI/CD Pipeline

Heimdall includes an automated CI/CD pipeline built with GitHub Actions (`.github/workflows/build.yml`) that compiles the firmware and deploys a browser-based Web Flasher to GitHub Pages.

**Architecture:**
- **Build Matrix:** The workflow compiles both `STANDARD` and `HARDENED` profiles concurrently using the official `esp-idf-ci-action`.
- **ESP Web Tools:** The flasher UI (`docs/index.html`) is built on [ESP Web Tools](https://esphome.github.io/esp-web-tools/), enabling direct-from-browser flashing via Web Serial.
- **Manifests:** Two JSON manifests (`docs/manifest_standard.json` and `docs/manifest_hardened.json`) map the compiled binaries (`bootloader.bin`, `partition-table.bin`, `heimdall-*.bin`) to their required flash offsets.
- **Artifact Flattening:** To prevent 404 errors caused by GitHub Actions preserving the build directory structure, all compiled binaries are aggressively flattened into the root artifact directory before upload.
- **Deployment Mechanics:** Pushing to the `main` branch automatically deploys the Web Flasher to GitHub Pages (which natively satisfies GitHub's default environment protection rules). Pushing a Git tag (`v1.0.0`) automatically creates a GitHub Release and attaches the compiled binaries for manual download.

---

## Development Environment

### IDE Code Intelligence (clangd)

A `.clangd` configuration file is committed at the repository root. It is **only read by the IDE language server** — never by `idf.py` or the Xtensa GCC toolchain.

**Why it exists:** The ESP-IDF build system passes Xtensa GCC-specific compiler flags (`-mlongcalls`, `-fno-shrink-wrap`, `-fstrict-volatile-bitfields`, etc.) that the IDE's clangd LLVM-based parser does not recognise. Without this file, clangd aborts flag processing early, fails to resolve the include paths, and reports false-positive errors for standard C headers (`string.h`, `stdint.h`) and all symbols they define (`memset`, `strlen`, etc.).

**What it does:**
```yaml
CompileFlags:
  CompilationDatabase: build   # location of compile_commands.json
  Remove: [-m*, -f*]           # strip GCC-only flags before clangd evaluates them
```

**Impact matrix:**

| | With `.clangd` | Without `.clangd` |
|---|---|---|
| `idf.py build` firmware | ✅ Unaffected | ✅ Unaffected |
| Flashed firmware behaviour | ✅ Identical | ✅ Identical |
| IDE error squiggles | ✅ Clean | 🟡 False positives |

For full sysroot resolution (eliminating the remaining `string.h not found` warning), also add the following to your IDE's clangd settings, substituting the path to your local Xtensa GCC installation:

```json
"clangd.arguments": [
    "--query-driver=C:/Espressif/tools/xtensa-esp-elf/<version>/xtensa-esp-elf/bin/xtensa-esp32-elf-gcc.exe"
]
```

The exact toolchain path for your machine is printed in the first line of `build/compile_commands.json`.

---

*Heimdall — watching the Bifrost since 2026.*
