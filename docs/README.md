# Heimdall — Technical Documentation

This document explains how Heimdall works internally: its architecture, boot sequence, component responsibilities, configuration system, security model, and operational behaviour. It assumes you have already flashed the firmware and completed provisioning. If you haven't, start with the main [README](../README.md).

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
4. [Build Profiles](#build-profiles)
5. [Configuration Reference](#configuration-reference)
6. [Network Security Model](#network-security-model)
7. [MQTT Protocol](#mqtt-protocol)
8. [Wake-on-LAN](#wake-on-lan)
9. [Self-Healing & Recovery](#self-healing--recovery)
10. [NVS Storage Schema](#nvs-storage-schema)

---

## Architecture Overview

Heimdall is built as a **component-based embedded application** on top of ESP-IDF and FreeRTOS. Each logical concern lives in its own isolated component under `components/`. Components communicate through direct function calls across clean public APIs defined in their header files — there is no global state shared between components except through the `storage` component, which acts as the single source of truth for all persisted configuration.

The runtime is **event-driven**: WiFi events, IP events, and MQTT events are dispatched by ESP-IDF's event loop to registered callbacks. FreeRTOS tasks handle the MQTT client lifecycle and the DNS server. The main task is used for sequential boot orchestration and then enters the MQTT relay health-monitor loop indefinitely.

```
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

```
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

**Crash loop detection:** On every boot, `esp_reset_reason()` is checked. If the reason is `ESP_RST_PANIC` or `ESP_RST_TASK_WDT` (genuine firmware crashes — not intentional software resets), a counter in NVS is incremented. Once that counter reaches the configured threshold (default: 5 consecutive crashes), `storage_erase_all()` is called and the device reboots into provisioning mode. Any successful WiFi connection resets the counter to zero.

**Factory reset button:** GPIO0 (the BOOT button on most ESP32 dev boards) is sampled at boot. If held for `CONFIG_WOL_FACTORY_RESET_HOLD_MS` (default: 5000 ms), all NVS credentials are erased and the device reboots into the captive portal. The detection uses a blocking polling loop with a 20 ms debounce — the entire rest of boot is paused while the button is held, which is intentional.

---

### storage

**Files:** `components/storage/storage.c`, `components/storage/storage.h`

The single NVS interface for the entire project. Every other component that needs to persist or read data does so through functions defined here — nothing else calls NVS APIs directly. This centralises all key name definitions and ensures consistent error handling across the codebase.

All NVS key names are two characters, opaque by design. A raw NVS dump should not reveal the purpose of any stored field.

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

**Files:** `components/portal/portal.c`, `components/portal/portal_html/index.html`

Runs exclusively on the first boot (or after a factory reset). Brings up a SoftAP in `WIFI_MODE_APSTA` mode (both AP and STA active simultaneously — STA is needed for the WiFi scan feature even though it stays unconnected).

**Captive portal interception uses three complementary mechanisms:**

| Mechanism | Handles |
|---|---|
| DNS redirect (dns_server) | All DNS queries → 192.168.4.1 |
| DHCP Option 114 | Advertises captive portal URI during IP assignment (Chrome, Android) |
| HTTP 303 + body | `handle_captive_redirect` returns 303 with body content (iOS requirement) |

**Provisioning flow:**
1. User connects to the SoftAP — captive portal popup appears automatically
2. Portal scans nearby WiFi networks and presents them as a selectable list
3. User enters: WiFi SSID/password, MQTT broker URL/port/credentials, optional custom hostname
4. The browser posts JSON to `POST /api/provision`; the firmware parses it with `cJSON_Parse()`
5. The portal validates all fields server-side:
   - WiFi SSID: required, 1–32 bytes
   - MQTT broker host: required, 1–128 bytes, no whitespace/control characters
   - MQTT broker scheme prefixes are stripped before storage (`mqtt://`, `mqtts://`, `tcp://`, `ssl://`, `http://`, `https://`)
   - MQTT port: numeric, defaults to 8883 if omitted
   - MQTT username/password: optional strings, max 64 bytes each; overlength values are rejected instead of truncated
   - Hostname: optional RFC 1123 label, 1–32 chars, letters/digits/hyphen, no leading or trailing hyphen
6. Credentials are written to NVS via `storage_save_credentials()`
7. If OPSEC is enabled, HMAC secret and TOTP seed are generated now and shown on a one-time HTML secrets page — **this is the only moment they are visible**
8. The user records any shown secrets and clicks the final **Start Relay** button, which posts to `/reboot` and triggers `esp_restart()`

**HTTP server:** 11 URI handlers registered on port 80. `max_uri_handlers` set to 12 for headroom. The wildcard catch-all (`/*`) is registered last and handles all OS captive-portal detection URLs.

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
- Response topic: bytes 8–15 of digest → 16 hex characters

The secret is a 32-byte random blob generated once during provisioning and stored in NVS. The same device always produces the same topics (deterministic), but the topics reveal nothing about the device's purpose or MAC address to a broker observer.

**TOTP command authentication (RFC 6238):**

Uses HMAC-SHA1 with the stored 20-byte seed and the current time counter `T = floor(unix_time / step_seconds)` (default step: 30 s). Dynamic truncation produces a 6-digit code. A ±1 window (T-1, T, T+1) accommodates up to 30 seconds of clock drift.

SNTP is required for TOTP. `opsec_sync_clock()` blocks for up to 30 seconds waiting for a successful sync. If sync fails, TOTP validation is unavailable and commands are rejected.

**Payload format with TOTP enabled:**
```
AA:BB:CC:DD:EE:FF:123456
└─── target MAC ───┘└code┘
```

---

### mqtt_relay

**Files:** `components/mqtt_relay/mqtt_relay.c`, `components/mqtt_relay/mqtt_relay.h`

The operational core. Runs indefinitely after WiFi is connected. Uses the `esp-mqtt` managed component (`espressif__mqtt`) with TLS.

**Startup sequence inside `mqtt_relay_start()`:**
1. `opsec_init()` — loads HMAC secret and TOTP seed from NVS
2. `opsec_sync_clock()` — SNTP time sync (no-op in STANDARD builds)
3. `opsec_derive_topics()` — computes command and response topic strings
4. `storage_load_credentials()` — reads MQTT broker URL, port, username, password
5. Builds broker URI: `mqtt://` for port 1883, `mqtts://` for 8883
6. Logs broker URI, MQTT username/password lengths, and whether TLS hostname verification/SNI is enabled; raw credentials are never logged
7. `esp_mqtt_client_init()` + `esp_mqtt_client_start()`

**TLS and hosted brokers:** TLS verification uses the ESP x.509 certificate bundle (`esp_crt_bundle_attach`). Hostname verification and SNI are enabled by default through the broker URI hostname. `CONFIG_MQTT_RELAY_SKIP_CERT_CN_CHECK` should stay disabled for hosted brokers such as HiveMQ Cloud because enabling it disables both certificate hostname matching and SNI.

**Event handling:**

| Event | Action |
|---|---|
| `MQTT_EVENT_CONNECTED` | Subscribe to command topic (QoS 1), publish `{"status":"online"}` retained |
| `MQTT_EVENT_SUBSCRIBED` | Call `esp_ota_mark_app_valid_cancel_rollback()` — firmware proven functional |
| `MQTT_EVENT_DATA` | Parse payload → TOTP validate (if enabled) → `wol_send_raw()` → publish response |
| `MQTT_EVENT_DISCONNECTED` | Log only — client auto-reconnects |
| `MQTT_EVENT_ERROR` | Log TLS/TCP details; on `CONNECTION_REFUSED` with bad-credentials code → `storage_erase_all()` + reboot |

**Response payload:**
```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "status": "sent",
  "free_heap": 187432,
  "uptime_s": 3672
}
```

**Health monitor loop:** Wakes every 5 minutes to log uptime at `DEBUG` level. No other logic — the MQTT client handles reconnection internally.

**Wrong MQTT credential recovery:** If the broker returns `MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED` or `MQTT_CONNECTION_REFUSE_BAD_USERNAME`, retrying forever with the same credentials is pointless. Heimdall erases all stored credentials and reboots into the captive portal, exactly as it does for wrong WiFi passwords.

---

### wol

**Files:** `components/wol/wol.c`, `components/wol/wol.h`

Constructs and broadcasts the Wake-on-LAN magic packet.

**Magic packet structure (102 bytes):**
```
Bytes  0–5:   FF FF FF FF FF FF          (sync stream)
Bytes  6–101: AA BB CC DD EE FF × 16    (target MAC repeated 16 times)
```

Sent as a UDP broadcast. The broadcast address is computed dynamically at send time from the STA interface's current IP and netmask:

```c
broadcast = ip_info.ip.addr | ~ip_info.netmask.addr
```

This works correctly on any subnet — 192.168.x.x, 10.x.x.x, 172.16.x.x, or any other. The packet is sent `SEND_REPETITIONS` times (default: 3) with a 10 ms gap between transmissions for reliability.

---

## Build Profiles

Profiles are selected via `idf.py menuconfig` or by setting Kconfig symbols in `sdkconfig.defaults`.

**STANDARD** — Default. No OPSEC features active. MQTT topics are human-readable:
```
Command topic:  wol/AA:BB:CC:DD:EE:FF
Response topic: wol/AA:BB:CC:DD:EE:FF/r
```

**HARDENED** — Enable by setting `CONFIG_WOL_PROFILE_HARDENED=y` or individually enabling the OPSEC Kconfig options. All four OPSEC features activate:
- `CONFIG_OPSEC_IDENTITY_SPOOF_MAC=y`
- `CONFIG_OPSEC_IDENTITY_FAKE_HOSTNAME=y`
- `CONFIG_OPSEC_HMAC_TOPIC=y`
- `CONFIG_OPSEC_TOTP=y`

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
| `CONFIG_PORTAL_AP_PASSWORD_FROM_MAC` | y | Derive a reproducible WPA2 portal password from the chip MAC hash |
| `CONFIG_PORTAL_TIMEOUT_SEC` | 180 | Portal timeout in seconds (0 = wait forever) |
| `CONFIG_STORAGE_NVS_NAMESPACE` | wol | NVS namespace used for all persisted configuration |

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
```
Topic:   <response_topic>
Payload: {"status":"offline"}
QoS:     1
Retain:  true
```

When the device connects successfully it publishes:
```
Topic:   <response_topic>
Payload: {"status":"online"}
QoS:     1
Retain:  true
```

This means any MQTT client subscribed to the response topic always knows the current device state without polling.

### Command Format

**STANDARD build:**
```text
AA:BB:CC:DD:EE:FF
```

**HARDENED build with TOTP:**
```
AA:BB:CC:DD:EE:FF:123456
```
The payload is a plain string: MAC address, colon separator, 6-digit TOTP code. No JSON wrapper in TOTP mode — the format is intentionally compact and non-descriptive.

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

```
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
| `hs` | blob | HMAC secret — 32 random bytes (HARDENED) |
| `ts` | blob | TOTP seed — 20 random bytes (HARDENED) |
| `rc` | u8 | WiFi slow-path reboot strike counter |

Keys `hs` and `ts` are generated once during provisioning and never transmitted after that point. They are displayed on the one-time HTML secrets page and never again — if lost, they can only be regenerated by factory-resetting and reprovisioning.

---

*Heimdall — watching the Bifrost since 2026.*
