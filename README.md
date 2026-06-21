<div align="center">

<img src="https://img.shields.io/badge/-%F0%9F%91%81%20HEIMDALL-%230a0a0a?style=for-the-badge&labelColor=0a0a0a" alt="Heimdall"/>

# 👁 HEIMDALL

**The Watchman of the Network**

*Always watching. Never sleeping. Ready to wake the dead.*

<br>

[![Version](https://img.shields.io/badge/version-v0.3.0-blueviolet?style=for-the-badge)](https://github.com/SS-Sauron/Heimdall/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/SS-Sauron/Heimdall/build.yml?style=for-the-badge)](https://github.com/SS-Sauron/Heimdall/actions/workflows/build.yml)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v6.0.1-E7352C?style=for-the-badge&logo=espressif&logoColor=white)](https://idf.espressif.com/)
[![Platform](https://img.shields.io/badge/ESP32-classic-E7352C?style=for-the-badge&logo=espressif&logoColor=white)](https://www.espressif.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-brightgreen?style=for-the-badge)](LICENSE)
[![MQTT](https://img.shields.io/badge/MQTT-TLS%208883-660066?style=for-the-badge&logo=mqtt&logoColor=white)](https://mqtt.org/)

</div>

---

<div align="center">

A compact **ESP32** firmware that stands silent watch on your MQTT broker, intercepts wake commands, and broadcasts **Wake-on-LAN magic packets** to sleeping machines on your local network.

Configure it once through the built-in captive portal — then forget it exists. Until you need it.

</div>

---

## ✦ What It Does

```text
  [ MQTT Broker ] ──── TLS ────► [ Heimdall / ESP32 ] ──── UDP ────► [ Sleeping PC ]
                                         👁
                                    Always Watching
```

You send a command. Heimdall wakes your machine. That's it.

---

## ✦ Features

| | Feature |
|---|---|
| 🌐 | **Captive Portal Provisioning** — Connect, configure, done. Full DNS redirect on iOS, Android & Windows |
| 🔐 | **Two Build Profiles** — STANDARD for simplicity, HARDENED for OPSEC-grade deployments |
| 🔑 | **TOTP Authentication** — RFC 6238 compliant. Every wake command requires a valid one-time code (HARDENED only) |
| 🕵️ | **Identity Obfuscation** — MAC spoofing, generic device hostname, HMAC-derived opaque MQTT topics (HARDENED only) |
| 📡 | **Dynamic Broadcast** — Computes the correct broadcast address at runtime. Works on any subnet |
| 🔄 | **OTA Ready** — Dual-slot partition table with automatic rollback on failure |
| 🛡️ | **Self-Healing WiFi** — Distinguishes wrong credentials from transient outages. Never bounces into setup mode during a router restart |
| 🏷️ | **Custom Hostname** — Set your own device name, synced to DHCP, mDNS, and NetBIOS |

---

## ✦ Build Profiles

<div align="center">

| | STANDARD | HARDENED |
|---|:---:|:---:|
| Captive Portal Provisioning | ✅ | ✅ |
| OTA Dual-Slot Partition | ✅ | ✅ |
| Self-Healing WiFi Recovery | ✅ | ✅ |
| Dynamic Broadcast Address | ✅ | ✅ |
| TOTP Command Authentication | ❌ | ✅ |
| HMAC-Derived MQTT Topics | ❌ | ✅ |
| MAC Address Spoofing | ❌ | ✅ |
| Hostname Obfuscation | ❌ | ✅ |

</div>

---

## ✦ Hardware

- **ESP32** (classic) development board
- Connected to your local WiFi network
- Access to an MQTT broker (local or cloud, port 1883 or 8883 TLS)

That's it. No extra components required.

---

## ✦ Prerequisites

Before building, make sure the ESP-IDF environment is installed and exported in your shell.

| Requirement | Version | Notes |
|---|---|---|
| [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) | v6.0.1 | Use the official installer or `install.sh` flow |
| Python | 3.8+ | Installed by the ESP-IDF tools setup |
| Xtensa ESP32 toolchain | ESP-IDF managed | Installed by `install.sh` / the ESP-IDF installer |
| IDF Component Manager | ESP-IDF bundled | Resolves managed components during build |

Check the active environment with:

```bash
idf.py --version
```

---

## ✦ Quick Start

**1. Clone the project**

```bash
git clone https://github.com/SS-Sauron/Heimdall.git
cd Heimdall
idf.py set-target esp32
```

**2. Select a build profile (optional)**

The default profile is STANDARD. To switch to HARDENED before building:

```bash
idf.py menuconfig
```

Navigate to **WoL Relay → Build Profile**, choose the profile, save, and exit.

**3. Build, flash, and monitor**

```bash
idf.py build flash monitor
```

**4. Connect to the portal**

On first boot, Heimdall creates a WPA2-protected WiFi access point. The SSID and permanent portal password are printed to the serial monitor when serial provisioning output is enabled. Connect from your phone or laptop — the configuration page opens automatically on iOS, Android, and Windows.

<div align="center">
  <img src="resources/Portal.png" alt="Heimdall Captive Portal Configuration" width="400"/>
</div>

After saving, the device reboots into relay mode. Use the successful startup log below to confirm WiFi, TLS, and MQTT are all working.

**5. Send a wake command**

Publish the target machine's MAC address as a plain-text payload to Heimdall's command topic:

```text
AA:BB:CC:DD:EE:FF
```

Your machine wakes up.

Publish a different target MAC to the same command topic to wake a different WoL-capable device on the same LAN. Heimdall does not store a single target PC MAC; the payload selects the target for each command.

> See the **[Usage & Operation](#-usage--operation)** section below for details on how to use the provided bash scripts to automate this, and how to find your specific command topic.

---

## ✦ MQTT Broker

Heimdall works with hosted or local MQTT brokers. Use port `8883` for MQTT over TLS, or port `1883` for plain MQTT on a trusted local network.

Example hosted brokers include [HiveMQ Cloud](https://www.hivemq.com/mqtt-cloud-broker/) and [Adafruit IO](https://io.adafruit.com). These are examples only; any compatible MQTT broker should work.

In the portal, enter the broker hostname such as:

```text
example-cluster.s1.eu.hivemq.cloud
```

Do not include credentials, paths, or real secrets in the broker field. Scheme prefixes such as `mqtts://`, `mqtt://`, `https://`, and `tcp://` are accepted but stripped before storage.

---

## ✦ First Provisioning Boot

```console
I (645) main: Not provisioned — starting captive portal
I (646) main: Portal password: <HIDDEN>  (permanent — same after every reset)
I (660) portal: Portal AP  SSID: NETGEAR-XXXXXX
I (663) portal: Portal AP  Auth: WPA2
I (1109) portal: SoftAP started  SSID: NETGEAR-XXXXXX  Auth: WPA2  DHCP opt-114: http://192.168.4.1/
I (1117) dns_server: Listening on UDP port 53 — redirect → 192.168.4.1
I (1122) dns_server: Started — redirecting all A queries to 192.168.4.1
I (1135) portal: HTTP server ready on port 80
I (1135) portal: Portal ready — waiting for credentials
I (10709) esp_netif_lwip: DHCP server assigned IP to a client, IP is: 192.168.4.2
I (123605) portal: Stripped scheme prefix from broker URL: 'https://xxx.eu.hivemq.cloud' → 'xxx.eu.hivemq.cloud'
I (123618) storage: Credentials saved successfully
I (123619) storage: Hostname saved: test-relay-name
I (137113) portal: Credentials saved — rebooting into relay mode
```

---

## ✦ Successful Relay Startup

After provisioning valid WiFi and MQTT credentials, the next reboot should move past the portal and into relay mode. The important success markers are: WiFi gets an IP address, TLS validates the broker certificate, MQTT connects, and the command topic subscription is confirmed.

<div align="center">
  <img src="resources/relay-start.jpeg" alt="Heimdall relay startup confirmation screen" width="360"/>
</div>

```console
I (646) identity: Hostname loaded from NVS: test-relay
I (649) main: Credentials found — starting relay
I (2875) wifi_sta: Got IP: <local-ip>
I (2876) main: WiFi connected
I (2879) main: Starting MQTT relay
I (2881) opsec: Command  topic: wol/<device-mac>
I (2885) opsec: Response topic: wol/<device-mac>/r
I (2893) mqtt_relay: Connecting to MQTT broker: mqtts://<cluster>.hivemq.cloud:8883
I (2900) mqtt_relay: MQTT credential lengths: username=<len> password=<len>
I (2906) mqtt_relay: TLS hostname verification/SNI: enabled via broker URI hostname
I (2917) mqtt_relay: MQTT client started — relay is active
I (3702) esp-x509-crt-bundle: Certificate validated
I (4895) mqtt_relay: MQTT connected — subscribing to: wol/<device-mac>
I (5002) mqtt_relay: Subscription confirmed (msg_id=22951)
```

If the log reaches `MQTT connected` and `Subscription confirmed`, Heimdall is online and waiting for wake commands on the command topic shown above.

> 📁 For detailed configuration, security hardening, TOTP setup, OTA instructions, and future feature planning — see the [`/docs`](docs/) folder and [roadmap](docs/heimdall_feature_roadmap.md).

---

## ✦ Usage & Operation

Once Heimdall is successfully provisioned and connected to your MQTT broker, you can start sending wake commands.

> [!IMPORTANT]
> **Don't mix up your MAC addresses!**
> - **Topic MAC:** The MAC address of the *Heimdall ESP32 device*. This defines *where* the command is sent.
> - **Payload MAC:** The MAC address of the *Sleeping PC* you want to wake. This defines *what* is woken up.

### Finding Your Command Topic

The topic Heimdall subscribes to depends on the selected build profile.

**STANDARD build**

```text
Command:  wol/<device-mac>
Response: wol/<device-mac>/r
```

`<device-mac>` is the ESP32 station MAC printed in the serial monitor.

**HARDENED build**

```text
Command:  <16-character-hmac-topic>
Response: <16-character-hmac-response-topic>
```

HARDENED topics are opaque strings derived from the device MAC and a secret generated during provisioning. They are printed to the serial monitor during relay startup.

### Using the Trigger Scripts

The repository includes ready-to-use Bash scripts that format the MQTT payload and handle the `mosquitto_pub` command for you.

**Prerequisites:** You must have `mosquitto-clients` installed (and `oathtool` if using the hardened script).

**STANDARD Script Usage:**
```bash
./scripts/wake_standard.sh <broker> <port> <topic> <target-mac> [user] [pass]
```
*Example:* `./scripts/wake_standard.sh mqtt.example.com 8883 "wol/AA:BB:CC:11:22:33" 99:88:77:66:55:44`

**HARDENED Script Usage (with TOTP):**
```bash
./scripts/wake_hardened.sh <broker> <port> <topic> <target-mac> <totp-secret> [user] [pass]
```
*Example:* `./scripts/wake_hardened.sh mqtt.example.com 8883 "a1b2c3d4e5f6g7h8" 99:88:77:66:55:44 "JBSWY3DPEHPK3PXP"`

### Response Payload

After dispatching a magic packet, Heimdall publishes a confirmation to the response topic:

```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "status": "sent",
  "free_heap": 187432,
  "uptime_s": 3672
}
```

| Field | Description |
|---|---|
| `mac` | The target MAC address that the Wake-on-LAN magic packet was dispatched to. |
| `status` | Confirmation that the packet was successfully broadcast to the local network. |
| `free_heap` | The available RAM on the ESP32 in bytes. Useful for monitoring device health. |
| `uptime_s` | Total time the ESP32 has been continuously running in seconds since the last reboot. |

### TOTP Setup (HARDENED only)

When TOTP is enabled, every wake command must append a valid 6-digit time-based code to the target MAC address:

```text
AA:BB:CC:DD:EE:FF:123456
```

The TOTP seed is generated during provisioning and shown **once** on the portal secrets page as a Base32 value plus an `otpauth://` URI. Save it immediately. If it is lost, factory reset and reprovision the device to generate a new seed.

Any RFC 6238-compatible authenticator app or trigger script can generate codes from that seed.

---

## ✦ Over-The-Air (OTA) Updates

Heimdall supports dual-slot OTA updates with automatic rollback. You don't need to plug the ESP32 into your computer to update the firmware.

If `CONFIG_OTA_ALLOW_HTTP=y` is enabled in your `sdkconfig.defaults`, you can flash a new build over your local network using the provided script:

```bash
./scripts/ota_push.sh --host <esp32-ip-address> [--bin build/wol_relay.bin]
```

> [!WARNING]
> The OTA transport is plain HTTP (port 3232) and should only be used on a trusted local network. If the new firmware crashes upon boot, the ESP32 will automatically reboot and roll back to the previous working firmware slot.

---

## ✦ Factory Reset

To wipe stored credentials and return to provisioning mode:

1. Hold the **BOOT** button for 5 seconds.
2. Wait for the factory reset confirmation in the serial monitor.
3. The device erases the `wol` NVS namespace and reboots into the captive portal.

This works during normal relay operation and after provisioning mistakes.

---

## ✦ Project Structure

```text
Heimdall/
├── components/
│   ├── dns_server/     # Captive portal DNS redirect
│   ├── identity/       # MAC spoofing & hostname obfuscation
│   ├── mqtt_relay/     # MQTT client & WoL dispatch core
│   ├── opsec/          # HMAC topics, TOTP, SNTP
│   ├── portal/         # Provisioning web server
│   ├── storage/        # NVS credential persistence
│   ├── wifi_sta/       # WiFi station with self-healing
│   └── wol/            # Magic packet builder & broadcaster
├── main/               # Boot sequence & orchestration
├── resources/          # README images and visual design assets
├── scripts/            # MQTT trigger helpers and Windows WoL setup helper
├── partitions.csv      # OTA-ready dual-slot partition table
└── sdkconfig.defaults  # Baseline Kconfig configuration
```

---

## ✦ Contributing

Bug reports, feature requests, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening larger changes.

---

<div align="center">

## ✦ Built With

[![C](https://img.shields.io/badge/C-99-A8B9CC?style=for-the-badge&logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C99)
[![FreeRTOS](https://img.shields.io/badge/FreeRTOS-embedded-brightgreen?style=for-the-badge)](https://www.freertos.org/)
[![mbedTLS](https://img.shields.io/badge/mbedTLS-3.x-003865?style=for-the-badge)](https://tls.mbed.org/)
[![lwIP](https://img.shields.io/badge/lwIP-network%20stack-0078D4?style=for-the-badge)](https://savannah.nongnu.org/projects/lwip/)

---

*Heimdall watches the Bifrost — the bridge between realms.*
*This watches your network. Same job, smaller board.*

<br>

**[ [Documentation](docs/) · [Releases](https://github.com/SS-Sauron/Heimdall/releases) · [License](LICENSE) ]**

</div>
