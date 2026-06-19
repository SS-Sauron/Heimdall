<div align="center">

<img src="https://img.shields.io/badge/-%F0%9F%91%81%20HEIMDALL-%230a0a0a?style=for-the-badge&labelColor=0a0a0a" alt="Heimdall"/>

# 👁 HEIMDALL

**The Watchman of the Network**

*Always watching. Never sleeping. Ready to wake the dead.*

<br>

[![Version](https://img.shields.io/badge/version-v0.2.0-blueviolet?style=for-the-badge)](https://github.com/SS-Sauron/Heimdall/releases)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v6.0.1-E7352C?style=for-the-badge&logo=espressif&logoColor=white)](https://idf.espressif.com/)
[![Platform](https://img.shields.io/badge/ESP32-classic-E7352C?style=for-the-badge&logo=espressif&logoColor=white)](https://www.espressif.com/)
[![License](https://img.shields.io/badge/license-MIT-brightgreen?style=for-the-badge)](LICENSE)
[![MQTT](https://img.shields.io/badge/MQTT-TLS%208883-660066?style=for-the-badge&logo=mqtt&logoColor=white)](https://mqtt.org/)

</div>

---

<div align="center">

A compact **ESP32** firmware that stands silent watch on your MQTT broker, intercepts wake commands, and broadcasts **Wake-on-LAN magic packets** to sleeping machines on your local network.

Configure it once through the built-in captive portal — then forget it exists. Until you need it.

</div>

---

## ✦ What It Does

```
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
| 🔑 | **TOTP Authentication** — RFC 6238 compliant. Every wake command requires a valid one-time code |
| 🕵️ | **Identity Obfuscation** — MAC spoofing, fake consumer-device hostname, HMAC-derived opaque MQTT topics |
| 📡 | **Dynamic Broadcast** — Computes the correct broadcast address at runtime. Works on any subnet |
| 🔄 | **OTA Updates** — Pull firmware over HTTPS with automatic rollback on failure |
| 🛡️ | **Self-Healing** — Crash loop detection, wrong-credential recovery, WiFi timeout escape hatch |
| 🏷️ | **Custom Hostname** — Set your own device name, synced to DHCP, mDNS, and NetBIOS |

---

## ✦ Build Profiles

<div align="center">

| | STANDARD | HARDENED |
|---|:---:|:---:|
| Captive Portal Provisioning | ✅ | ✅ |
| OTA Updates | ✅ | ✅ |
| Self-Healing Recovery | ✅ | ✅ |
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

## ✦ Quick Start

**1. Flash the firmware**
```bash
git clone https://github.com/SS-Sauron/Heimdall.git
cd Heimdall
idf.py build flash monitor
```

**2. Connect to the portal**

On first boot, Heimdall creates a WiFi access point. Connect to it — your device will automatically open the configuration page. Enter your WiFi and MQTT broker credentials.

**3. Send a wake command**

Publish a payload to Heimdall's command topic:
```json
{ "mac": "AA:BB:CC:DD:EE:FF" }
```

Your machine wakes up.

> 📁 For detailed configuration, security hardening, TOTP setup, and OTA instructions — see the [`/docs`](docs/) folder.

---

## ✦ Project Structure

```
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
├── partitions.csv      # OTA-ready dual-slot partition table
└── sdkconfig.defaults  # Baseline Kconfig configuration
```

---

## ✦ Response Payload

After dispatching a magic packet, Heimdall publishes a confirmation to the response topic:

```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "status": "sent",
  "heap_free": 187432,
  "uptime_s": 3672
}
```

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
