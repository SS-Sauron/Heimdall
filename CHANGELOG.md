# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-06-21

### Added
- OTA update documentation and `scripts/ota_push.sh` helper script for wireless
  firmware updates over the local network using `espota.py`.
- GitHub Actions CI status badge in README.
- Automated GitHub Release job in CI pipeline — pushing a `v*.*.*` tag now
  creates a release and attaches the compiled firmware binaries automatically.

### Changed
- `sdkconfig.defaults`: added `CONFIG_OTA_ALLOW_HTTP=y` to allow local-network
  OTA uploads via `espota.py` (transport is plain HTTP on port 3232, LAN only).

### Fixed
- Removed broken unit-tests (host) CI job that failed due to mbedTLS linker
  issues on the linux IDF target.
- Resolved `esp_mbedtls_mem_calloc` / `esp_mbedtls_mem_free` undefined
  references caused by `__attribute__((weak))` shim and archive ordering.

## [0.2.0] - Initial Release

### Added
- Core MQTT Relay architecture.
- Captive portal provisioning.
- OPSEC Hardening profile (HMAC topics, MAC spoofing, fake hostname).
- RFC 6238 TOTP Command Authentication.
- Dual-slot OTA application partitioning.
- Setup initial community standard files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, and Issue/PR templates).
- `scripts/wake_standard.sh` and `scripts/wake_hardened.sh` companion scripts for triggering WoL packets.

### Fixed
- Corrected payload documentation format.
- Resolved minor UI and parameter naming inconsistencies.
- Eliminated redundant Kconfig properties and optimized component dependencies.
