# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Setup initial community standard files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, and Issue/PR templates).
- `scripts/wake.sh` companion script for triggering WoL packets with TOTP signatures.

### Fixed
- Corrected payload documentation format.
- Resolved minor UI and parameter naming inconsistencies.
- Eliminated redundant Kconfig properties and optimized component dependencies.

## [0.2.0] - Initial Release

### Added
- Core MQTT Relay architecture.
- Captive portal provisioning.
- OPSEC Hardening profile (HMAC topics, MAC spoofing, fake hostname).
- RFC 6238 TOTP Command Authentication.
- Dual-slot OTA application partitioning.
