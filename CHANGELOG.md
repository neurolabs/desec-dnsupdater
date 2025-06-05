# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Randomization of delays as proposed by https://talk.desec.io/t/erratic-502-bad-gateway-responses-on-update-dedyn-io/1312/18
- Bigger delay after update as proposed by https://talk.desec.io/t/erratic-502-bad-gateway-responses-on-update-dedyn-io/1312/18

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.1.3] - 2025-06-05

### Added

- Added documentation about the requirement for EUI-64 IPv6 addresses
- Added debug log output for detected IPv4 address, analogous to detected IPv6 address
- Added debug log for interface parameter unspecified

### Changed

- open log file for appending instead of for writing
- only configure cli logging for desec lib if log target is stdout

### Deprecated

### Removed

### Fixed

- Handled special case of empty subdomain (`-s ""`)
- Fixed error in IPv6 update path where IPv6 address was compared against IPv4 address

### Security

## [0.1.2] - 2025-06-05

### Added

- Added a changelog
- Added some more Trove Classifiers in `pyproject.toml`
- Added github project and issue links in `pyproject.toml`

### Changed

- Updated to poetry 2
- Switched to standard src structure
- Standardized pyproject.toml according to `poetry check`
- Cleaned up `pyproject.toml`

## [0.1.1] - 2025-06-05

Initial release