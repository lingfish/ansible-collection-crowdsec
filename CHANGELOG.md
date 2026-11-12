# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-12

### Added

- `lingfish.crowdsec.allowlist` module: manage CrowdSec centralized allowlists and their entries with `cscli allowlists`, with check mode, diff mode, exclusive entry management and refusal to touch Console-managed allowlists
- `lingfish.crowdsec.cscli` role: manage the allowlists in `cscli_allowlists` with the module
- Unit tests, `ansible-test` sanity, and integration tests against CrowdSec 1.6.8, 1.7, 1.8 and latest in containers
