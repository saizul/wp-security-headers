# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added

- Settings > Security Headers screen with Settings, Scan, Violations and
  Export tabs, built on the Settings API with nonces, capability checks,
  sanitising and escaping.
- Strict-Transport-Security with max-age presets, `includeSubDomains`,
  `preload` and a preload checklist (HTTPS, max-age, subdomains, redirects,
  registrable domain). Only sent over HTTPS.
- X-Content-Type-Options, Referrer-Policy, X-Frame-Options with
  `frame-ancestors` (including extra trusted origins),
  Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy.
- Permissions-Policy builder with a checkbox per feature and "nobody" or
  "this site only".
- Content-Security-Policy builder with Strict, WordPress-compatible and
  WooCommerce-compatible presets, validated sources, live preview and
  warnings, `upgrade-insecure-requests`, Report-Only and Enforce modes.
- Per-request CSP nonces added to scripts through `wp_script_attributes` and
  `wp_inline_script_attributes`.
- Built-in report endpoint `POST /wp-json/security-headers/v1/report` for
  `report-uri` and `report-to` (Reporting API), with size limits, per-client
  and global rate limits, host checks and a capped, deduplicated custom
  table; Violations screen with suggestions.
- "Scan my site": server-side request to the home page and an A-F grade with
  a fix per header.
- nginx and Apache export.
- WP-CLI: `wp security-headers status`, `scan` (`--url`, `--fail-under`,
  `--format=json`) and `export`.
- Options to send headers in wp-admin and on wp-login.php (without CSP) and
  to remove `X-Powered-By`.
- Filters: `security_headers_headers`, `security_headers_report_hosts`,
  `security_headers_client_ip`, `security_headers_capability`.
- Translation template, multisite-aware uninstall.
- PHPUnit tests on WordPress stubs, phpcs (WordPress Coding Standards), CI on
  PHP 7.4 to 8.4, POT check and a release workflow that builds the plugin zip.

[Unreleased]: https://github.com/saizul/wp-security-headers/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/wp-security-headers/releases/tag/v0.1.0
