# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" tab, "Report a vulnerability") on
<https://github.com/saizul/wp-security-headers>.

Include the affected version, a description and steps to reproduce. You can
expect an acknowledgement within 7 days. Please give us reasonable time to
release a fix before disclosing the issue.

Examples of what we treat as security bugs: a way to inject header lines or
directives through settings or filters, a policy the plugin builds that is
weaker than what the settings say, a way to fill or abuse the report endpoint
despite its limits, and missing capability or nonce checks.

## How the plugin protects your site

- **Admin**: the settings screen, the scan and the violations screen require
  `manage_options` (filterable with `security_headers_capability`). The
  settings form uses the Settings API (`options.php` checks the capability and
  the nonce). "Scan my site" and "Delete all stored violations" post to
  `admin-post.php` with their own nonces, checked with
  `check_admin_referer()`.
- **Input**: every setting goes through one sanitiser. Choices are checked
  against fixed lists, numbers are clamped, and every CSP source is validated
  against the CSP grammar (keywords, hashes, schemes, hosts); anything with
  `;`, `,`, quotes in the wrong place, whitespace or control characters is
  dropped, so a setting cannot add directives. Static nonces are refused.
- **Headers**: the final list is checked again before sending: header names
  must be tokens and values must not contain line breaks, even when a filter
  changed them.
- **Nonce**: 128 bits from `random_bytes()`, new on every request.
- **Output**: everything printed on the admin screens is escaped with
  `esc_html()`, `esc_attr()`, `esc_url()` or `esc_textarea()`, including
  values that come from violation reports.
- **Report endpoint**: public by design (browsers send reports without
  cookies). It is refused while CSP or reporting is off, limited to 64 KB and
  20 reports per request, rate-limited per client (HMAC of the IP, keyed with
  the site salt) and globally, accepts only reports about pages on this
  site's host, removes query strings and fragments from URLs, truncates every
  value and stores at most `report_cap` distinct violations. It never stores
  IP addresses or user agents. SQL uses `$wpdb->prepare()` throughout.
- **Scan**: the admin button only fetches the site's own home page. Arbitrary
  URLs can only be scanned from WP-CLI.
- **No tracking**, no external services, no fonts or scripts from other
  sites.
- **Uninstall** removes the options and the reports table on every site of a
  network.

Security headers reduce the impact of some attacks (XSS, clickjacking,
protocol downgrade, data leaks through referrers). They do not replace
keeping WordPress, themes and plugins updated.
