# Security Headers for WordPress

[![CI](https://github.com/saizul/wp-security-headers/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/wp-security-headers/actions/workflows/ci.yml)
[![Release zip](https://github.com/saizul/wp-security-headers/actions/workflows/release-zip.yml/badge.svg)](https://github.com/saizul/wp-security-headers/actions/workflows/release-zip.yml)
[![Latest release](https://img.shields.io/github/v/release/saizul/wp-security-headers?sort=semver)](https://github.com/saizul/wp-security-headers/releases)
![PHP](https://img.shields.io/badge/PHP-7.4%20to%208.4-777bb4)
![WordPress](https://img.shields.io/badge/WordPress-6.3%2B-21759b)
[![License: GPL v2+](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Good first issues](https://img.shields.io/github/issues/saizul/wp-security-headers/good%20first%20issue?label=good%20first%20issues)](https://github.com/saizul/wp-security-headers/labels/good%20first%20issue)

**Add, test and tighten HTTP security headers in WordPress without touching
nginx or Apache.** HSTS with a preload checklist, a Content-Security-Policy
builder with nonces and Report-Only reporting, a Permissions-Policy builder,
an A-F "Scan my site" grade with fixes, and nginx/Apache export for when you
are ready to move the headers to the server.

Plugin slug: `wp-security-headers` - display name: *Security Headers*.

- Nothing that can break your site is on by default (HSTS, CSP and the
  cross-origin headers start off).
- No tracking, no external services, no upsells. The only outgoing request is
  the scan of your own home page, when you click the button.
- Every part of the header logic is a pure, unit-tested function.

## Contents

- [Features](#features)
- [Quick start (60 seconds)](#quick-start-60-seconds)
- [Rolling out a Content-Security-Policy](#rolling-out-a-content-security-policy)
- [Headers reference](#headers-reference)
- [Scan and grading](#scan-and-grading)
- [Violation reports endpoint](#violation-reports-endpoint)
- [Export to nginx or Apache](#export-to-nginx-or-apache)
- [WP-CLI](#wp-cli)
- [Hooks for developers](#hooks-for-developers)
- [FAQ](#faq)
- [Development and testing](#development-and-testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security and license](#security-and-license)

## Features

| Header | What you get |
| --- | --- |
| `Strict-Transport-Security` | max-age presets from 5 minutes to 2 years, `includeSubDomains`, `preload`, and a **preload checklist** that warns about subdomains, redirects, the registrable domain and how hard preload is to undo. Only sent over HTTPS. |
| `Content-Security-Policy` | Builder with one field per directive, **presets** (Strict, WordPress-compatible, WooCommerce-compatible), **per-request nonces** added to every script WordPress prints (`wp_script_attributes` / `wp_inline_script_attributes`), `upgrade-insecure-requests`, **Report-Only mode**, a live preview and warnings about weak spots. |
| CSP reporting | `report-uri` + `report-to` / `Reporting-Endpoints` pointing at a **built-in REST endpoint**: validated, rate-limited, deduplicated and stored in a **capped custom table**, with a **Violations screen** that suggests the exact change for each violation. |
| `Permissions-Policy` | Checkbox per feature (camera, microphone, geolocation, payment, USB, Topics API and 20+ more), "nobody" or "this site only". |
| `X-Frame-Options` / `frame-ancestors` | Same origin, nobody, or not restricted, plus extra trusted framing origins. `frame-ancestors` stays enforced even while the rest of the CSP is Report-Only. |
| `X-Content-Type-Options`, `Referrer-Policy` | `nosniff` and every Referrer-Policy value. |
| `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` | All standard values. |
| Housekeeping | Removes `X-Powered-By`. Optional headers on wp-admin and wp-login.php (without CSP). |
| Scan | "Scan my site" loads your home page server-side and grades it **A to F** with a fix per header. |
| Export | **nginx** `add_header` and **Apache** `Header always set` snippets for the current settings. |
| WP-CLI | `wp security-headers status`, `scan` (with `--fail-under` for CI) and `export`. |

## Quick start (60 seconds)

Requirements: WordPress 6.3 or newer (tested up to 7.1), PHP 7.4 or newer.

1. Download `wp-security-headers.zip` from the
   [latest release](https://github.com/saizul/wp-security-headers/releases)
   and install it from **Plugins > Add New > Upload Plugin** (or clone this
   repository into `wp-content/plugins/wp-security-headers`).
2. Activate **Security Headers**. Safe headers are sent right away:
   `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` /
   `frame-ancestors 'self'` and a Permissions-Policy that switches off
   camera, microphone, location and other unused features.
3. Go to **Settings > Security Headers > Scan** and click **Scan my site**
   to see your grade and what to fix.
4. On HTTPS sites, turn on **HSTS** with a short max-age, check the site,
   then raise it to 1 year.
5. Set the CSP mode to **Report-Only**, browse your site for a few days and
   work through **Violations**. Then switch to **Enforce**.

Check the result from a terminal:

```bash
curl -sI https://example.com/ | grep -iE 'strict|content-security|x-frame|referrer|permissions|x-content|cross-origin'
wp security-headers scan
```

## Rolling out a Content-Security-Policy

CSP is the header that stops cross-site scripting, and the one most likely to
break a site if you switch it on blindly. The plugin is built around a safe
rollout:

1. **Pick a preset** and click **Load preset**:
   - **WordPress-compatible**: `'self'` plus `'unsafe-inline'` for scripts and
     styles, images from any HTTPS host, YouTube and Vimeo embeds. Works with
     most themes and plugins.
   - **WooCommerce-compatible**: the above plus Stripe, PayPal and Google Pay
     (`js.stripe.com`, `hooks.stripe.com`, `api.stripe.com`, `*.paypal.com`,
     `pay.google.com`).
   - **Strict**: Google's "strict CSP" with a nonce and `'strict-dynamic'`.
     Scripts run only if WordPress printed them with the nonce (and whatever
     they load). Best for sites where you control the theme and plugins.
2. Set **Mode** to **Report-Only**. Browsers report what *would* be blocked;
   nothing breaks.
3. Open **Violations**. Each distinct violation is listed once with a hit
   counter and a suggestion, for example *"If you trust
   https://cdn.example.com, add it to script-src."*
4. Edit the directives, repeat until the list stays empty, then switch to
   **Enforce**.

### Nonces

With **Add a nonce** switched on, every request gets a fresh 128-bit nonce.
It is added to `script-src` and, through the core filters
`wp_script_attributes` and `wp_inline_script_attributes`, to every script tag
WordPress prints with `wp_enqueue_script()`, `wp_add_inline_script()`,
`wp_print_script_tag()` and `wp_print_inline_script_tag()`. Scripts that a
theme or plugin echoes directly (`echo '<script>...'`) do not get the nonce;
the Violations screen shows you which ones they are.

When a nonce is present, browsers ignore `'unsafe-inline'` in `script-src`.
The plugin warns you about this in the preview.

CSP is only sent on the front end. wp-admin and the block editor rely on
inline scripts and are left alone.

## Headers reference

| Setting | Header sent | Default |
| --- | --- | --- |
| HSTS | `Strict-Transport-Security: max-age=31536000[; includeSubDomains][; preload]` (HTTPS only) | off |
| X-Content-Type-Options | `X-Content-Type-Options: nosniff` | on |
| Referrer-Policy | `Referrer-Policy: strict-origin-when-cross-origin` | on |
| Framing | `X-Frame-Options: SAMEORIGIN` + `Content-Security-Policy: frame-ancestors 'self'` | same origin |
| Permissions-Policy | `Permissions-Policy: camera=(), microphone=(), geolocation=(), ...` | common features off |
| COOP / CORP | `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` | off |
| CSP | `Content-Security-Policy` or `Content-Security-Policy-Report-Only`, plus `Reporting-Endpoints` | off (WordPress preset loaded) |
| X-Powered-By | removed | on |
| Areas | front end always; wp-admin and wp-login.php optional (never CSP) | front end |

Preload note: when you tick **preload**, the plugin also enforces
`includeSubDomains` and a max-age of at least one year, because the preload
list rejects anything weaker.

## Scan and grading

**Scan my site** (Settings > Security Headers > Scan) makes a GET request from
your server to your home page, follows up to three redirects, and grades the
headers it receives. Because it looks at the real response, it also catches
headers added or removed by your host, page cache or CDN.

| Check | Points |
| --- | --- |
| Content-Security-Policy (enforced, restricts scripts; minus points for `'unsafe-inline'` without nonce, `'unsafe-eval'`, wildcard sources, missing `object-src`/`base-uri`; Report-Only only earns 5) | 25 |
| Strict-Transport-Security (at least 6 months for full points) | 20 |
| `frame-ancestors` or `X-Frame-Options` | 15 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |
| Cross-Origin-Opener-Policy | 5 |
| Cross-Origin-Resource-Policy | 5 |

Grades: **A** 90+, **B** 75+, **C** 60+, **D** 45+, **E** 30+, **F** below.
`X-Powered-By`, `Server` versions and an active `X-XSS-Protection` are listed
as information without costing points.

## Violation reports endpoint

```
POST /wp-json/security-headers/v1/report
```

- Accepts `application/csp-report` (from `report-uri`) and
  `application/reports+json` (from `report-to` / the Reporting API), plus
  `application/json`.
- Answers `204` when stored, `400` for invalid JSON or reports about pages of
  another site, `403` while reporting is off, `413` above 64 KB, `415` for
  other content types, and `429` with `Retry-After` when rate-limited.
- **Rate limits**: per visitor (default 30 reports per minute, keyed by an
  HMAC of the IP address, never the address itself) and 600 per minute for
  the whole site.
- **Storage**: `{prefix}security_headers_reports`. Repeated violations
  increase a counter instead of adding rows; the table keeps at most
  *report cap* rows (default 1000) and deletes the least recently seen
  first. Query strings and fragments are removed from URLs. No IP addresses
  or user agents are stored.
- Try it with `examples/send-test-report.sh`.

## Export to nginx or Apache

**Settings > Security Headers > Export** (or `wp security-headers export`)
prints the current headers as server configuration:

```nginx
add_header Strict-Transport-Security "max-age=31536000" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Permissions-Policy "browsing-topics=(), camera=(), display-capture=(), geolocation=(), hid=(), microphone=(), midi=(), serial=(), usb=()" always;
```

```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000"
    Header always set X-Content-Type-Options "nosniff"
</IfModule>
```

Full samples: [`examples/nginx-security-headers.conf`](examples/nginx-security-headers.conf)
and [`examples/apache-security-headers.conf`](examples/apache-security-headers.conf).
Nonces cannot be exported (a static config cannot create one per request), so
keep the CSP in the plugin if you use them.

## WP-CLI

```bash
wp security-headers status                  # headers for a front-end request + warnings
wp security-headers status --area=login --format=json
wp security-headers scan                    # grade the home page, store the result
wp security-headers scan --url=https://example.com/checkout/ --format=json
wp security-headers scan --fail-under=B     # exit status 1 below B (CI, monitoring)
wp security-headers export --server=nginx > /etc/nginx/snippets/security-headers.conf
```

See [`examples/github-actions-scan.yml`](examples/github-actions-scan.yml)
for a nightly check.

## Hooks for developers

| Hook | Type | Use |
| --- | --- | --- |
| `security_headers_headers` | filter | `( array $headers, string $area, array $settings )`. Edit the name/value pairs before they are sent. Malformed entries and values with line breaks are dropped. |
| `security_headers_report_hosts` | filter | Hosts whose pages may send violation reports (default: home and site URL hosts). |
| `security_headers_client_ip` | filter | Client IP used for rate limiting (default `REMOTE_ADDR`). |
| `security_headers_capability` | filter | Capability for the settings, scan and violations (default `manage_options`). |
| `security_headers_exit_after_redirect` | filter | Return false in tests to stop `exit` after admin redirects. |

`Saizul\SecurityHeaders\Csp\Policy` is a small immutable CSP parser and
serializer you can use in filters (`Policy::parse()`, `->add()`,
`->serialize()`). See [`examples/mu-plugin-filters.php`](examples/mu-plugin-filters.php).

## FAQ

**My page cache serves pages without the headers.**
Caches that serve HTML straight from disk or from the web server (for example
some modes of WP Super Cache, W3 Total Cache disk enhanced, nginx FastCGI
cache or Varnish without header storage) skip PHP, so `send_headers` never
runs. Either configure the cache to store headers, or use the Export tab to
put the static headers in your server config. The scan shows what visitors
really get.

**HSTS is not sent although the site uses HTTPS.**
HSTS is only sent when WordPress detects HTTPS (`is_ssl()`). Behind a load
balancer or CDN that terminates TLS, make sure WordPress sees the request as
HTTPS (for example by honouring `X-Forwarded-Proto` in `wp-config.php`, as
your host documents), or send HSTS from the proxy.

**Does the nonce work with full-page caching?**
A cached page carries the nonce of the request that created it. That is only
consistent if the cache stores and replays the response headers together with
the HTML. If it does not, use a policy without nonces (WordPress-compatible
preset) on cached pages.

**Will HSTS lock me out?**
Only if part of your site is not on HTTPS. Start with 5 minutes or 1 day,
check every subdomain when using `includeSubDomains`, and only tick preload
when you are sure. The preload checklist lists what to verify.

**Why is CSP not sent in wp-admin?**
The block editor, the Customizer and many plugins use inline scripts and
`eval()` in the dashboard. A strict policy there breaks things without much
gain; the other headers can still be sent in wp-admin.

**Another plugin or my host already sends some of these headers.**
The plugin replaces headers with the same name sent earlier by PHP. Headers
added later by the web server or a CDN are added on top, which can create
duplicates; the scan shows the final result. Switch off the header in one of
the two places.

**Is the report endpoint a risk?**
It is public by design (browsers send reports anonymously), so it is
size-limited, rate-limited, only accepts reports about your own pages, stores
cleaned values in a capped table and is off while CSP is off.

**Does it work on multisite?**
Yes, settings and the reports table are per site, and uninstall cleans up
every site.

## Development and testing

```bash
composer install
composer test     # PHPUnit on light WordPress stubs (no database needed)
composer phpcs    # WordPress Coding Standards + PHPCompatibilityWP (7.4+)
composer lint     # php -l on every file
composer make-pot # regenerate languages/wp-security-headers.pot
```

CI runs on PHP 7.4 to 8.4. See [CONTRIBUTING.md](CONTRIBUTING.md) for the code
layout.

## Roadmap

Ideas, many of them good first issues:

- "Copy to clipboard" buttons on the Export tab.
- One-click "Allow this" on a violation (adds the suggested source).
- Export the violations as CSV.
- `wp security-headers violations [--format=json]` and `violations clear`.
- `Cross-Origin-Embedder-Policy` with a clear warning about what it breaks.
- Per-post-type or per-URL CSP overrides in the UI.
- Detect duplicate headers sent by the server or CDN in the scan.
- Hash-based CSP for known inline scripts.
- Caddy and IIS (`web.config`) export formats.

## Contributing

Contributions of every size are welcome: bug reports, presets for popular
plugins, translations, docs and code. Start with
[CONTRIBUTING.md](CONTRIBUTING.md), which lists beginner tasks with the exact
files to touch, and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security and license

Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Licensed under the
[GNU General Public License v2.0 or later](LICENSE).
