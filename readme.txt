=== Security Headers ===
Contributors: saizul
Tags: security headers, content security policy, csp, hsts, permissions policy
Requires at least: 6.3
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Add and test HTTP security headers without editing server config: HSTS, CSP builder with nonces and reporting, Permissions-Policy, A-F scan.

== Description ==

Security Headers sends the HTTP security headers that scanners ask for, explains each one, and helps you roll out a Content-Security-Policy without breaking your site. No server configuration, no external services, no upsells.

**Headers**

* Strict-Transport-Security (HSTS) with max-age presets, includeSubDomains, preload and a preload checklist. Only sent over HTTPS.
* Content-Security-Policy builder with presets: Strict (nonce + strict-dynamic), WordPress-compatible and WooCommerce-compatible (Stripe, PayPal, Google Pay).
* Per-request nonces added automatically to every script WordPress prints.
* Report-Only mode with a built-in, rate-limited report endpoint and a Violations screen that suggests the change for each violation.
* Permissions-Policy builder with a checkbox per feature (camera, microphone, geolocation, payment, USB and more).
* X-Frame-Options and frame-ancestors, X-Content-Type-Options, Referrer-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy.
* Removes X-Powered-By. Optional headers for wp-admin and wp-login.php (without CSP).

**Test and export**

* "Scan my site" loads your home page from the server and grades the headers from A to F, with a fix for each one.
* Export the headers as nginx or Apache configuration.
* WP-CLI: wp security-headers status, scan (with --fail-under for CI) and export.

**Safe defaults**

Only headers that do not break sites are on after activation. HSTS, CSP and the cross-origin headers start switched off, and CSP is never sent in wp-admin.

No tracking. The only outgoing request is the scan of your own home page, when you click the button. Settings and reports are removed on uninstall (on every site of a network).

Development happens on GitHub: https://github.com/saizul/wp-security-headers. Contributions are welcome.

== Installation ==

1. Upload the plugin folder to /wp-content/plugins/, or install the zip from Plugins > Add New > Upload Plugin.
2. Activate the plugin.
3. Go to Settings > Security Headers > Scan and click "Scan my site".
4. Follow the fixes. For CSP, start in Report-Only mode and check the Violations tab before switching to Enforce.

== Frequently Asked Questions ==

= My page cache serves pages without the headers. =

Caches that serve HTML without running PHP skip WordPress headers. Configure the cache to store headers, or copy the snippets from the Export tab into your server configuration.

= Will HSTS lock visitors out? =

Only if part of the site is not available over HTTPS. Start with a short max-age, check every subdomain before using includeSubDomains, and only use preload when you are sure.

= Why is the Content-Security-Policy not sent in wp-admin? =

The block editor, the Customizer and many plugins need inline scripts in the dashboard. The other headers can still be sent there.

= Inline scripts are blocked after switching on nonces. =

Scripts printed with wp_enqueue_script(), wp_add_inline_script() and the core script tag functions get the nonce automatically. Scripts that a theme or plugin echoes directly do not; the Violations screen shows which ones they are.

= Is the report endpoint safe? =

It only accepts reports while CSP reporting is on, limits size and rate, ignores reports about other sites, stores no IP addresses and keeps a capped number of rows.

= What is removed when I delete the plugin? =

The wp_security_headers_settings, wp_security_headers_last_scan and wp_security_headers_db_version options and the security_headers_reports table, on every site of a network.

== Screenshots ==

1. Settings: HSTS, basic headers and the Permissions-Policy builder.
2. The CSP builder with presets, preview and warnings.
3. Scan: grade and fixes.
4. Violations with suggestions.

== Changelog ==

= 0.1.0 =
* First release: HSTS with preload checklist, CSP builder with presets, nonces and Report-Only reporting, report endpoint and Violations screen, Permissions-Policy builder, framing and cross-origin headers, A-F scan, nginx/Apache export, WP-CLI.

== Upgrade Notice ==

= 0.1.0 =
First release.
