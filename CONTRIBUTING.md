# Contributing

Thanks for helping improve Security Headers. Bug reports, fixes, presets,
tests, documentation and translations are all welcome, and first-time
contributors are especially welcome: the header logic is a set of small pure
classes, and every one of them has tests.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to help

- **Pick a beginner task** from the list below or from issues labelled
  [`good first issue`](https://github.com/saizul/wp-security-headers/labels/good%20first%20issue).
  Comment on the issue first so two people do not work on the same thing.
- **Report a bug** with the "Bug report" template. Include the output of
  `curl -sI https://your-site/` (remove anything private) and
  `wp security-headers status --format=json`.
- **Share a working CSP** for a popular theme or plugin (page builders,
  analytics, chat widgets, payment gateways). Those become presets or README
  recipes.
- **Translate** the plugin: `languages/wp-security-headers.pot` is the
  template.

Security problems go to the private channel in [SECURITY.md](SECURITY.md),
not to public issues.

## Good first issues

Each task is small, has a clear "done" and touches one or two files. Tests go
in `tests/Unit/`.

1. **Copy buttons on the Export tab.** In `src/Admin/Tools.php::render_export()`,
   add a "Copy" button under each textarea that uses
   `navigator.clipboard.writeText()` (inline script, no build step) and shows
   a translatable "Copied" message. Keep the read-only textarea as fallback.
2. **`wp security-headers violations`.** Add a subcommand to
   `src/Cli/Command.php` that lists `Store::rows()` as a table or JSON, with a
   `clear` sub-action that asks for confirmation (`WP_CLI::confirm()`). Test it
   in `tests/Unit/CliTest.php` with the `FakeWpdb` stub.
3. **Detect duplicate headers in the scan.** In `src/Grader.php`, add an
   `info` finding when a header such as `X-Frame-Options` or
   `Strict-Transport-Security` appears more than once (the normalised headers
   are already lists). Add cases to `tests/Unit/GraderTest.php`.
4. **CSV export of violations.** Add an admin-post handler in
   `src/Admin/Tools.php` (capability + nonce, like `handle_clear()`) that
   streams the rows as CSV, and a button on the Violations tab. Test the CSV
   building as a pure static method.
5. **Caddy export.** Add `Export::caddy()` that prints a `header { }` block,
   with tests in `tests/Unit/ScannerExportTest.php`, and a third textarea on
   the Export tab.
6. **"Allow this" link on a violation.** For rows whose suggestion is "add
   ORIGIN to DIRECTIVE", add a button that appends the origin to that
   directive (admin-post, capability + nonce, through `Sanitizer::directives()`).
   Put the "what to add" logic in `src/Reports/Suggest.php` as a pure method
   that returns `array( directive, source )` and test it.
7. **More Permissions-Policy features.** Check the list in
   `src/PermissionsPolicy.php::features()` against the current
   [W3C feature list](https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md)
   and add missing standardised features with a one-line description.
8. **Translate the plugin into your language** with Poedit or Loco Translate
   from `languages/wp-security-headers.pot`, and open a PR with the `.po`
   file.

## Development setup

```bash
git clone https://github.com/saizul/wp-security-headers.git
cd wp-security-headers
composer install
composer test           # PHPUnit on WordPress stubs
composer phpcs          # WordPress Coding Standards + PHPCompatibilityWP
composer phpcbf         # fix what phpcs can fix automatically
composer lint           # php -l
composer make-pot       # regenerate the translations template
```

PHP 7.4 or newer is required. Dependencies are resolved for PHP 7.4
(`config.platform`), so the same lock file works across the CI matrix. There
is no JavaScript build.

To try the plugin in a real site, symlink or copy the folder into
`wp-content/plugins/` of a local WordPress install (wp-env, LocalWP, DDEV or
similar), activate it and check the response with
`curl -sI http://localhost:8888/`. Send sample reports with
`sh examples/send-test-report.sh http://localhost:8888` (edit the host in
`examples/reports/*.json` first).

## Where things go

- `src/HeaderBuilder.php` - **all** decisions about which headers are sent.
  A pure function of the settings and a request context; keep it that way.
- `src/Csp/Policy.php` - CSP parsing, sanitising, serialising and warnings.
  `src/Csp/Presets.php` - the presets.
- `src/PermissionsPolicy.php`, `src/Hsts.php` - Permissions-Policy features,
  HSTS value and preload checklist.
- `src/Sanitizer.php`, `src/Settings.php` - the single option and its
  sanitiser.
- `src/Grader.php`, `src/Scanner.php` - A-F grading and the server-side scan.
- `src/Export.php` - nginx and Apache snippets.
- `src/Reports/` - report endpoint, parser, rate limiter, capped table and
  suggestions.
- `src/Frontend.php`, `src/Nonce.php` - sending headers and the CSP nonce.
- `src/Admin/` - settings screen and the Scan, Violations and Export tabs.
- `src/Cli/Command.php` - `wp security-headers`.
- `tests/Stubs/` - light WordPress and WP-CLI stubs, including `FakeWpdb`
  which records SQL. Add a stub when you use a new WordPress function; keep it
  minimal and record calls in `WpStubs` so tests can assert them.

## Coding standards

- WordPress Coding Standards (`composer phpcs` must pass) and PHP 7.4
  compatibility: no union types, no `match`, no named arguments, no
  constructor promotion, no `str_contains()`.
- Escape all output, sanitise all input, check capabilities and nonces.
- No remote requests (other than the scan of the site itself), no tracking,
  no upsells, no new runtime dependencies.
- Translatable strings use the `wp-security-headers` text domain.
- Keep pull requests focused. Update `CHANGELOG.md` under "Unreleased".

## Pull requests

1. Fork the repository and create a branch (`feature/copy-buttons`,
   `fix/report-host-check`).
2. Make your change with tests.
3. Run `composer test`, `composer phpcs` and, if strings changed,
   `composer make-pot`, and commit the regenerated file.
4. Open the pull request and fill in the checklist.

CI must pass before a pull request is merged.

## Releases

Maintainers bump the version in `wp-security-headers.php` (header and
`WP_SECURITY_HEADERS_VERSION`), `src/Plugin.php` (`VERSION`), `readme.txt`
(`Stable tag`) and `CHANGELOG.md`, then publish a GitHub release tagged
`vX.Y.Z`. The release workflow checks that the versions match, builds
`wp-security-headers.zip` and attaches it to the release.
