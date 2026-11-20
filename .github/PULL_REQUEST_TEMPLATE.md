## What does this change?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Type

- [ ] Bug fix
- [ ] Header logic (HeaderBuilder, CSP policy, presets, Permissions-Policy, HSTS)
- [ ] Scan, grading or export
- [ ] Report endpoint or Violations screen
- [ ] Admin screens, WP-CLI or hooks
- [ ] Documentation or translations
- [ ] Tests or tooling

## Checklist

- [ ] Header decisions stay in `src/HeaderBuilder.php` / `src/Csp/` and have tests.
- [ ] New settings are sanitised in `src/Sanitizer.php` and tested.
- [ ] Output is escaped; forms check a capability and a nonce.
- [ ] No remote requests (other than the site scan), no tracking, no new runtime dependencies.
- [ ] `composer test` and `composer phpcs` pass.
- [ ] `composer make-pot` run and `languages/wp-security-headers.pot` committed (if strings changed).
- [ ] `CHANGELOG.md` updated under "Unreleased".

## How did you test it on a real site?

<!-- WordPress and PHP versions, web server, cache, `curl -sI` output before and after. -->
