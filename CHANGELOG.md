# Changelog

All notable changes to `laravel-security-headers` will be documented in this file.

## v2.1.0 - 2026-10-09

The CSP nonce is now Laravel's Vite nonce:

- the middleware sets a fresh `Vite::useCspNonce()` at the start of every request (no reuse on Octane workers)
- `@vite` tags, Vite prefetching and Livewire scripts get the nonce automatically
- the header reads the nonce after the response is built, so a page cache that restores the nonce of its cached markup stays in sync (laravel-page-cache 1.3)
- `csp_nonce()`, `@cspNonce` and the `security-headers.nonce` binding return the same value

## v2.0.0 - 2026-06-21

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-security-headers/compare/v1.0.1...v2.0.0

## v1.0.1 - 2026-06-20

chore: ignore the .phpunit.cache directory.

## v1.0.0 - 2026-06-20

Initial release.
