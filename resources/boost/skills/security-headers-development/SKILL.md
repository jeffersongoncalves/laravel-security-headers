---
name: security-headers-development
description: Development guide for laravel-security-headers, a package that stamps a configurable set of baseline security headers (including a fully configurable Content-Security-Policy and HSTS) onto HTTP responses via a single middleware.
---

# Security Headers Development Skill

## When to use this skill

- When developing or extending the laravel-security-headers package
- When adding a new managed header or CSP directive default
- When changing how the CSP string is assembled from config
- When adjusting the HSTS gating logic (secure / environment)
- When writing tests for the middleware
- When debugging why a header is or isn't present on a response

## Setup

### Requirements
- PHP 8.2+
- Laravel 11, 12, or 13
- `spatie/laravel-package-tools` ^1.14

### Installation

```bash
composer require jeffersongoncalves/laravel-security-headers
```

Publish the config:

```bash
php artisan vendor:publish --tag="laravel-security-headers-config"
```

## Package Structure

```
src/
  SecurityHeadersServiceProvider.php     # configurePackage()->name('laravel-security-headers')->hasConfigFile()
  Middleware/
    SecurityHeaders.php                  # Reads config and stamps headers onto the response
config/
  laravel-security-headers.php           # headers, csp (enabled + directives), hsts
tests/
  SecurityHeadersTest.php                # Middleware behaviour
  TestCase.php
  Pest.php
```

## How It Works

The single `SecurityHeaders` middleware does three things at `handle()` time:

1. Iterates `config('laravel-security-headers.headers')` and stamps each `name => value`. A `null` value is skipped (the header is omitted).
2. Builds the CSP from `config('laravel-security-headers.csp.directives')` (ordered). A directive value may be a string or an array of sources; a `null`/`''` value emits a *valueless* directive (e.g. `upgrade-insecure-requests`). When `csp.enabled` is `false`, no CSP header is set.
3. Builds HSTS from `config('laravel-security-headers.hsts')`, but **only** when `$request->secure()` is true and the app is not in the `local` environment.

Register the middleware as the **outermost** middleware of the protected group so it also stamps cached (HIT) responses produced further down the stack.

## Features

### Managed Headers

| Header | Default value |
|--------|---------------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()` |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` |
| `X-Permitted-Cross-Domain-Policies` | `none` |
| `Content-Security-Policy` | assembled from `csp.directives` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` (HTTPS + non-local only) |

### Skipping a header

Set the value to `null` in config:

```php
'headers' => [
    'X-Frame-Options' => null, // omitted from the response
],
```

### Content-Security-Policy

```php
'csp' => [
    'enabled' => true,
    'directives' => [
        'default-src' => "'self'",
        'script-src' => ["'self'", "'unsafe-inline'", 'https://www.googletagmanager.com'],
        'img-src' => "'self' data: https:",
        'frame-ancestors' => "'self'",
        'object-src' => "'none'",
        'upgrade-insecure-requests' => null, // valueless
    ],
],
```

The directives are joined with `; ` in declaration order. Arrays are joined with a single space.

### HSTS

```php
'hsts' => [
    'enabled' => true,
    'max-age' => 31536000,
    'include-subdomains' => true,
    'preload' => true,
],
```

Output: `max-age=<max-age>` plus `; includeSubDomains` and/or `; preload` when those flags are truthy. Never emitted on insecure requests or in `local`.

## Security Note

The default CSP keeps `'unsafe-inline'`/`'unsafe-eval'` on `script-src`/`style-src` so inline GTM/gtag and Alpine.js keep working. That makes the CSP **NOT** an XSS backstop for untrusted HTML — pair it with output sanitization (e.g. `symfony/html-sanitizer`) for any rendered third-party/imported markup. The protective value of the default policy lives in the structural directives (`frame-ancestors`, `object-src 'none'`, `base-uri`/`form-action`, `upgrade-insecure-requests`).

If your app does not need inline scripts, tighten `script-src`/`style-src` (drop `'unsafe-inline'`/`'unsafe-eval'`, adopt nonces/hashes).

## Testing Patterns

The middleware is best tested directly by passing a `Request` and a closure that returns a response.

```php
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders;

function runSecurityHeaders(Request $request)
{
    return (new SecurityHeaders)->handle($request, fn () => new Response('OK'));
}

it('stamps nosniff', function () {
    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('X-Content-Type-Options'))->toBe('nosniff');
});

it('adds HSTS on a secure non-local request', function () {
    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Strict-Transport-Security'))
        ->toBe('max-age=31536000; includeSubDomains; preload');
});

it('omits HSTS on an insecure request', function () {
    $response = runSecurityHeaders(Request::create('http://example.com'));

    expect($response->headers->has('Strict-Transport-Security'))->toBeFalse();
});

it('omits a header set to null in config', function () {
    config()->set('laravel-security-headers.headers.X-Frame-Options', null);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->has('X-Frame-Options'))->toBeFalse();
});

it('renders a custom CSP directive from config', function () {
    config()->set('laravel-security-headers.csp.directives.img-src', "'self' https://cdn.example.com");

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Content-Security-Policy'))
        ->toContain("img-src 'self' https://cdn.example.com");
});
```

Note: Testbench runs in the `testing` environment (not `local`), so HSTS is applied for secure requests in tests.

### Running Tests

```bash
# Run all tests
vendor/bin/pest

# Run with coverage
vendor/bin/pest --coverage

# Static analysis
vendor/bin/phpstan analyse

# Code formatting
vendor/bin/pint
```

## Adding a New Managed Header

1. Add the default to `config/laravel-security-headers.php` under `headers`:

```php
'headers' => [
    // ...
    'Cross-Origin-Resource-Policy' => 'same-origin',
],
```

2. No code change is needed — the middleware iterates the `headers` map. Setting the value to `null` skips it.

3. Add a test asserting the header is present (and omitted when `null`).
