<div class="filament-hidden">

![Laravel Security Headers](https://raw.githubusercontent.com/jeffersongoncalves/laravel-security-headers/master/art/jeffersongoncalves-laravel-security-headers.png)

</div>

# Laravel Security Headers

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jeffersongoncalves/laravel-security-headers.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-security-headers)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-security-headers/run-tests.yml?branch=master&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/laravel-security-headers/actions?query=workflow%3Arun-tests+branch%3Amaster)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-security-headers/fix-php-code-style-issues.yml?branch=master&label=code%20style&style=flat-square)](https://github.com/jeffersongoncalves/laravel-security-headers/actions?query=workflow%3A"Fix+PHP+code+styling"+branch%3Amaster)
[![Total Downloads](https://img.shields.io/packagist/dt/jeffersongoncalves/laravel-security-headers.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-security-headers)

This Laravel package stamps a configurable set of baseline security headers onto your HTTP responses via a single middleware. Every header value and the full Content-Security-Policy directive map are driven by `config/security-headers.php`, so you can tune or disable each one without touching code.

The headers it manages:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Content-Security-Policy`
- `Cross-Origin-Opener-Policy`
- `X-Permitted-Cross-Domain-Policies`
- `Strict-Transport-Security` (HSTS) — only over real HTTPS and never in the `local` environment

## Installation

You can install the package via composer:

```bash
composer require jeffersongoncalves/laravel-security-headers
```

You can publish the config file with:

```bash
php artisan vendor:publish --tag="security-headers-config"
```

## Usage

The package ships a single middleware: `JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders`. The service provider **auto-registers a `security-headers` route-middleware alias** for you, but it does **not** apply the middleware globally — you must still attach it to a route or group. Place it as the **outermost** middleware of the group you want protected so it also stamps cached (HIT) responses produced further down the stack.

### Attach it via the registered alias

The alias `security-headers` is wired up automatically, so you can use it directly on a route or group:

```php
Route::middleware('security-headers')->group(function () {
    // ...
});
```

### Or apply it to the whole web group (Laravel 11+)

In `bootstrap/app.php`:

```php
use Illuminate\Foundation\Configuration\Middleware;
use JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders;

->withMiddleware(function (Middleware $middleware) {
    $middleware->web(prepend: [
        SecurityHeaders::class,
    ]);
})
```

### Legacy kernel (Laravel 10 style)

Add the middleware to a group in `app/Http/Kernel.php`:

```php
protected $middlewareGroups = [
    'web' => [
        \JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders::class,
        // ...
    ],
];
```

## Configuration

After publishing, `config/security-headers.php` exposes three blocks.

### Static headers

Each entry is stamped onto every response. Set any value to `null` to **skip** that header:

```php
'headers' => [
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'SAMEORIGIN',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
    'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()',
    'Cross-Origin-Opener-Policy' => 'same-origin-allow-popups',
    // Disable a header by setting it to null:
    'X-Permitted-Cross-Domain-Policies' => null,
],
```

### Customizing the Content-Security-Policy

The CSP header is assembled from the associative `directives` map, **preserving order**. A value may be a string or an array of source expressions. A directive whose value is `null` (or an empty string) is emitted as a *valueless* directive (e.g. `upgrade-insecure-requests`). Set `csp.enabled` to `false` to drop the header entirely.

The shipped default is a **strict, first-party-only** policy — no `'unsafe-*'`, no third-party origins — so it is a genuine XSS backstop:

```php
'csp' => [
    'enabled' => true,
    'directives' => [
        'default-src' => "'self'",
        'script-src' => "'self'",
        'style-src' => "'self'",
        'img-src' => "'self' data:",
        'object-src' => "'none'",
        'base-uri' => "'self'",
        'form-action' => "'self'",
        'frame-ancestors' => "'self'",
    ],
],
```

#### Nonces for inline scripts

Rather than reaching for `'unsafe-inline'`, allow specific inline scripts with a per-request nonce. Put the `{nonce}` placeholder in a directive — the middleware substitutes it with a fresh, random per-request value:

```php
'script-src' => "'self' 'nonce-{nonce}'",
```

Then emit the matching nonce in your Blade markup with the `@cspNonce` directive (or the `csp_nonce()` helper):

```blade
<script nonce="@cspNonce">
    // your trusted inline script
</script>
```

Both the header and the view receive the **same** value for that request, so the script validates while injected markup (which cannot guess the nonce) is blocked.

#### Report-only mode and violation reporting

Set `report-only` to emit `Content-Security-Policy-Report-Only` instead of the enforcing header (useful for rolling out a policy without breaking pages). `report-uri` / `report-to` are appended as CSP directives when non-null:

```php
'csp' => [
    'enabled' => true,
    'report-only' => true,
    'report-uri' => 'https://example.com/csp-report', // legacy endpoint
    'report-to' => 'csp-endpoint',                    // Reporting-API group name
    // ...
],
```

#### Opt-in: GTM / gtag / Alpine.js (permissive)

If you rely on inline Google Tag Manager / gtag and Alpine.js (which evaluates expressions via `new Function`, requiring `'unsafe-eval'`) and cannot adopt nonces, you can loosen the policy. **This removes the CSP's XSS protection** — pair it with output sanitization (e.g. `symfony/html-sanitizer`) for any untrusted markup you render:

```php
'directives' => [
    'default-src' => "'self'",
    'script-src' => "'self' 'unsafe-inline' 'unsafe-eval' https://www.googletagmanager.com https://www.google-analytics.com https://static.cloudflareinsights.com",
    'style-src' => "'self' 'unsafe-inline'",
    'img-src' => "'self' data: https:",
    'font-src' => "'self' data:",
    'connect-src' => "'self' https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com https://cloudflareinsights.com",
    'frame-src' => "'self' https://www.googletagmanager.com",
    'frame-ancestors' => "'self'",
    'base-uri' => "'self'",
    'form-action' => "'self'",
    'object-src' => "'none'",
    'upgrade-insecure-requests' => null,
],
```

### HSTS

`Strict-Transport-Security` is only stamped over real HTTPS and never while the app is in the `local` environment (a cached `max-age` on a `*.test` domain is a pain to undo):

```php
'hsts' => [
    'enabled' => true,
    'max-age' => 31536000,
    'include-subdomains' => true,
    'preload' => false,
],
```

> **`preload` is a near-irreversible commitment.** Enabling it and submitting your domain to [hstspreload.org](https://hstspreload.org) hard-codes HTTPS-only for the apex domain **and every subdomain** into browsers shipped worldwide. Removal is slow (months) and painful. Leave it `false` unless you are certain every current and future subdomain serves valid TLS. It defaults to `false`.

#### HSTS depends on a correct `$request->secure()`

HSTS is only emitted when Laravel considers the request secure (`$request->secure()`). Behind a TLS-terminating proxy or load balancer (the app receives plain HTTP on the back end), `secure()` returns `false` and HSTS will be silently skipped unless you configure trusted proxies. Make sure your `TrustProxies` middleware / `bootstrap/app.php` `trustProxies(...)` config is set so the `X-Forwarded-Proto` header is honoured — otherwise the proxy must add HSTS itself.

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Jèfferson Gonçalves](https://github.com/jeffersongoncalves)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
