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
php artisan vendor:publish --tag="laravel-security-headers-config"
```

## Usage

The package ships a single middleware: `JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders`. Register it however you apply security to your responses. Place it as the **outermost** middleware of the group you want protected so it also stamps cached (HIT) responses produced further down the stack.

### Register an alias and/or apply to a group (Laravel 11+)

In `bootstrap/app.php`:

```php
use Illuminate\Foundation\Configuration\Middleware;
use JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders;

->withMiddleware(function (Middleware $middleware) {
    // Apply to the whole web group...
    $middleware->web(prepend: [
        SecurityHeaders::class,
    ]);

    // ...or register an alias and attach it per route/group.
    $middleware->alias([
        'security-headers' => SecurityHeaders::class,
    ]);
})
```

Then, with the alias, on a route or group:

```php
Route::middleware('security-headers')->group(function () {
    // ...
});
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

The CSP header is assembled from the associative `directives` map, **preserving order**. A value may be a string or an array of source expressions. A directive whose value is `null` (or an empty string) is emitted as a *valueless* directive (e.g. `upgrade-insecure-requests`). Set `csp.enabled` to `false` to drop the header entirely:

```php
'csp' => [
    'enabled' => true,
    'directives' => [
        'default-src' => "'self'",
        'script-src' => ["'self'", "'unsafe-inline'", 'https://www.googletagmanager.com'],
        'img-src' => "'self' data: https:",
        'frame-ancestors' => "'self'",
        'object-src' => "'none'",
        'upgrade-insecure-requests' => null, // valueless directive
    ],
],
```

### HSTS

`Strict-Transport-Security` is only stamped over real HTTPS and never while the app is in the `local` environment (a cached `max-age` on a `*.test` domain is a pain to undo):

```php
'hsts' => [
    'enabled' => true,
    'max-age' => 31536000,
    'include-subdomains' => true,
    'preload' => true,
],
```

## Security caveat: the CSP is not an XSS backstop

The default CSP is deliberately permissive on `script-src`/`style-src` — it keeps `'unsafe-inline'` and `'unsafe-eval'` so inline Google Tag Manager / gtag and Alpine.js (which evaluates expressions via `new Function`) keep working. The protective value is in the **structural** directives: `frame-ancestors` (clickjacking), `object-src 'none'`, `base-uri`/`form-action` lock-down, and `upgrade-insecure-requests`.

Because `'unsafe-inline'`/`'unsafe-eval'` remain, **this CSP is NOT the XSS backstop** for any untrusted HTML you render (third-party content, imported article bodies, READMEs, etc.). Pair it with output sanitization (for example `symfony/html-sanitizer`) for any such markup — do not treat a permissive script/style CSP as a compensating control. If you do not need inline scripts, tighten `script-src`/`style-src` (drop `'unsafe-inline'`/`'unsafe-eval'`, adopt nonces/hashes).

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
