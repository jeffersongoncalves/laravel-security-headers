## Laravel Security Headers

### Overview
Laravel Security Headers stamps a configurable set of baseline security headers onto HTTP responses through a single middleware. Every header value and the full Content-Security-Policy directive map are driven by `config/laravel-security-headers.php`.

**Namespace:** `JeffersonGoncalves\SecurityHeaders`
**Service Provider:** `SecurityHeadersServiceProvider` (auto-discovered)
**Middleware:** `JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders`

### Key Concepts
- **Single middleware:** All headers are applied by one middleware — register it as the outermost middleware of the group you want protected so it also covers cached responses.
- **Config-driven:** The `headers` map, the `csp.directives` map, and the `hsts` block are all read from config at request time.
- **Skip a header:** Set any value in `headers` to `null` to omit it. Set `csp.enabled`/`hsts.enabled` to `false` to drop those.
- **Valueless CSP directives:** A directive whose value is `null`/`''` (e.g. `upgrade-insecure-requests`) is emitted without a value.
- **HSTS gating:** `Strict-Transport-Security` is only added when `$request->secure()` is true and the app is not in the `local` environment.

### Managed Headers

| Header | Default |
|--------|---------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()` |
| `Content-Security-Policy` | Built from `csp.directives` |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` |
| `X-Permitted-Cross-Domain-Policies` | `none` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` (HTTPS, non-local) |

### Registering the Middleware

@verbatim
<code-snippet name="register-middleware" lang="php">
use Illuminate\Foundation\Configuration\Middleware;
use JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders;

->withMiddleware(function (Middleware $middleware) {
    $middleware->web(prepend: [
        SecurityHeaders::class,
    ]);

    // or as an alias
    $middleware->alias([
        'security-headers' => SecurityHeaders::class,
    ]);
})
</code-snippet>
@endverbatim

### Customizing the CSP

@verbatim
<code-snippet name="csp-config" lang="php">
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
</code-snippet>
@endverbatim

### Configuration
- Config file: `config/laravel-security-headers.php` (config key `laravel-security-headers`).
- `headers`: associative `name => value`; `null` value = skip the header.
- `csp.directives`: ordered associative map; value may be string or array of sources; `null`/`''` = valueless directive.
- `hsts`: `enabled`, `max-age`, `include-subdomains`, `preload`.

### Conventions
- The middleware lives in `JeffersonGoncalves\SecurityHeaders\Middleware\`.
- The CSP keeps `'unsafe-inline'`/`'unsafe-eval'` by default — it is NOT an XSS backstop. Pair with output sanitization for untrusted HTML.
- HSTS is intentionally suppressed in `local` and on non-secure requests.
