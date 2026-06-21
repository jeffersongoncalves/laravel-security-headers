<?php

// config for JeffersonGoncalves/SecurityHeaders

return [

    /*
    |--------------------------------------------------------------------------
    | Static Response Headers
    |--------------------------------------------------------------------------
    |
    | Each entry is stamped onto every response handled by the middleware.
    | Set any value to `null` to skip that header entirely.
    |
    */

    'headers' => [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'SAMEORIGIN',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()',
        // Isolate the browsing context (XS-Leaks / Spectre defence-in-depth).
        // "-allow-popups" keeps analytics/GTM popups from being severed.
        'Cross-Origin-Opener-Policy' => 'same-origin-allow-popups',
        'X-Permitted-Cross-Domain-Policies' => 'none',
    ],

    /*
    |--------------------------------------------------------------------------
    | Content Security Policy
    |--------------------------------------------------------------------------
    |
    | The CSP header is assembled from the associative `directives` map below,
    | preserving order. A directive whose value is `null` (or an empty string)
    | is emitted as a valueless directive (e.g. `upgrade-insecure-requests`).
    | A value may be a string or an array of source expressions. Set
    | `enabled` to `false` to drop the header altogether.
    |
    | The shipped default is a STRICT, first-party-only policy: no `'unsafe-*'`
    | and no third-party origins. It is a real XSS backstop. If your app needs
    | inline scripts you have two clean options:
    |   - Add a per-request nonce: place the `{nonce}` placeholder in a directive
    |     (e.g. "script-src 'self' 'nonce-{nonce}'") and emit it in markup via the
    |     `@cspNonce` Blade directive or the `csp_nonce()` helper. The middleware
    |     substitutes `{nonce}` with the same value exposed to the view.
    |   - Or loosen specific directives (see the opt-in GTM/Alpine snippet in the
    |     README). Loosening with `'unsafe-inline'`/`'unsafe-eval'` removes the XSS
    |     protection — pair it with output sanitization (e.g. symfony/html-sanitizer).
    |
    | Set `report-only` to true to emit `Content-Security-Policy-Report-Only`
    | instead of the enforcing header. `report-uri`/`report-to` are appended as
    | directives when non-null so violations can be collected.
    |
    */

    'csp' => [
        'enabled' => true,

        // Emit Content-Security-Policy-Report-Only instead of the enforcing header.
        'report-only' => false,

        // Optional violation-reporting endpoints. Appended as CSP directives.
        // 'report-uri' is the legacy endpoint; 'report-to' references a
        // Reporting-API group name you configure via a Report-To/Reporting-Endpoints header.
        'report-uri' => null,
        'report-to' => null,

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

    /*
    |--------------------------------------------------------------------------
    | HTTP Strict Transport Security (HSTS)
    |--------------------------------------------------------------------------
    |
    | HSTS is only stamped over real HTTPS and never while the application is
    | in the `local` environment (a cached max-age on a *.test domain is a
    | pain to undo). Toggle and tune the directive parameters below.
    |
    | `preload` defaults to FALSE: turning it on is a near-irreversible
    | commitment. Submitting your domain to hstspreload.org bakes HTTPS-only for
    | the apex AND every subdomain into browsers, and removal can take months to
    | propagate. Only enable it once you are certain every subdomain serves TLS.
    |
    */

    'hsts' => [
        'enabled' => true,
        'max-age' => 31536000,
        'include-subdomains' => true,
        'preload' => false,
    ],

];
