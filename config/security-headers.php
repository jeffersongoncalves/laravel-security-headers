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
    | XSS NOTE: this default policy keeps 'unsafe-inline'/'unsafe-eval' on
    | script/style so inline GTM/gtag and Alpine.js keep working. That makes
    | the CSP NOT an XSS backstop for untrusted HTML — pair it with output
    | sanitization (e.g. symfony/html-sanitizer) for any rendered third-party
    | or imported markup.
    |
    */

    'csp' => [
        'enabled' => true,
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
    */

    'hsts' => [
        'enabled' => true,
        'max-age' => 31536000,
        'include-subdomains' => true,
        'preload' => true,
    ],

];
