<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SecurityHeaders\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Baseline security headers, driven entirely by config/security-headers.php.
 *
 * Apply this as the outermost middleware of the group you want protected so it
 * also stamps cached (HIT) responses produced further down the stack.
 *
 * The default CSP is deliberately permissive on script/style: Alpine.js
 * evaluates expressions via `new Function` (needs 'unsafe-eval') and pages
 * commonly ship inline handlers + Google Tag Manager / gtag / Cloudflare Web
 * Analytics. The value is in the structural directives — frame-ancestors
 * (clickjacking), object-src none, base-uri and form-action lock-down, and
 * upgrade-insecure-requests.
 *
 * XSS NOTE: because the default keeps 'unsafe-inline'/'unsafe-eval', the CSP is
 * NOT an XSS backstop for untrusted HTML. Pair it with output sanitization
 * (e.g. symfony/html-sanitizer) for any third-party or imported markup you
 * render. Do not treat a permissive script/style CSP as a compensating control.
 */
class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        foreach ((array) config('security-headers.headers', []) as $name => $value) {
            if ($value === null) {
                continue;
            }

            $response->headers->set($name, $value);
        }

        $csp = $this->contentSecurityPolicy();

        if ($csp !== null) {
            $response->headers->set('Content-Security-Policy', $csp);
        }

        $hsts = $this->strictTransportSecurity($request);

        if ($hsts !== null) {
            $response->headers->set('Strict-Transport-Security', $hsts);
        }

        return $response;
    }

    private function contentSecurityPolicy(): ?string
    {
        if (! config('security-headers.csp.enabled', true)) {
            return null;
        }

        $directives = [];

        foreach ((array) config('security-headers.csp.directives', []) as $directive => $value) {
            if (is_array($value)) {
                $value = implode(' ', $value);
            }

            if ($value === null || $value === '') {
                $directives[] = $directive;

                continue;
            }

            $directives[] = trim($directive.' '.$value);
        }

        if ($directives === []) {
            return null;
        }

        return implode('; ', $directives);
    }

    private function strictTransportSecurity(Request $request): ?string
    {
        if (! config('security-headers.hsts.enabled', true)) {
            return null;
        }

        // HSTS only over real HTTPS and never in local dev (a cached max-age on
        // a *.test domain is a pain to undo).
        if (! $request->secure() || app()->environment('local')) {
            return null;
        }

        $value = 'max-age='.(int) config('security-headers.hsts.max-age', 31536000);

        if (config('security-headers.hsts.include-subdomains', true)) {
            $value .= '; includeSubDomains';
        }

        if (config('security-headers.hsts.preload', true)) {
            $value .= '; preload';
        }

        return $value;
    }
}
