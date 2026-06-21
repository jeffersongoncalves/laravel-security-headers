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
 * The shipped default CSP is strict and first-party only ('self'), so it acts
 * as a real XSS backstop. To allow inline scripts, place the `{nonce}`
 * placeholder in a directive (e.g. "script-src 'self' 'nonce-{nonce}'") and
 * emit the matching nonce in markup with the `@cspNonce` Blade directive or the
 * `csp_nonce()` helper — this middleware substitutes `{nonce}` with the same
 * per-request value. If you instead loosen directives with
 * 'unsafe-inline'/'unsafe-eval', the CSP stops being an XSS backstop; pair it
 * with output sanitization (e.g. symfony/html-sanitizer) for untrusted markup.
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
            $header = config('security-headers.csp.report-only', false)
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy';

            $response->headers->set($header, $csp);
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

            $value = $this->substituteNonce((string) $value);

            $directives[] = trim($directive.' '.$value);
        }

        $reportUri = config('security-headers.csp.report-uri');

        if (is_string($reportUri) && $reportUri !== '') {
            $directives[] = 'report-uri '.$reportUri;
        }

        $reportTo = config('security-headers.csp.report-to');

        if (is_string($reportTo) && $reportTo !== '') {
            $directives[] = 'report-to '.$reportTo;
        }

        if ($directives === []) {
            return null;
        }

        return implode('; ', $directives);
    }

    private function substituteNonce(string $value): string
    {
        if (! str_contains($value, '{nonce}')) {
            return $value;
        }

        return str_replace('{nonce}', csp_nonce(), $value);
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
