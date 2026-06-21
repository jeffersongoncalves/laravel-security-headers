<?php

declare(strict_types=1);

if (! function_exists('csp_nonce')) {
    /**
     * The per-request Content-Security-Policy nonce.
     *
     * Bound as a scoped container instance by the service provider, so this
     * returns the same value throughout a single request — the same value the
     * middleware substitutes into the `{nonce}` placeholder of CSP directives.
     */
    function csp_nonce(): string
    {
        return (string) app('security-headers.nonce');
    }
}
