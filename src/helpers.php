<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Vite;

if (! function_exists('csp_nonce')) {
    /**
     * The per-request Content-Security-Policy nonce.
     *
     * It is Laravel's Vite nonce (Vite::cspNonce()), so the tags Vite and Livewire
     * render carry the same value the middleware substitutes into the `{nonce}`
     * placeholder. The SecurityHeaders middleware starts every request with a fresh
     * one; outside it, the first call generates it.
     */
    function csp_nonce(): string
    {
        return Vite::cspNonce() ?? Vite::useCspNonce();
    }
}
