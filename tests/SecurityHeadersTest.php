<?php

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

function runSecurityHeaders(Request $request): SymfonyResponse
{
    return (new SecurityHeaders)->handle($request, fn () => new Response('OK'));
}

it('stamps the baseline security headers', function () {
    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('X-Content-Type-Options'))->toBe('nosniff')
        ->and($response->headers->get('X-Frame-Options'))->toBe('SAMEORIGIN')
        ->and($response->headers->get('Referrer-Policy'))->toBe('strict-origin-when-cross-origin')
        ->and($response->headers->get('Permissions-Policy'))->toBe('camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()')
        ->and($response->headers->get('Cross-Origin-Opener-Policy'))->toBe('same-origin-allow-popups')
        ->and($response->headers->get('X-Permitted-Cross-Domain-Policies'))->toBe('none');
});

it('builds the content security policy from config directives', function () {
    $response = runSecurityHeaders(Request::create('https://example.com'));

    $csp = $response->headers->get('Content-Security-Policy');

    expect($csp)->toContain("default-src 'self'")
        ->and($csp)->toContain("object-src 'none'")
        ->and($csp)->toContain("frame-ancestors 'self'")
        // valueless directive is emitted without a value
        ->and($csp)->toContain('upgrade-insecure-requests');
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
    config()->set('security-headers.headers.X-Frame-Options', null);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->has('X-Frame-Options'))->toBeFalse()
        // other headers are still stamped
        ->and($response->headers->get('X-Content-Type-Options'))->toBe('nosniff');
});

it('renders a custom CSP directive from config', function () {
    config()->set('security-headers.csp.directives.img-src', "'self' https://cdn.example.com");

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Content-Security-Policy'))
        ->toContain("img-src 'self' https://cdn.example.com");
});

it('drops the CSP header entirely when disabled', function () {
    config()->set('security-headers.csp.enabled', false);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->has('Content-Security-Policy'))->toBeFalse();
});
