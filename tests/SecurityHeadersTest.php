<?php

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders;
use JeffersonGoncalves\SecurityHeaders\SecurityHeadersServiceProvider;
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

it('builds a strict first-party content security policy by default', function () {
    $response = runSecurityHeaders(Request::create('https://example.com'));

    $csp = $response->headers->get('Content-Security-Policy');

    expect($csp)->toContain("default-src 'self'")
        ->and($csp)->toContain("script-src 'self'")
        ->and($csp)->toContain("style-src 'self'")
        ->and($csp)->toContain("object-src 'none'")
        ->and($csp)->toContain("frame-ancestors 'self'")
        // no permissive sources baked into the shipped default
        ->and($csp)->not->toContain("'unsafe-inline'")
        ->and($csp)->not->toContain("'unsafe-eval'")
        ->and($csp)->not->toContain('googletagmanager.com');
});

it('emits a valueless directive when the value is null', function () {
    config()->set('security-headers.csp.directives.upgrade-insecure-requests', null);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Content-Security-Policy'))
        ->toContain('upgrade-insecure-requests');
});

it('joins array-valued CSP directives with spaces', function () {
    config()->set('security-headers.csp.directives.script-src', ["'self'", "'nonce-abc'", 'https://cdn.example.com']);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Content-Security-Policy'))
        ->toContain("script-src 'self' 'nonce-abc' https://cdn.example.com");
});

it('substitutes the {nonce} placeholder with the per-request nonce', function () {
    config()->set('security-headers.csp.directives.script-src', "'self' 'nonce-{nonce}'");

    $response = runSecurityHeaders(Request::create('https://example.com'));

    $nonce = csp_nonce();

    expect($nonce)->not->toBe('')
        ->and($response->headers->get('Content-Security-Policy'))
        ->toContain("script-src 'self' 'nonce-".$nonce."'")
        ->not->toContain('{nonce}');
});

it('emits the report-only header instead of the enforcing one when enabled', function () {
    config()->set('security-headers.csp.report-only', true);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->has('Content-Security-Policy'))->toBeFalse()
        ->and($response->headers->get('Content-Security-Policy-Report-Only'))
        ->toContain("default-src 'self'");
});

it('appends report-uri and report-to directives when configured', function () {
    config()->set('security-headers.csp.report-uri', 'https://example.com/csp-report');
    config()->set('security-headers.csp.report-to', 'csp-endpoint');

    $response = runSecurityHeaders(Request::create('https://example.com'));

    $csp = $response->headers->get('Content-Security-Policy');

    expect($csp)->toContain('report-uri https://example.com/csp-report')
        ->and($csp)->toContain('report-to csp-endpoint');
});

it('adds HSTS on a secure non-local request', function () {
    $response = runSecurityHeaders(Request::create('https://example.com'));

    // preload defaults to false now
    expect($response->headers->get('Strict-Transport-Security'))
        ->toBe('max-age=31536000; includeSubDomains');
});

it('omits HSTS on an insecure request', function () {
    $response = runSecurityHeaders(Request::create('http://example.com'));

    expect($response->headers->has('Strict-Transport-Security'))->toBeFalse();
});

it('omits HSTS in the local environment even over HTTPS', function () {
    app()->detectEnvironment(fn () => 'local');

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->has('Strict-Transport-Security'))->toBeFalse();
});

it('omits includeSubDomains when disabled', function () {
    config()->set('security-headers.hsts.include-subdomains', false);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Strict-Transport-Security'))->toBe('max-age=31536000');
});

it('appends preload when enabled', function () {
    config()->set('security-headers.hsts.preload', true);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Strict-Transport-Security'))
        ->toBe('max-age=31536000; includeSubDomains; preload');
});

it('honours a custom max-age', function () {
    config()->set('security-headers.hsts.max-age', 600);

    $response = runSecurityHeaders(Request::create('https://example.com'));

    expect($response->headers->get('Strict-Transport-Security'))
        ->toBe('max-age=600; includeSubDomains');
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

it('publishes the config file under the expected tag', function () {
    $paths = ServiceProvider::pathsToPublish(
        SecurityHeadersServiceProvider::class,
        'security-headers-config'
    );

    expect($paths)->not->toBeEmpty();

    $target = array_values($paths)[0];

    @unlink($target);

    $this->artisan('vendor:publish', [
        '--tag' => 'security-headers-config',
        '--force' => true,
    ])->assertExitCode(0);

    expect(file_exists($target))->toBeTrue();

    @unlink($target);
});

it('applies the headers on a real route via the registered alias', function () {
    Route::middleware('security-headers')->get('/_security-headers-test', fn () => 'ok');

    $response = $this->get('https://localhost/_security-headers-test');

    $response->assertOk()
        ->assertHeader('X-Content-Type-Options', 'nosniff')
        ->assertHeader('X-Frame-Options', 'SAMEORIGIN')
        ->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    expect($response->headers->get('Content-Security-Policy'))->toContain("default-src 'self'");
});
