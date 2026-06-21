<?php

declare(strict_types=1);

namespace JeffersonGoncalves\SecurityHeaders;

use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\SecurityHeaders\Middleware\SecurityHeaders;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SecurityHeadersServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-security-headers')
            ->hasConfigFile();
    }

    public function packageRegistered(): void
    {
        // One nonce per request, shared between the middleware (which substitutes
        // the {nonce} placeholder in CSP directives) and the @cspNonce / csp_nonce()
        // helpers used in views.
        $this->app->scoped('security-headers.nonce', fn (): string => base64_encode(random_bytes(16)));
    }

    public function packageBooted(): void
    {
        // Register the alias so the middleware is wirable by name. NOTE: this does
        // NOT apply it globally — you still have to attach `security-headers` to a
        // route or middleware group (see the README).
        Route::aliasMiddleware('security-headers', SecurityHeaders::class);

        // Emit the per-request nonce in markup, e.g. <script nonce="@cspNonce">.
        Blade::directive('cspNonce', fn (): string => '<?php echo e(csp_nonce()); ?>');
    }
}
