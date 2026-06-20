<?php

namespace JeffersonGoncalves\SecurityHeaders;

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
}
