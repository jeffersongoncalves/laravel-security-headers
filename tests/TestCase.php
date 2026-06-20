<?php

namespace JeffersonGoncalves\SecurityHeaders\Tests;

use JeffersonGoncalves\SecurityHeaders\SecurityHeadersServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app)
    {
        return [
            SecurityHeadersServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app)
    {
        config()->set('database.default', 'testing');
    }
}
