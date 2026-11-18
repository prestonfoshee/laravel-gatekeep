<?php

declare(strict_types=1);

namespace Gatekeep\Tests;

use Gatekeep\GatekeepServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return array<int, class-string<ServiceProvider>>
     */
    protected function getPackageProviders($app)
    {
        return [
            GatekeepServiceProvider::class,
        ];
    }
}
