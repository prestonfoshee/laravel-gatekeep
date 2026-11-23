<?php

declare(strict_types=1);

namespace Gatekeep\Tests;

use Gatekeep\Facades\Gatekeep as GatekeepFacade;
use Gatekeep\GatekeepServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.connections.sqlite.foreign_key_constraints', true);
        $app['config']->set('database.connections.testing.foreign_key_constraints', true);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__).'/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
    }

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

    /**
     * @param  Application  $app
     * @return array<string, class-string>
     */
    protected function getPackageAliases($app)
    {
        return [
            'Gatekeep' => GatekeepFacade::class,
        ];
    }
}
