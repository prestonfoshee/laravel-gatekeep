<?php

declare(strict_types=1);

namespace Gatekeep;

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Contracts\TenantResolver;
use Gatekeep\Repositories\EloquentConnectionRepository;
use Gatekeep\Resolvers\ChainResolver;
use Illuminate\Contracts\Foundation\Application;
use InvalidArgumentException;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

final class GatekeepServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-gatekeep')
            ->hasConfigFile()
            ->hasMigrations([
                '2026_01_01_000001_create_sso_connections_table',
                '2026_01_01_000002_create_sso_connection_domains_table',
                '2026_01_01_000003_create_sso_identities_table',
                '2026_01_01_000004_create_sso_replay_cache_table',
                '2026_01_01_000005_create_sso_sp_certificates_table',
                '2026_01_01_000006_create_sso_login_attempts_table',
            ]);
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(DriverManager::class, fn (Application $app): DriverManager => new DriverManager($app));

        $this->app->singleton(Gatekeep::class, fn (Application $app): Gatekeep => new Gatekeep($app->make(DriverManager::class)));

        $this->app->alias(Gatekeep::class, 'gatekeep');

        $this->app->singleton(ConnectionRepository::class, EloquentConnectionRepository::class);

        $this->app->singleton(ChainResolver::class, function (Application $app): ChainResolver {
            $resolvers = [];

            foreach ($this->resolverClasses() as $resolverClass) {
                $resolver = $app->make($resolverClass);

                if (! $resolver instanceof TenantResolver) {
                    throw new InvalidArgumentException($resolverClass.' must implement '.TenantResolver::class.'.');
                }

                $resolvers[] = $resolver;
            }

            return new ChainResolver($resolvers);
        });

        $this->app->singleton(TenantResolver::class, fn (Application $app): TenantResolver => $app->make(ChainResolver::class));
    }

    /**
     * @return list<class-string<TenantResolver>>
     */
    private function resolverClasses(): array
    {
        $configured = config('gatekeep.resolvers', []);

        if (! is_array($configured)) {
            throw new InvalidArgumentException('gatekeep.resolvers must be a list of '.TenantResolver::class.' class names.');
        }

        $classes = [];

        foreach ($configured as $resolverClass) {
            if (! is_string($resolverClass) || ! is_a($resolverClass, TenantResolver::class, true)) {
                throw new InvalidArgumentException('Each gatekeep resolver must be a '.TenantResolver::class.' class name.');
            }

            if ($resolverClass === ChainResolver::class) {
                throw new InvalidArgumentException('ChainResolver cannot be nested in gatekeep.resolvers.');
            }

            $classes[] = $resolverClass;
        }

        return $classes;
    }
}
