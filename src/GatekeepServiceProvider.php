<?php

declare(strict_types=1);

namespace Gatekeep;

use Gatekeep\Console\PruneReplayCacheCommand;
use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Contracts\ReplayGuard;
use Gatekeep\Contracts\TenantResolver;
use Gatekeep\Contracts\UserProvisioner;
use Gatekeep\Exceptions\ProvisioningDenied;
use Gatekeep\Replay\CacheReplayGuard;
use Gatekeep\Replay\DatabaseReplayGuard;
use Gatekeep\Repositories\EloquentConnectionRepository;
use Gatekeep\Resolvers\ChainResolver;
use Gatekeep\Saml\SamlDriver;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
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
            ->hasRoute('gatekeep')
            ->hasCommand(PruneReplayCacheCommand::class)
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
        $this->app->singleton(DriverManager::class, function (Application $app): DriverManager {
            $manager = new DriverManager($app);
            $manager->extend('saml', fn (): SamlDriver => $app->make(SamlDriver::class));

            return $manager;
        });

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

        $this->app->singleton(ReplayGuard::class, function (Application $app): ReplayGuard {
            $store = config('gatekeep.replay.store', 'database');

            return match ($store) {
                'cache' => $app->make(CacheReplayGuard::class),
                'database' => $app->make(DatabaseReplayGuard::class),
                default => throw new InvalidArgumentException('gatekeep.replay.store must be database or cache.'),
            };
        });

        $this->app->bind(UserProvisioner::class, function (Application $app): UserProvisioner {
            $class = config('gatekeep.provisioning.provisioner');

            if (! is_string($class) || ! class_exists($class)) {
                throw new ProvisioningDenied;
            }

            $provisioner = $app->make($class);

            if (! $provisioner instanceof UserProvisioner) {
                throw new ProvisioningDenied;
            }

            return $provisioner;
        });
    }

    public function packageBooted(): void
    {
        $this->registerRateLimiters();
        $this->exemptAssertionConsumerFromCsrf();
        $this->schedulePrune();
    }

    private function registerRateLimiters(): void
    {
        RateLimiter::for('gatekeep-discover', function (Request $request) {
            return Limit::perMinute($this->rateLimit('discover_per_minute', 10))->by('discover|'.($request->ip() ?? 'unknown'));
        });

        RateLimiter::for('gatekeep-acs', function (Request $request) {
            return Limit::perMinute($this->rateLimit('acs_per_minute', 30))->by('acs|'.($request->ip() ?? 'unknown'));
        });
    }

    private function rateLimit(string $key, int $default): int
    {
        $value = config('gatekeep.rate_limits.'.$key, $default);
        $limit = is_numeric($value) ? (int) $value : $default;

        return max(1, $limit);
    }

    private function exemptAssertionConsumerFromCsrf(): void
    {
        $prefix = config('gatekeep.route_prefix', 'sso');
        $prefix = is_string($prefix) ? trim($prefix, '/') : 'sso';

        PreventRequestForgery::except($prefix.'/saml/*/acs');
    }

    private function schedulePrune(): void
    {
        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            $schedule->command('gatekeep:prune')->hourly();
        });
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
