# Gatekeep

Self-hosted, open-source multi-tenant enterprise SSO (SAML 2.0 + OIDC) for Laravel. IdP-initiated SAML is supported and off by default, identity-provider metadata can be imported from an upload or an HTTPS URL, and service-provider certificates rotate without downtime. JIT provisioning, attribute presets, login events, OIDC, and the admin UI come in later phases.

## Requirements

- PHP 8.2–8.4
- Laravel 12 or 13

Laravel 13 requires PHP 8.3. Pest 3 covers PHP 8.2 with Laravel 12. Laravel 13 is tested with Pest 4, because Pest 3's Laravel plugin does not support Laravel 13. Laravel 11 is not supported: it is end of life, and current Composer blocks every 11.x release.

## Installation

```bash
composer require prestonfoshee/laravel-gatekeep
```

The service provider is auto-discovered. Publish the config and migrations, then migrate:

```bash
php artisan vendor:publish --tag=gatekeep-config
php artisan vendor:publish --tag=gatekeep-migrations
php artisan migrate
```

To try the package from a local checkout before it is on Packagist:

```bash
composer config repositories.gatekeep path ../laravel-gatekeep
composer require prestonfoshee/laravel-gatekeep:@dev
```

## Testing

```bash
composer test
composer analyse
composer format
```

## License

MIT. See [LICENSE](LICENSE).
