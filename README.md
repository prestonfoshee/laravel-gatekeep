# Gatekeep

Self-hosted, open-source multi-tenant enterprise SSO (SAML 2.0 + OIDC) for Laravel.

Phase 2 adds SP-initiated SAML: a per-connection OneLogin settings factory, the discovery and login routes, signed service-provider metadata, and an assertion consumer that checks the signature, audience, destination, issuer, lifetime, and InResponseTo value. IdP-initiated login, metadata import, and JIT provisioning are not implemented yet.

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
