# Gatekeep

Self-hosted, open-source multi-tenant enterprise SSO (SAML 2.0 + OIDC) for Laravel.

Phase 0 is the empty package skeleton. Protocol drivers, models, and routes are not implemented yet.

## Requirements

- PHP 8.2–8.4
- Laravel 11, 12, or 13

Laravel 13 requires PHP 8.3. Pest 3 covers PHP 8.2 with Laravel 11 and 12. Laravel 13 is tested with Pest 4, because Pest 3's Laravel plugin does not support Laravel 13.

## Installation

```bash
composer require prestonfoshee/laravel-gatekeep
```

The service provider is auto-discovered.

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
