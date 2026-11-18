# Contributing

Gatekeep is implemented one phase at a time from `docs/SPEC.md`.

- PHP 8.2 or newer. Declare `strict_types=1`. Classes are `final` unless they must be extended. Value objects are `readonly`.
- Depend on interfaces in `src/Contracts`, and bind them in `GatekeepServiceProvider`.
- Cover public behavior with Pest. Tests must not call the network; use fixtures or fakes.
- Do not log SAML assertions, tokens, private keys, or secrets.
- Do not add a dependency that `docs/SPEC.md` does not list unless a maintainer agrees.

Before opening a pull request:

```bash
composer test
composer analyse
composer format -- --test
```
