# Changelog

## Unreleased

### Added

- IdP-initiated SAML login, disabled by default, with a per-connection override. Unsolicited responses are accepted only when they omit `InResponseTo`.
- Identity-provider metadata import from an XML upload or an HTTPS URL, with SSRF, XXE, and size limits, plus `gatekeep:refresh-metadata` and the `IdpMetadataRefreshed` and `IdpCertificateChanged` events.
- Overlapping IdP certificate validation, and service-provider certificate rotation via `gatekeep:sp-cert:generate`, `gatekeep:sp-cert:promote`, and `gatekeep:sp-cert:retire`.
- SP-initiated SAML login through `onelogin/php-saml` v4, including discovery, the assertion consumer, signed service-provider metadata, replay guards, and `gatekeep:prune`.
- Package skeleton with a Laravel service provider, Pest and Testbench, Larastan at level max, Pint, and GitHub Actions for the PHP and Laravel matrix.
- Domain models, publishable config and migrations, tenant resolvers, and a driver manager skeleton. Connection config and service-provider private keys are encrypted at rest.

### Changed

- Support Laravel 12 and 13 only. Laravel 11 is end of life, and Composer blocks every 11.x release.
