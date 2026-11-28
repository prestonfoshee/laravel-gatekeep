<?php

declare(strict_types=1);

use App\Models\User;
use Gatekeep\Provisioning\DefaultUserProvisioner;
use Gatekeep\Resolvers\EmailDomainResolver;
use Gatekeep\Resolvers\SubdomainResolver;

it('merges the published gatekeep config', function () {
    expect(config('gatekeep.route_prefix'))->toBe('sso')
        ->and(config('gatekeep.middleware'))->toBe(['web'])
        ->and(config('gatekeep.user_model'))->toBe(User::class)
        ->and(config('gatekeep.guard'))->toBe('web')
        ->and(config('gatekeep.home'))->toBe('/dashboard')
        ->and(config('gatekeep.resolvers'))->toBe([
            EmailDomainResolver::class,
            SubdomainResolver::class,
        ])
        ->and(config('gatekeep.saml.want_assertions_signed'))->toBeTrue()
        ->and(config('gatekeep.saml.want_messages_signed'))->toBeFalse()
        ->and(config('gatekeep.saml.allow_idp_initiated'))->toBeFalse()
        ->and(config('gatekeep.saml.clock_skew_seconds'))->toBe(120)
        ->and(config('gatekeep.saml.signature_algorithm'))->toBe('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
        ->and(config('gatekeep.oidc.scopes'))->toBe(['openid', 'email', 'profile'])
        ->and(config('gatekeep.oidc.use_pkce'))->toBeTrue()
        ->and(config('gatekeep.provisioning.jit'))->toBeTrue()
        ->and(config('gatekeep.provisioning.update_on_login'))->toBeTrue()
        ->and(config('gatekeep.provisioning.provisioner'))->toBe(DefaultUserProvisioner::class)
        ->and(config('gatekeep.replay.store'))->toBe('database')
        ->and(config('gatekeep.metadata_refresh.enabled'))->toBeTrue()
        ->and(config('gatekeep.metadata_refresh.schedule'))->toBe('daily')
        ->and(config('gatekeep.metadata.max_bytes'))->toBe(262144)
        ->and(config('gatekeep.audit.enabled'))->toBeTrue()
        ->and(config('gatekeep.redirect.allowed_hosts'))->toBe([])
        ->and(config('gatekeep.rate_limits.discover_per_minute'))->toBe(10)
        ->and(config('gatekeep.rate_limits.acs_per_minute'))->toBe(30);
});
