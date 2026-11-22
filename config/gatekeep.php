<?php

declare(strict_types=1);
use App\Models\User;
use Gatekeep\Provisioning\DefaultUserProvisioner;
use Gatekeep\Resolvers\EmailDomainResolver;
use Gatekeep\Resolvers\SubdomainResolver;

return [
    'route_prefix' => 'sso',
    'middleware' => ['web'],
    'user_model' => User::class,
    'guard' => 'web',
    'home' => '/dashboard',
    'resolvers' => [
        EmailDomainResolver::class,
        SubdomainResolver::class,
    ],
    'subdomain' => [
        'base_domain' => env('GATEKEEP_BASE_DOMAIN'),
    ],
    'saml' => [
        'sp_entity_id' => env('GATEKEEP_SP_ENTITY_ID'),
        'want_assertions_signed' => true,
        'want_messages_signed' => false,
        'allow_idp_initiated' => false,
        'clock_skew_seconds' => 120,
        'signature_algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    ],
    'oidc' => [
        'scopes' => ['openid', 'email', 'profile'],
        'use_pkce' => true,
    ],
    'provisioning' => [
        'jit' => true,
        'update_on_login' => true,
        'provisioner' => DefaultUserProvisioner::class,
    ],
    'replay' => [
        'store' => 'database',
    ],
    'metadata_refresh' => [
        'enabled' => true,
        'schedule' => 'daily',
    ],
    'audit' => [
        'enabled' => true,
    ],
];
