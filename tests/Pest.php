<?php

declare(strict_types=1);

use Gatekeep\Enums\Protocol;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Tests\Support\SamlResponseFactory;
use Gatekeep\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);

/**
 * @param  array<string, mixed>  $overrides
 */
function ssoConnection(array $overrides = []): SsoConnection
{
    /** @var array<string, mixed> $attributes */
    $attributes = array_replace([
        'tenant_key' => 'acme',
        'name' => 'Acme',
        'protocol' => Protocol::Saml,
        'enabled' => true,
        'domains' => ['acme.com'],
        'config' => [
            'idp_entity_id' => 'https://idp.acme.com',
            'x509_certs' => ['cert-a'],
            'client_secret' => 'super-secret-value',
        ],
    ], $overrides);

    return SsoConnection::query()->create($attributes);
}

/**
 * @param  array<string, mixed>  $overrides
 */
function samlConnection(array $overrides = []): SsoConnection
{
    /** @var array<string, mixed> $config */
    $config = $overrides['config'] ?? [
        'idp_entity_id' => 'https://idp.acme.test/entity',
        'sso_url' => 'https://idp.acme.test/sso',
        'x509_certs' => [SamlResponseFactory::certificate()],
    ];

    unset($overrides['config']);

    return ssoConnection(array_replace([
        'config' => $config,
    ], $overrides));
}
