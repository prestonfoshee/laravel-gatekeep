<?php

declare(strict_types=1);

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Exceptions\DuplicateDomainException;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Repositories\EloquentConnectionRepository;

it('returns the enabled connection for an email domain', function () {
    $acme = ssoConnection();

    $repository = app(ConnectionRepository::class);

    expect($repository)->toBeInstanceOf(EloquentConnectionRepository::class)
        ->and($repository->forDomain('alice@does-not-matter.com'))->toBeNull()
        ->and($repository->forDomain('ACME.COM')?->is($acme))->toBeTrue()
        ->and($repository->forDomain('acme.com.')?->is($acme))->toBeTrue();
});

it('finds an internationalized domain in either unicode or punycode', function () {
    $connection = ssoConnection(['domains' => ['München.de']]);
    $repository = app(ConnectionRepository::class);

    expect($repository->forDomain('münchen.de')?->is($connection))->toBeTrue()
        ->and($repository->forDomain('MÜNCHEN.DE')?->is($connection))->toBeTrue()
        ->and($repository->forDomain('xn--mnchen-3ya.de')?->is($connection))->toBeTrue();
});

it('ignores disabled connections when resolving a domain', function () {
    $connection = ssoConnection(['enabled' => false]);
    $repository = app(ConnectionRepository::class);

    expect($repository->forDomain('acme.com'))->toBeNull()
        ->and($repository->find($connection->id)?->is($connection))->toBeTrue();
});

it('keeps a disabled connection\'s domain reserved', function () {
    ssoConnection(['enabled' => false]);

    expect(fn () => ssoConnection([
        'name' => 'Other',
        'domains' => ['acme.com'],
    ]))->toThrow(DuplicateDomainException::class);
});

it('lists every connection for a tenant, including disabled ones, by name', function () {
    ssoConnection(['name' => 'Zed', 'domains' => ['zed.example']]);
    ssoConnection(['name' => 'Alpha', 'domains' => ['alpha.example'], 'enabled' => false]);
    ssoConnection(['tenant_key' => 'globex', 'name' => 'Globex', 'domains' => ['globex.example']]);

    $connections = app(ConnectionRepository::class)->forTenant('acme');

    expect($connections)->toHaveCount(2)
        ->and($connections->pluck('name')->all())->toBe(['Alpha', 'Zed'])
        ->and($connections->first())->toBeInstanceOf(SsoConnection::class);
});

it('returns null when the connection id is unknown or the domain is unusable', function () {
    $repository = app(ConnectionRepository::class);

    expect($repository->find('01J00000000000000000000000'))->toBeNull()
        ->and($repository->forDomain(''))->toBeNull()
        ->and($repository->forDomain('not a domain'))->toBeNull();
});
