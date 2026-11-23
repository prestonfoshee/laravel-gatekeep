<?php

declare(strict_types=1);

use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\DuplicateDomainException;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Models\SsoConnectionDomain;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

it('stores config encrypted and keeps it out of serialized output', function () {
    $connection = ssoConnection();

    $raw = DB::table('sso_connections')->where('id', $connection->id)->value('config');

    expect($raw)->toBeString()
        ->and($raw)->not->toContain('super-secret-value')
        ->and($raw)->not->toContain('cert-a')
        ->and($connection->fresh()->config)->toBe([
            'idp_entity_id' => 'https://idp.acme.com',
            'x509_certs' => ['cert-a'],
            'client_secret' => 'super-secret-value',
        ])
        ->and($connection->toArray())->not->toHaveKey('config')
        ->and($connection->toJson())->not->toContain('super-secret-value');

    $logged = [];
    Log::listen(function (MessageLogged $event) use (&$logged): void {
        $logged[] = json_encode($event->context);
    });

    Log::info('connection saved', ['connection' => $connection]);

    expect(implode("\n", $logged))->not->toContain('super-secret-value');
});

it('normalizes domains and syncs the unique lookup table', function () {
    $connection = ssoConnection([
        'domains' => ['  ACME.COM. ', 'München.de', 'münchen.de'],
    ]);

    expect($connection->fresh()->domains)->toBe([
        'acme.com',
        'xn--mnchen-3ya.de',
    ])->and(SsoConnectionDomain::query()->orderBy('domain')->pluck('domain')->all())->toBe([
        'acme.com',
        'xn--mnchen-3ya.de',
    ]);
});

it('replaces domain lookup rows without clearing verification', function () {
    $connection = ssoConnection();
    SsoConnectionDomain::query()->where('domain', 'acme.com')->update([
        'verified_at' => '2026-01-01 00:00:00',
    ]);

    $connection->update([
        'name' => 'Acme Inc',
        'domains' => ['acme.com', 'acme.io'],
    ]);

    expect(SsoConnectionDomain::query()->orderBy('domain')->pluck('domain')->all())->toBe([
        'acme.com',
        'acme.io',
    ])->and(SsoConnectionDomain::query()->where('domain', 'acme.com')->value('verified_at'))->not->toBeNull();

    $connection->update(['domains' => ['acme.io']]);

    expect(SsoConnectionDomain::query()->pluck('domain')->all())->toBe(['acme.io']);
});

it('rejects a domain that already belongs to another connection', function () {
    ssoConnection();

    expect(fn () => ssoConnection([
        'tenant_key' => 'globex',
        'name' => 'Globex',
        'domains' => ['ACME.com'],
    ]))->toThrow(DuplicateDomainException::class);

    expect(SsoConnection::query()->count())->toBe(1)
        ->and(SsoConnectionDomain::query()->count())->toBe(1);
});

it('treats a unicode domain and its punycode form as the same domain', function () {
    ssoConnection(['domains' => ['München.de']]);

    expect(fn () => ssoConnection([
        'name' => 'Other',
        'domains' => ['xn--mnchen-3ya.de'],
    ]))->toThrow(DuplicateDomainException::class);
});

it('rejects domains that are not plain host names', function (mixed $domain) {
    expect(fn () => ssoConnection(['domains' => [$domain]]))
        ->toThrow(InvalidArgumentException::class);

    expect(SsoConnection::query()->count())->toBe(0);
})->with([
    'blank' => '   ',
    'email' => 'alice@acme.com',
    'whitespace' => 'acme .com',
    'not a string' => [['acme.com']],
]);

it('stores the protocol as a backed enum and defaults enabled to true', function () {
    $connection = ssoConnection([
        'protocol' => Protocol::Oidc,
        'enabled' => false,
    ]);

    expect($connection->fresh()->protocol)->toBe(Protocol::Oidc)
        ->and(DB::table('sso_connections')->where('id', $connection->id)->value('protocol'))->toBe('oidc')
        ->and($connection->enabled)->toBeFalse();

    SsoConnection::query()->create([
        'tenant_key' => 'default-enabled',
        'name' => 'Enabled',
        'protocol' => Protocol::Saml,
        'domains' => ['enabled.example'],
        'config' => ['client_secret' => 'another-secret'],
    ]);

    $created = SsoConnection::query()->where('name', 'Enabled')->firstOrFail();

    expect($created->enabled)->toBeTrue();
});

it('deletes domain rows when the connection is deleted', function () {
    $connection = ssoConnection();

    $connection->delete();

    expect(SsoConnectionDomain::query()->count())->toBe(0);
});
