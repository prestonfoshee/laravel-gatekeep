<?php

declare(strict_types=1);

use Gatekeep\Models\SsoIdentity;
use Gatekeep\Tests\Fixtures\User;
use Illuminate\Database\UniqueConstraintViolationException;

it('links an idp subject to a local user', function () {
    $connection = ssoConnection();
    $user = User::query()->create(['email' => 'alice@acme.com']);

    $identity = SsoIdentity::query()->create([
        'sso_connection_id' => $connection->id,
        'subject' => 'name-id-1',
        'user_type' => $user->getMorphClass(),
        'user_id' => $user->getKey(),
        'last_login_at' => '2026-01-02 03:04:05',
    ]);

    expect($identity->connection)->toBeInstanceOf($connection::class)
        ->and($identity->connection->is($connection))->toBeTrue()
        ->and($identity->user)->toBeInstanceOf(User::class)
        ->and($identity->user->is($user))->toBeTrue()
        ->and($identity->last_login_at?->toDateTimeString())->toBe('2026-01-02 03:04:05');
});

it('allows the same subject on a different connection only', function () {
    $acme = ssoConnection();
    $globex = ssoConnection([
        'tenant_key' => 'globex',
        'name' => 'Globex',
        'domains' => ['globex.com'],
    ]);
    $user = User::query()->create(['email' => 'alice@acme.com']);

    $attributes = [
        'subject' => 'name-id-1',
        'user_type' => $user->getMorphClass(),
        'user_id' => $user->getKey(),
    ];

    SsoIdentity::query()->create(['sso_connection_id' => $acme->id, ...$attributes]);
    SsoIdentity::query()->create(['sso_connection_id' => $globex->id, ...$attributes]);

    expect(fn () => SsoIdentity::query()->create(['sso_connection_id' => $acme->id, ...$attributes]))
        ->toThrow(UniqueConstraintViolationException::class);
});

it('removes identities when the connection is deleted', function () {
    $connection = ssoConnection();
    $user = User::query()->create(['email' => 'alice@acme.com']);

    SsoIdentity::query()->create([
        'sso_connection_id' => $connection->id,
        'subject' => 'name-id-1',
        'user_type' => $user->getMorphClass(),
        'user_id' => $user->getKey(),
    ]);

    $connection->delete();

    expect(SsoIdentity::query()->count())->toBe(0)
        ->and(User::query()->count())->toBe(1);
});
