<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Gatekeep\Contracts\ReplayGuard;
use Gatekeep\Models\ReplayCache;
use Gatekeep\Replay\CacheReplayGuard;
use Gatekeep\Replay\DatabaseReplayGuard;
use Gatekeep\Support\ReplayCacheKey;
use Illuminate\Support\Facades\Cache;

it('claims a message id once in the database until it expires', function () {
    $guard = new DatabaseReplayGuard;
    $expiresAt = CarbonImmutable::now()->addMinutes(5);

    expect($guard->claim('connection', 'assertion', $expiresAt))->toBeTrue()
        ->and($guard->claim('connection', 'assertion', $expiresAt))->toBeFalse()
        ->and($guard->claim('other-connection', 'assertion', $expiresAt))->toBeTrue()
        ->and(ReplayCache::query()->whereKey(ReplayCacheKey::make('connection', 'assertion'))->exists())->toBeTrue();
});

it('reclaims an expired database entry', function () {
    $guard = new DatabaseReplayGuard;
    $key = ReplayCacheKey::make('connection', 'old');

    ReplayCache::query()->create([
        'key' => $key,
        'expires_at' => CarbonImmutable::now()->subMinute(),
    ]);

    expect($guard->claim('connection', 'old', CarbonImmutable::now()->addMinute()))->toBeTrue()
        ->and(ReplayCache::query()->whereKey($key)->first()?->expires_at?->isFuture())->toBeTrue();
});

it('claims a message id once in the cache', function () {
    Cache::flush();
    $guard = new CacheReplayGuard;
    $expiresAt = CarbonImmutable::now()->addMinute();

    expect($guard->claim('connection', 'assertion', $expiresAt))->toBeTrue()
        ->and($guard->claim('connection', 'assertion', $expiresAt))->toBeFalse()
        ->and($guard->claim('connection', 'expired', CarbonImmutable::now()->subSecond()))->toBeFalse()
        ->and(Cache::has(ReplayCacheKey::make('connection', 'assertion')))->toBeTrue();
});

it('binds the replay guard from configuration', function () {
    expect(app(ReplayGuard::class))->toBeInstanceOf(DatabaseReplayGuard::class);

    config()->set('gatekeep.replay.store', 'cache');
    app()->forgetInstance(ReplayGuard::class);

    expect(app(ReplayGuard::class))->toBeInstanceOf(CacheReplayGuard::class);
});
