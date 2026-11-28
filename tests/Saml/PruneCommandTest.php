<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Gatekeep\Models\ReplayCache;
use Illuminate\Console\Scheduling\Schedule;

it('deletes expired replay cache rows', function () {
    ReplayCache::query()->create([
        'key' => hash('sha256', 'expired'),
        'expires_at' => CarbonImmutable::now()->subMinute(),
    ]);
    ReplayCache::query()->create([
        'key' => hash('sha256', 'fresh'),
        'expires_at' => CarbonImmutable::now()->addHour(),
    ]);

    $this->artisan('gatekeep:prune')
        ->expectsOutputToContain('Pruned 1 expired replay-cache entries.')
        ->assertSuccessful();

    expect(ReplayCache::query()->pluck('key')->all())->toBe([hash('sha256', 'fresh')]);
});

it('schedules the prune command hourly', function () {
    $commands = collect(app(Schedule::class)->events())
        ->map(fn (object $event): string => property_exists($event, 'command') && is_string($event->command) ? $event->command : '')
        ->implode(' ');

    expect($commands)->toContain('gatekeep:prune');
});
