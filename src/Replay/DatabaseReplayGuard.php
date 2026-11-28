<?php

declare(strict_types=1);

namespace Gatekeep\Replay;

use Carbon\CarbonImmutable;
use Gatekeep\Contracts\ReplayGuard;
use Gatekeep\Models\ReplayCache;
use Gatekeep\Support\ReplayCacheKey;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

final class DatabaseReplayGuard implements ReplayGuard
{
    public function claim(string $connectionId, string $messageId, CarbonImmutable $expiresAt): bool
    {
        $key = ReplayCacheKey::make($connectionId, $messageId);

        try {
            return DB::transaction(function () use ($key, $expiresAt): bool {
                $existing = ReplayCache::query()->whereKey($key)->lockForUpdate()->first();

                if ($existing !== null) {
                    if ($existing->expires_at->greaterThan(CarbonImmutable::now())) {
                        return false;
                    }

                    $existing->delete();
                }

                ReplayCache::query()->create([
                    'key' => $key,
                    'expires_at' => $expiresAt,
                ]);

                return true;
            });
        } catch (UniqueConstraintViolationException) {
            return false;
        }
    }
}
