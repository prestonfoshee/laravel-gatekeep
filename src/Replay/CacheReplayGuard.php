<?php

declare(strict_types=1);

namespace Gatekeep\Replay;

use Carbon\CarbonImmutable;
use Gatekeep\Contracts\ReplayGuard;
use Gatekeep\Support\ReplayCacheKey;
use Illuminate\Support\Facades\Cache;

final class CacheReplayGuard implements ReplayGuard
{
    public function claim(string $connectionId, string $messageId, CarbonImmutable $expiresAt): bool
    {
        $ttl = $expiresAt->getTimestamp() - time();

        if ($ttl <= 0) {
            return false;
        }

        return Cache::add(ReplayCacheKey::make($connectionId, $messageId), '1', $expiresAt);
    }
}
