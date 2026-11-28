<?php

declare(strict_types=1);

namespace Gatekeep\Console;

use Carbon\CarbonImmutable;
use Gatekeep\Models\ReplayCache;
use Illuminate\Console\Command;

final class PruneReplayCacheCommand extends Command
{
    protected $signature = 'gatekeep:prune';

    protected $description = 'Delete expired SSO replay-cache rows.';

    public function handle(): int
    {
        $expired = ReplayCache::query()->where('expires_at', '<=', CarbonImmutable::now());
        $deleted = $expired->count();
        $expired->delete();

        $this->info('Pruned '.$deleted.' expired replay-cache entries.');

        return self::SUCCESS;
    }
}
