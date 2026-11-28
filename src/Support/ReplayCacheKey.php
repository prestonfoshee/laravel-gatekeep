<?php

declare(strict_types=1);

namespace Gatekeep\Support;

final class ReplayCacheKey
{
    public static function make(string $connectionId, string $messageId): string
    {
        return hash('sha256', $connectionId.'|'.$messageId);
    }
}
