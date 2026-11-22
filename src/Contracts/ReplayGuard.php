<?php

declare(strict_types=1);

namespace Gatekeep\Contracts;

use Carbon\CarbonImmutable;

interface ReplayGuard
{
    /**
     * Return false if the message id was already seen. Store it until it expires.
     */
    public function claim(string $connectionId, string $messageId, CarbonImmutable $expiresAt): bool;
}
