<?php

declare(strict_types=1);

namespace Gatekeep\ValueObjects;

final readonly class LoginIntent
{
    public function __construct(
        public ?string $returnTo = null,
        public ?string $relayState = null,
        public bool $forceAuthn = false,
    ) {}
}
