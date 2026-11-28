<?php

declare(strict_types=1);

namespace Gatekeep\Events;

final readonly class IdpCertificateChanged
{
    public function __construct(
        public string $connectionId,
    ) {}
}
