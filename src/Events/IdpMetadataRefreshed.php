<?php

declare(strict_types=1);

namespace Gatekeep\Events;

final readonly class IdpMetadataRefreshed
{
    public function __construct(
        public string $connectionId,
        public ?string $metadataUrl,
    ) {}
}
