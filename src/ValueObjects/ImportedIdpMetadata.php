<?php

declare(strict_types=1);

namespace Gatekeep\ValueObjects;

final readonly class ImportedIdpMetadata
{
    /**
     * @param  list<string>  $certificates
     */
    public function __construct(
        public string $entityId,
        public string $ssoUrl,
        public array $certificates,
    ) {}
}
