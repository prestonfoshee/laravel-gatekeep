<?php

declare(strict_types=1);

namespace Gatekeep\ValueObjects;

final readonly class SsoUser
{
    /**
     * @param  list<string>  $groups
     * @param  array<array-key, mixed>  $raw
     */
    public function __construct(
        public string $id,
        public string $email,
        public ?string $firstName,
        public ?string $lastName,
        public array $groups,
        public array $raw,
    ) {}
}
