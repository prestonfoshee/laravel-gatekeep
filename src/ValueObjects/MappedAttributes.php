<?php

declare(strict_types=1);

namespace Gatekeep\ValueObjects;

final readonly class MappedAttributes
{
    /**
     * @param  list<string>  $groups
     * @param  array<array-key, mixed>  $attributes
     */
    public function __construct(
        public ?string $email = null,
        public ?string $firstName = null,
        public ?string $lastName = null,
        public array $groups = [],
        public array $attributes = [],
    ) {}
}
