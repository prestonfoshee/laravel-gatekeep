<?php

declare(strict_types=1);

namespace Gatekeep\Tests\Support;

use Gatekeep\Contracts\HostResolver;

final class StaticHostResolver implements HostResolver
{
    /**
     * @param  array<string, list<string>>  $addresses
     */
    public function __construct(private readonly array $addresses) {}

    public function addresses(string $host): array
    {
        return $this->addresses[$host] ?? [];
    }
}
