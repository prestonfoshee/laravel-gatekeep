<?php

declare(strict_types=1);

namespace Gatekeep\Contracts;

interface HostResolver
{
    /**
     * Addresses a metadata host resolves to. An IP host is returned as itself.
     *
     * @return list<string>
     */
    public function addresses(string $host): array;
}
