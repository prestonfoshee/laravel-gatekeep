<?php

declare(strict_types=1);

namespace Gatekeep\Contracts;

use Gatekeep\Models\SsoConnection;
use Illuminate\Support\Collection;

interface ConnectionRepository
{
    public function find(string $connectionId): ?SsoConnection;

    /**
     * @return Collection<int, SsoConnection>
     */
    public function forTenant(string $tenantKey): Collection;

    public function forDomain(string $domain): ?SsoConnection;
}
