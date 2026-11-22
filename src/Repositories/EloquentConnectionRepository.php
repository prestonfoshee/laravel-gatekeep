<?php

declare(strict_types=1);

namespace Gatekeep\Repositories;

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Models\SsoConnectionDomain;
use Gatekeep\Support\DomainNormalizer;
use Illuminate\Support\Collection;
use InvalidArgumentException;

final class EloquentConnectionRepository implements ConnectionRepository
{
    public function find(string $connectionId): ?SsoConnection
    {
        return SsoConnection::query()->whereKey($connectionId)->first();
    }

    public function forTenant(string $tenantKey): Collection
    {
        return SsoConnection::query()
            ->where('tenant_key', $tenantKey)
            ->orderBy('name')
            ->orderBy('id')
            ->get();
    }

    public function forDomain(string $domain): ?SsoConnection
    {
        try {
            $normalized = DomainNormalizer::normalize($domain);
        } catch (InvalidArgumentException) {
            return null;
        }

        $connectionId = SsoConnectionDomain::query()
            ->where('domain', $normalized)
            ->value('sso_connection_id');

        if (! is_string($connectionId) || $connectionId === '') {
            return null;
        }

        return SsoConnection::query()
            ->whereKey($connectionId)
            ->where('enabled', true)
            ->first();
    }
}
