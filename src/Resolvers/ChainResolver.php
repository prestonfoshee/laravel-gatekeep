<?php

declare(strict_types=1);

namespace Gatekeep\Resolvers;

use Gatekeep\Contracts\TenantResolver;
use Illuminate\Http\Request;

final class ChainResolver implements TenantResolver
{
    /**
     * @param  list<TenantResolver>  $resolvers
     */
    public function __construct(private readonly array $resolvers) {}

    public function resolve(Request $request, ?string $email = null): ?string
    {
        foreach ($this->resolvers as $resolver) {
            $tenantKey = $resolver->resolve($request, $email);

            if (is_string($tenantKey) && $tenantKey !== '') {
                return $tenantKey;
            }
        }

        return null;
    }
}
