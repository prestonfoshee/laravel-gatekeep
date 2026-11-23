<?php

declare(strict_types=1);

namespace Gatekeep\Resolvers;

use Gatekeep\Contracts\TenantResolver;
use Gatekeep\Support\DomainNormalizer;
use Illuminate\Http\Request;

final class SubdomainResolver implements TenantResolver
{
    public function resolve(Request $request, ?string $email = null): ?string
    {
        $baseDomain = config('gatekeep.subdomain.base_domain');

        if (! is_string($baseDomain) || trim($baseDomain) === '') {
            return null;
        }

        return DomainNormalizer::subdomain($request->getHost(), $baseDomain);
    }
}
