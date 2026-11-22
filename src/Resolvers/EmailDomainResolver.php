<?php

declare(strict_types=1);

namespace Gatekeep\Resolvers;

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Contracts\TenantResolver;
use Gatekeep\Support\DomainNormalizer;
use Illuminate\Http\Request;

final class EmailDomainResolver implements TenantResolver
{
    public function __construct(private readonly ConnectionRepository $connections) {}

    public function resolve(Request $request, ?string $email = null): ?string
    {
        if ($email === null) {
            $input = $request->input('email');
            $email = is_string($input) ? $input : null;
        }

        if ($email === null || trim($email) === '') {
            return null;
        }

        $domain = DomainNormalizer::fromEmail($email);

        if ($domain === null) {
            return null;
        }

        return $this->connections->forDomain($domain)?->tenant_key;
    }
}
