<?php

declare(strict_types=1);

namespace Gatekeep\Contracts;

use Illuminate\Http\Request;

interface TenantResolver
{
    /**
     * Return the tenant key, or null so the next resolver can try.
     */
    public function resolve(Request $request, ?string $email = null): ?string;
}
