<?php

declare(strict_types=1);

namespace Gatekeep\Http\Controllers;

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Contracts\TenantResolver;
use Gatekeep\Enums\Protocol;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Support\DomainNormalizer;
use Gatekeep\Support\SafeRedirect;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class DiscoverController
{
    public function __construct(
        private readonly TenantResolver $tenants,
        private readonly ConnectionRepository $connections,
        private readonly SafeRedirect $redirects,
    ) {}

    public function __invoke(Request $request): JsonResponse|RedirectResponse
    {
        $email = $request->input('email');
        $email = is_string($email) ? $email : null;
        $tenantKey = $this->tenants->resolve($request, $email);

        if ($tenantKey === null) {
            return $this->noSso();
        }

        $connection = $this->connectionFor($tenantKey, $email);

        if ($connection === null) {
            return $this->noSso();
        }

        $parameters = ['connection' => $connection->id];
        $returnTo = $request->input('return_to');

        if (is_string($returnTo)) {
            $safe = $this->redirects->sanitize($returnTo);

            if ($safe !== null) {
                $parameters['return_to'] = $safe;
            }
        }

        return redirect()->route('gatekeep.login', $parameters);
    }

    private function connectionFor(string $tenantKey, ?string $email): ?SsoConnection
    {
        $connections = $this->connections
            ->forTenant($tenantKey)
            ->filter(fn (SsoConnection $connection): bool => $connection->enabled && $connection->protocol === Protocol::Saml)
            ->values();

        if ($connections->isEmpty()) {
            return null;
        }

        $domain = $email === null ? null : DomainNormalizer::fromEmail($email);

        if ($domain !== null) {
            $matched = $connections->first(
                fn (SsoConnection $connection): bool => in_array($domain, $connection->domains, true),
            );

            if ($matched !== null) {
                return $matched;
            }
        }

        return $connections->first();
    }

    private function noSso(): JsonResponse
    {
        return response()->json([
            'message' => 'no SSO',
        ], 422);
    }
}
