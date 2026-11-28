<?php

declare(strict_types=1);

namespace Gatekeep\Http\Controllers;

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Http\LoginAttemptWriter;
use Gatekeep\Saml\SamlDriver;
use Gatekeep\ValueObjects\LoginIntent;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class LoginController
{
    public function __construct(
        private readonly ConnectionRepository $connections,
        private readonly SamlDriver $driver,
        private readonly LoginAttemptWriter $attempts,
    ) {}

    public function __invoke(Request $request, string $connection): JsonResponse|RedirectResponse
    {
        $model = $this->connections->find($connection);

        if ($model === null || ! $model->enabled || $model->protocol !== Protocol::Saml) {
            return $this->attempts->unknownConnection($model?->id, $request);
        }

        $returnTo = $request->query('return_to');
        $intent = new LoginIntent(
            returnTo: is_string($returnTo) ? $returnTo : null,
            forceAuthn: $request->boolean('force_authn'),
        );

        try {
            return $this->driver->redirect($model, $intent);
        } catch (SsoException $exception) {
            return $this->attempts->failure($model->id, $exception, $request);
        }
    }
}
