<?php

declare(strict_types=1);

namespace Gatekeep\Http\Controllers;

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Contracts\UserProvisioner;
use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Http\LoginAttemptWriter;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Saml\SamlDriver;
use Gatekeep\Saml\SamlSession;
use Gatekeep\Support\SafeRedirect;
use Gatekeep\ValueObjects\SsoUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

final class AssertionConsumerServiceController
{
    public function __construct(
        private readonly Container $container,
        private readonly ConnectionRepository $connections,
        private readonly SamlDriver $driver,
        private readonly SafeRedirect $redirects,
        private readonly LoginAttemptWriter $attempts,
    ) {}

    public function __invoke(Request $request, string $connection): JsonResponse|RedirectResponse
    {
        $model = $this->connections->find($connection);

        if ($model === null || ! $model->enabled || $model->protocol !== Protocol::Saml) {
            return $this->attempts->unknownConnection($model?->id, $request);
        }

        try {
            $ssoUser = $this->driver->handleCallback($model, $request);
            $account = $this->provision($model, $ssoUser);
            $guard = config('gatekeep.guard', 'web');
            Auth::guard(is_string($guard) && $guard !== '' ? $guard : 'web')->login($account);
            $request->session()->regenerate();
            $this->attempts->record($model->id, 'succeeded', null, $request);

            return redirect()->to($this->destination($model->id, $request));
        } catch (SsoException $exception) {
            return $this->attempts->failure($model->id, $exception, $request);
        }
    }

    private function provision(SsoConnection $connection, SsoUser $user): Authenticatable
    {
        return $this->container->make(UserProvisioner::class)->provision($connection, $user);
    }

    private function destination(string $connectionId, Request $request): string
    {
        $stored = session()->pull(SamlSession::returnTo($connectionId));
        $stored = is_string($stored) ? $this->redirects->sanitize($stored) : null;

        if ($stored !== null) {
            return $stored;
        }

        $relayState = $request->input('RelayState');
        $relayState = is_string($relayState) ? $this->redirects->sanitize($relayState) : null;

        if ($relayState !== null) {
            return $relayState;
        }

        $home = config('gatekeep.home', '/dashboard');
        $safeHome = $this->redirects->sanitize(is_string($home) ? $home : null);

        return $safeHome ?? '/';
    }
}
