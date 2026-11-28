<?php

declare(strict_types=1);

namespace Gatekeep\Http;

use Gatekeep\Exceptions\ProvisioningDenied;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Exceptions\UnknownConnection;
use Gatekeep\Models\LoginAttempt;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

final class LoginAttemptWriter
{
    public function record(?string $connectionId, string $status, ?string $errorCode, Request $request): void
    {
        if (config('gatekeep.audit.enabled') !== true) {
            return;
        }

        $ip = $request->ip();

        LoginAttempt::query()->create([
            'sso_connection_id' => $connectionId,
            'status' => $status,
            'error_code' => $errorCode,
            'ip' => is_string($ip) ? substr($ip, 0, 45) : null,
        ]);
    }

    public function failure(?string $connectionId, SsoException $exception, Request $request): JsonResponse
    {
        $this->record($connectionId, 'failed', $exception->errorCode(), $request);

        Log::warning('SSO login failed.', [
            'error_code' => $exception->errorCode(),
        ]);

        return response()->json([
            'message' => $exception->getMessage(),
            'error_code' => $exception->errorCode(),
        ], $this->status($exception));
    }

    public function unknownConnection(?string $connectionId, Request $request): JsonResponse
    {
        return $this->failure($connectionId, new UnknownConnection, $request);
    }

    private function status(SsoException $exception): int
    {
        if ($exception instanceof UnknownConnection) {
            return 404;
        }

        if ($exception instanceof ProvisioningDenied) {
            return 403;
        }

        return 422;
    }
}
