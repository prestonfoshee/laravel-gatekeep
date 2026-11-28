<?php

declare(strict_types=1);

namespace Gatekeep\Http\Controllers;

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Http\LoginAttemptWriter;
use Gatekeep\Saml\SamlDriver;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

final class MetadataController
{
    public function __construct(
        private readonly ConnectionRepository $connections,
        private readonly SamlDriver $driver,
        private readonly LoginAttemptWriter $attempts,
    ) {}

    public function __invoke(Request $request, string $connection): JsonResponse|Response
    {
        $model = $this->connections->find($connection);

        if ($model === null || $model->protocol !== Protocol::Saml) {
            return $this->attempts->unknownConnection($model?->id, $request);
        }

        try {
            return $this->driver->metadata($model);
        } catch (SsoException $exception) {
            return $this->attempts->failure($model->id, $exception, $request);
        }
    }
}
