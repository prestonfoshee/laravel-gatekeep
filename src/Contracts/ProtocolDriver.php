<?php

declare(strict_types=1);

namespace Gatekeep\Contracts;

use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Models\SsoConnection;
use Gatekeep\ValueObjects\LoginIntent;
use Gatekeep\ValueObjects\SsoUser;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

interface ProtocolDriver
{
    public function protocol(): Protocol;

    public function redirect(SsoConnection $connection, LoginIntent $intent): RedirectResponse;

    /**
     * @throws SsoException
     */
    public function handleCallback(SsoConnection $connection, Request $request): SsoUser;

    public function metadata(SsoConnection $connection): ?Response;
}
