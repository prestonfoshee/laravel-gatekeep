<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class ProvisioningDenied extends SsoException
{
    public function __construct(string $message = 'The user is not allowed to sign in through this connection.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'provisioning_denied';
    }
}
