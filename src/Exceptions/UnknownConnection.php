<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class UnknownConnection extends SsoException
{
    public function __construct(string $message = 'The SSO connection could not be found.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'unknown_connection';
    }
}
