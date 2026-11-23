<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use RuntimeException;
use Throwable;

class SsoException extends RuntimeException
{
    public function __construct(string $message = 'SSO authentication failed.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'sso_error';
    }
}
