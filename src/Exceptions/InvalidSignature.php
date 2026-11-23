<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class InvalidSignature extends SsoException
{
    public function __construct(string $message = 'The SSO response signature is invalid.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'invalid_signature';
    }
}
