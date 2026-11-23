<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class IssuerMismatch extends SsoException
{
    public function __construct(string $message = 'The SSO response issuer does not match this connection.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'issuer_mismatch';
    }
}
