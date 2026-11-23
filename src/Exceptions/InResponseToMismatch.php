<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class InResponseToMismatch extends SsoException
{
    public function __construct(string $message = 'The SSO response does not match the login request.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'in_response_to_mismatch';
    }
}
