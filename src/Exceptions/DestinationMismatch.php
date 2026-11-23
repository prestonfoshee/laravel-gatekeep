<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class DestinationMismatch extends SsoException
{
    public function __construct(string $message = 'The SSO response was sent to the wrong destination.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'destination_mismatch';
    }
}
