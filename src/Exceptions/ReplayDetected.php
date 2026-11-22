<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class ReplayDetected extends SsoException
{
    public function __construct(string $message = 'The SSO response was already used.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'replay_detected';
    }
}
