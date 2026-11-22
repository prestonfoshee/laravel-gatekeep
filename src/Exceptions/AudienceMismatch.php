<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class AudienceMismatch extends SsoException
{
    public function __construct(string $message = 'The SSO response audience does not match this service provider.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'audience_mismatch';
    }
}
