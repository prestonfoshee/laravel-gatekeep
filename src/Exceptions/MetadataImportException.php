<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use Throwable;

final class MetadataImportException extends SsoException
{
    public function __construct(string $message = 'The identity provider metadata could not be imported.', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public function errorCode(): string
    {
        return 'metadata_import_failed';
    }
}
