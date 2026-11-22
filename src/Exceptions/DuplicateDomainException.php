<?php

declare(strict_types=1);

namespace Gatekeep\Exceptions;

use RuntimeException;
use Throwable;

final class DuplicateDomainException extends RuntimeException
{
    /**
     * @param  list<string>  $domains
     */
    public function __construct(
        public readonly array $domains,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            'The SSO domain is already assigned to another connection: '.implode(', ', $domains).'.',
            previous: $previous,
        );
    }
}
