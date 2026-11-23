<?php

declare(strict_types=1);

namespace Gatekeep\Contracts;

use Gatekeep\Models\SsoConnection;
use Gatekeep\ValueObjects\MappedAttributes;

interface AttributeMapper
{
    /**
     * @param  array<array-key, mixed>  $rawAttributes
     */
    public function map(SsoConnection $connection, array $rawAttributes): MappedAttributes;
}
