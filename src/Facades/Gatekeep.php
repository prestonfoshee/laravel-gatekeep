<?php

declare(strict_types=1);

namespace Gatekeep\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Gatekeep\Gatekeep extend(string $driver, \Closure $callback)
 * @method static mixed driver(string|null $driver = null)
 *
 * @see \Gatekeep\Gatekeep
 */
final class Gatekeep extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Gatekeep\Gatekeep::class;
    }
}
