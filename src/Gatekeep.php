<?php

declare(strict_types=1);

namespace Gatekeep;

use Closure;

final class Gatekeep
{
    public function __construct(private readonly DriverManager $drivers) {}

    /**
     * @param  Closure(mixed): mixed  $callback
     */
    public function extend(string $driver, Closure $callback): self
    {
        $this->drivers->extend($driver, $callback);

        return $this;
    }

    public function driver(?string $driver = null): mixed
    {
        return $this->drivers->driver($driver);
    }
}
