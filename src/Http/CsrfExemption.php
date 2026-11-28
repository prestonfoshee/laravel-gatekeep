<?php

declare(strict_types=1);

namespace Gatekeep\Http;

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;

final class CsrfExemption
{
    /**
     * CSRF middleware that may sit on the web group.
     *
     * Laravel 12 registers ValidateCsrfToken. Laravel 13 registers PreventRequestForgery.
     * VerifyCsrfToken remains for applications that still list the older class.
     *
     * @return list<class-string>
     */
    public static function classes(): array
    {
        $classes = [];

        foreach (self::candidates() as $class) {
            if (class_exists($class)) {
                $classes[] = $class;
            }
        }

        return $classes;
    }

    public static function except(string $uri): void
    {
        foreach (self::classes() as $class) {
            self::exceptOn($class, $uri);
        }
    }

    /**
     * @return list<class-string>
     */
    private static function candidates(): array
    {
        return [
            PreventRequestForgery::class,
            ValidateCsrfToken::class,
            VerifyCsrfToken::class,
        ];
    }

    /**
     * @param  class-string  $class
     */
    private static function exceptOn(string $class, string $uri): void
    {
        if (! method_exists($class, 'except')) {
            return;
        }

        $class::except($uri);
    }
}
