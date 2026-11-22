<?php

declare(strict_types=1);

use Gatekeep\DriverManager;
use Gatekeep\Gatekeep as GatekeepManager;

it('resolves custom drivers through the facade and manager', function () {
    $marker = new stdClass;

    expect(app(DriverManager::class)->getDefaultDriver())->toBe('saml')
        ->and(fn () => app(GatekeepManager::class)->driver())->toThrow(InvalidArgumentException::class);

    Gatekeep::extend('custom', fn () => $marker);

    expect(Gatekeep::driver('custom'))->toBe($marker)
        ->and(app(GatekeepManager::class)->driver('custom'))->toBe($marker)
        ->and(app('gatekeep'))->toBeInstanceOf(GatekeepManager::class);
});
