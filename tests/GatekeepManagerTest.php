<?php

declare(strict_types=1);

use Gatekeep\DriverManager;
use Gatekeep\Enums\Protocol;
use Gatekeep\Gatekeep as GatekeepManager;
use Gatekeep\Saml\SamlDriver;

it('resolves custom drivers through the facade and manager', function () {
    $marker = new stdClass;

    expect(app(DriverManager::class)->getDefaultDriver())->toBe('saml')
        ->and(app(GatekeepManager::class)->driver())->toBeInstanceOf(SamlDriver::class)
        ->and(app(GatekeepManager::class)->driver()->protocol())->toBe(Protocol::Saml);

    Gatekeep::extend('custom', fn () => $marker);

    expect(Gatekeep::driver('custom'))->toBe($marker)
        ->and(app(GatekeepManager::class)->driver('custom'))->toBe($marker)
        ->and(app('gatekeep'))->toBeInstanceOf(GatekeepManager::class);
});
