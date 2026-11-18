<?php

declare(strict_types=1);

use Gatekeep\GatekeepServiceProvider;

it('boots the package service provider', function () {
    expect(app()->getProvider(GatekeepServiceProvider::class))
        ->toBeInstanceOf(GatekeepServiceProvider::class);
});
