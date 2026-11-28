<?php

declare(strict_types=1);

use Gatekeep\Http\CsrfExemption;
use Illuminate\Support\Facades\Cache;

it('exempts the assertion consumer from csrf and rate limits it', function () {
    $route = app('router')->getRoutes()->getByName('gatekeep.saml.acs');
    $csrf = CsrfExemption::classes();

    expect($route)->not->toBeNull()
        ->and($csrf)->not->toBeEmpty()
        ->and($route->gatherMiddleware())->toContain('throttle:gatekeep-acs');

    foreach ($csrf as $class) {
        expect($route->excludedMiddleware())->toContain($class)
            ->and(app($class)->getExcludedPaths())->toContain('sso/saml/*/acs');
    }
});

it('rate limits the assertion consumer', function () {
    Cache::flush();
    config()->set('gatekeep.rate_limits.acs_per_minute', 1);
    $connection = samlConnection();

    $this->post(route('gatekeep.saml.acs', $connection, false), [])->assertStatus(422);
    $this->post(route('gatekeep.saml.acs', $connection, false), [])->assertStatus(429);
});
