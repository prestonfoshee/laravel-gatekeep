<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Cache;

it('exempts the assertion consumer from csrf and rate limits it', function () {
    $route = app('router')->getRoutes()->getByName('gatekeep.saml.acs');

    expect($route)->not->toBeNull()
        ->and($route->excludedMiddleware())->toContain(PreventRequestForgery::class)
        ->and($route->gatherMiddleware())->toContain('throttle:gatekeep-acs');

    expect(app(PreventRequestForgery::class)->getExcludedPaths())->toContain('sso/saml/*/acs');
});

it('rate limits the assertion consumer', function () {
    Cache::flush();
    config()->set('gatekeep.rate_limits.acs_per_minute', 1);
    $connection = samlConnection();

    $this->post(route('gatekeep.saml.acs', $connection, false), [])->assertStatus(422);
    $this->post(route('gatekeep.saml.acs', $connection, false), [])->assertStatus(429);
});
