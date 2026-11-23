<?php

declare(strict_types=1);

use Gatekeep\Http\Controllers\AssertionConsumerServiceController;
use Gatekeep\Http\Controllers\DiscoverController;
use Gatekeep\Http\Controllers\LoginController;
use Gatekeep\Http\Controllers\MetadataController;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Route;

$prefix = config('gatekeep.route_prefix', 'sso');
$middleware = config('gatekeep.middleware', ['web']);

Route::middleware(is_array($middleware) ? $middleware : ['web'])
    ->prefix(is_string($prefix) ? trim($prefix, '/') : 'sso')
    ->name('gatekeep.')
    ->group(function (): void {
        Route::post('/discover', DiscoverController::class)
            ->middleware('throttle:gatekeep-discover')
            ->name('discover');

        Route::get('/saml/{connection}/metadata', MetadataController::class)
            ->name('saml.metadata');

        Route::post('/saml/{connection}/acs', AssertionConsumerServiceController::class)
            ->middleware('throttle:gatekeep-acs')
            ->withoutMiddleware([PreventRequestForgery::class])
            ->name('saml.acs');

        Route::get('/{connection}/login', LoginController::class)
            ->name('login');
    });
