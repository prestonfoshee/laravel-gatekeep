<?php

declare(strict_types=1);

use Illuminate\Support\Facades\URL;

beforeEach(function () {
    config()->set('app.url', 'http://localhost');
    URL::forceRootUrl('http://localhost');
});

it('redirects a known email domain to the connection login', function () {
    $connection = samlConnection();

    $response = $this->post('/sso/discover', [
        'email' => 'Alice@ACME.com',
        'return_to' => '/account',
    ]);

    $response->assertRedirect(route('gatekeep.login', [
        'connection' => $connection,
        'return_to' => '/account',
    ]));
});

it('returns no sso when the domain has no enabled connection', function () {
    samlConnection(['enabled' => false]);

    $response = $this->post('/sso/discover', [
        'email' => 'alice@acme.com',
    ]);

    $response->assertStatus(422);
    $response->assertJsonPath('message', 'no SSO');
});

it('returns no sso for an unknown email', function () {
    samlConnection();

    $this->post('/sso/discover', [
        'email' => 'ada@unknown.test',
    ])->assertStatus(422)->assertJsonPath('message', 'no SSO');
});

it('drops an unsafe return path during discovery', function () {
    $connection = samlConnection();

    $this->post('/sso/discover', [
        'email' => 'alice@acme.com',
        'return_to' => 'https://evil.example/phish',
    ])->assertRedirect(route('gatekeep.login', $connection));
});

it('rate limits discovery', function () {
    config()->set('gatekeep.rate_limits.discover_per_minute', 1);
    samlConnection();

    $this->post('/sso/discover', ['email' => 'alice@acme.com'])->assertRedirect();
    $this->post('/sso/discover', ['email' => 'alice@acme.com'])->assertStatus(429);
});
