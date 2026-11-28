<?php

declare(strict_types=1);

use Gatekeep\Contracts\UserProvisioner;
use Gatekeep\Tests\Fixtures\User;
use Gatekeep\Tests\Support\RecordingProvisioner;
use Gatekeep\Tests\Support\SamlResponseFactory;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\URL;

beforeEach(function () {
    config()->set('app.url', 'http://localhost');
    config()->set('auth.providers.users.model', User::class);
    config()->set('auth.defaults.guard', 'web');
    URL::forceRootUrl('http://localhost');

    app()->instance(UserProvisioner::class, new RecordingProvisioner);
});

it('accepts a signature from either certificate while both are configured', function () {
    $connection = samlConnection([
        'config' => [
            'idp_entity_id' => 'https://idp.acme.test/entity',
            'sso_url' => 'https://idp.acme.test/sso',
            'x509_certs' => [
                SamlResponseFactory::certificate(),
                SamlResponseFactory::secondCertificate(),
            ],
        ],
    ]);

    foreach (['idp', 'second'] as $signing) {
        Auth::logout();
        $requestId = startSamlLogin($connection);

        postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
            'signing' => $signing,
        ])))->assertRedirect();

        $this->assertAuthenticated();
    }

    expect(User::query()->count())->toBe(2);
});
