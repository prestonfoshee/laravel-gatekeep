<?php

declare(strict_types=1);

use Gatekeep\Contracts\UserProvisioner;
use Gatekeep\Models\LoginAttempt;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Tests\Fixtures\User;
use Gatekeep\Tests\Support\RecordingProvisioner;
use Gatekeep\Tests\Support\SamlResponseFactory;
use Illuminate\Support\Facades\URL;

beforeEach(function () {
    config()->set('app.url', 'http://localhost');
    config()->set('auth.providers.users.model', User::class);
    config()->set('auth.defaults.guard', 'web');
    URL::forceRootUrl('http://localhost');

    app()->instance(UserProvisioner::class, new RecordingProvisioner);
});

it('rejects an unsolicited response that omits in response to while idp initiated login is disabled', function () {
    $connection = samlConnection();

    assertRejectedSaml($connection, idpAssertion($connection), 'in_response_to_mismatch');
    $this->assertGuest();
});

it('rejects an in response to value when no request id is stored, even if idp initiated login is enabled', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection();

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, '_unsolicited')), 'in_response_to_mismatch');
    $this->assertGuest();
});

it('rejects an unsolicited response that arrives while a service provider request is in progress', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'inResponseTo' => null,
    ])), 'in_response_to_mismatch');
});

it('logs the user in from an idp initiated response when the setting is enabled', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection();

    postSamlAssertion($connection, idpAssertion($connection))->assertRedirect('/dashboard');

    $this->assertAuthenticated();
    expect(User::query()->count())->toBe(1)
        ->and(LoginAttempt::query()->where('status', 'succeeded')->whereNull('error_code')->count())->toBe(1);
});

it('lets the connection allow idp initiated login when the global setting is off', function () {
    $connection = samlConnection([
        'config' => idpConfig(['allow_idp_initiated' => true]),
    ]);

    postSamlAssertion($connection, idpAssertion($connection))->assertRedirect('/dashboard');
    $this->assertAuthenticated();
});

it('lets the connection reject idp initiated login when the global setting is on', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection([
        'config' => idpConfig(['allow_idp_initiated' => false]),
    ]);

    assertRejectedSaml($connection, idpAssertion($connection), 'in_response_to_mismatch');
    $this->assertGuest();
});

it('ignores a non boolean connection override and uses the global setting', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection([
        'config' => idpConfig(['allow_idp_initiated' => 'yes']),
    ]);

    postSamlAssertion($connection, idpAssertion($connection))->assertRedirect('/dashboard');
    $this->assertAuthenticated();
});

it('rejects an idp initiated assertion outside the configured skew', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection();

    assertRejectedSaml($connection, idpAssertion($connection, [
        'notBefore' => time() - 900,
        'notOnOrAfter' => time() - 121,
    ]), 'expired_assertion');
});

it('accepts an idp initiated assertion that expired inside the configured skew', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection();

    postSamlAssertion($connection, idpAssertion($connection, [
        'notBefore' => time() - 600,
        'notOnOrAfter' => time() - 60,
    ]))->assertRedirect('/dashboard');

    $this->assertAuthenticated();
});

it('rejects a replayed idp initiated assertion', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    $connection = samlConnection();
    $xml = idpAssertion($connection);

    postSamlAssertion($connection, $xml)->assertRedirect('/dashboard');
    assertRejectedSaml($connection, $xml, 'replay_detected');

    expect(User::query()->count())->toBe(1);
});

it('treats relay state on an idp initiated response as untrusted', function () {
    config()->set('gatekeep.saml.allow_idp_initiated', true);
    config()->set('gatekeep.redirect.allowed_hosts', ['trusted.test']);
    $connection = samlConnection();

    $response = postSamlAssertion($connection, idpAssertion($connection), [
        'RelayState' => 'https://evil.example/phish',
    ]);

    $response->assertRedirect('/dashboard');
    expect((string) $response->headers->get('Location'))->not->toContain('evil.example');

    postSamlAssertion($connection, idpAssertion($connection), [
        'RelayState' => '//evil.example/phish',
    ])->assertRedirect('/dashboard');

    postSamlAssertion($connection, idpAssertion($connection), [
        'RelayState' => '/from-idp',
    ])->assertRedirect('/from-idp');

    postSamlAssertion($connection, idpAssertion($connection), [
        'RelayState' => 'https://trusted.test/welcome',
    ])->assertRedirect('https://trusted.test/welcome');
});

/**
 * @param  array<string, mixed>  $extra
 * @return array<string, mixed>
 */
function idpConfig(array $extra = []): array
{
    return array_replace([
        'idp_entity_id' => 'https://idp.acme.test/entity',
        'sso_url' => 'https://idp.acme.test/sso',
        'x509_certs' => [SamlResponseFactory::certificate()],
    ], $extra);
}

/**
 * @param  array<string, mixed>  $overrides
 */
function idpAssertion(SsoConnection $connection, array $overrides = []): string
{
    return SamlResponseFactory::xml(samlAssertionOptions($connection, '_unused', array_replace([
        'inResponseTo' => null,
    ], $overrides)));
}
