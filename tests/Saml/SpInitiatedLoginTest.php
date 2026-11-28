<?php

declare(strict_types=1);

use Gatekeep\Contracts\UserProvisioner;
use Gatekeep\Models\LoginAttempt;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Saml\SamlSession;
use Gatekeep\Tests\Fixtures\User;
use Gatekeep\Tests\Support\RecordingProvisioner;
use Gatekeep\Tests\Support\SamlResponseFactory;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use Illuminate\Testing\TestResponse;

beforeEach(function () {
    config()->set('app.url', 'http://localhost');
    config()->set('auth.providers.users.model', User::class);
    config()->set('auth.defaults.guard', 'web');
    URL::forceRootUrl('http://localhost');

    app()->instance(UserProvisioner::class, new RecordingProvisioner);
});

it('starts an sp-initiated redirect and stores the authn request id', function () {
    $connection = samlConnection();

    $response = $this->get(route('gatekeep.login', [
        'connection' => $connection,
        'return_to' => '/account',
    ], false));

    $response->assertStatus(302);
    $location = (string) $response->headers->get('Location');

    expect($location)->toStartWith('https://idp.acme.test/sso?')
        ->and($location)->toContain('SAMLRequest=')
        ->and($location)->toContain('RelayState='.rawurlencode('/account'));

    $requestId = session(SamlSession::requestId($connection->id));
    $inflated = gzinflate((string) base64_decode((string) queryValue($location, 'SAMLRequest')));

    expect($requestId)->toBeString()->not->toBe('')
        ->and($inflated)->toContain('AuthnRequest')
        ->and($inflated)->toContain('ID="'.$requestId.'"')
        ->and(session(SamlSession::returnTo($connection->id)))->toBe('/account');
});

it('logs the user in from a signed assertion', function () {
    $connection = samlConnection();
    $before = session()->getId();
    $requestId = startSamlLogin($connection, ['return_to' => '/account']);

    $response = postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId)));

    $response->assertRedirect('/account');
    $this->assertAuthenticated();
    expect(session()->getId())->not->toBe($before)
        ->and(User::query()->count())->toBe(1)
        ->and(LoginAttempt::query()->where('status', 'succeeded')->whereNull('error_code')->count())->toBe(1);

    $provisioner = app(UserProvisioner::class);
    expect($provisioner)->toBeInstanceOf(RecordingProvisioner::class)
        ->and($provisioner->user?->id)->toBe('alice@acme.com')
        ->and($provisioner->user?->email)->toBe('alice@acme.com')
        ->and($provisioner->user?->firstName)->toBe('Alice')
        ->and($provisioner->user?->lastName)->toBe('Adams')
        ->and($provisioner->connection?->is($connection))->toBeTrue()
        ->and(Auth::user()?->email)->toBe('alice@acme.com');
});

it('accepts an assertion that is not yet valid only inside the configured skew', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);
    $now = time();

    postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'notBefore' => $now + 60,
        'notOnOrAfter' => $now + 300,
    ])))->assertRedirect();

    $this->assertAuthenticated();
});

it('rejects an assertion that is not yet valid outside the configured skew', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'notBefore' => time() + 121,
        'notOnOrAfter' => time() + 600,
    ])), 'expired_assertion');

    $this->assertGuest();
});

it('accepts an assertion that expired inside the configured skew', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);
    $now = time();

    postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'notBefore' => $now - 600,
        'notOnOrAfter' => $now - 60,
    ])))->assertRedirect();

    $this->assertAuthenticated();
});

it('rejects an expired assertion', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);
    $now = time();

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'notBefore' => $now - 900,
        'notOnOrAfter' => $now - 121,
    ])), 'expired_assertion');
});

it('rejects an unsigned assertion and logs only the error code', function () {
    Event::fake([MessageLogged::class]);
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);
    $xml = SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'sign' => false,
    ]));

    $response = assertRejectedSaml($connection, $xml, 'invalid_signature');

    expect($response->getContent())->not->toContain('samlp:Response')
        ->and($response->getContent())->not->toContain('alice@acme.com');

    Event::assertDispatched(MessageLogged::class, function (MessageLogged $event): bool {
        return $event->context === ['error_code' => 'invalid_signature']
            && ! str_contains($event->message, 'saml')
            && ! str_contains($event->message, 'alice@acme.com');
    });
});

it('rejects an assertion signed by the wrong certificate', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'signing' => 'wrong',
    ])), 'invalid_signature');
});

it('rejects a name id tampered after signing', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'tamperNameId' => 'mallory@evil.test',
    ])), 'invalid_signature');
});

it('rejects an xml signature wrapping attack', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'wrap' => true,
    ])), 'invalid_signature');

    expect(User::query()->where('email', 'attacker@evil.test')->exists())->toBeFalse();
});

it('rejects a comment injected into the name id', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'commentInNameId' => true,
    ])), 'invalid_signature');

    expect(User::query()->where('email', 'alice@acme.com')->exists())->toBeFalse();
});

it('rejects a doctype so an external entity cannot be loaded', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    $response = assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'doctype' => true,
    ])), 'invalid_signature');

    expect($response->getContent())->not->toContain('root:');
});

it('rejects the wrong audience', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'audience' => 'https://other.example/sp',
    ])), 'audience_mismatch');
});

it('rejects the wrong destination', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);
    $evil = 'https://evil.example/acs';

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'destination' => $evil,
        'recipient' => $evil,
    ])), 'destination_mismatch');
});

it('rejects the wrong issuer', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'issuer' => 'https://evil.example/idp',
    ])), 'issuer_mismatch');
});

it('rejects an in response to value that does not match the stored request', function () {
    $connection = samlConnection();
    startSamlLogin($connection);

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, '_some-other-request')), 'in_response_to_mismatch');
});

it('rejects an unsolicited response while idp initiated login is disabled', function () {
    $connection = samlConnection();

    assertRejectedSaml($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, '_unsolicited')), 'in_response_to_mismatch');
});

it('rejects a replayed assertion', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);
    $xml = SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId));

    postSamlAssertion($connection, $xml)->assertRedirect();
    $this->assertAuthenticated();

    assertRejectedSaml($connection, $xml, 'replay_detected');

    expect(User::query()->count())->toBe(1)
        ->and(LoginAttempt::query()->where('error_code', 'replay_detected')->count())->toBe(1);
});

it('sends an open redirect relay state to the configured home path', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection, ['return_to' => 'https://evil.example/phish']);

    $response = postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId)), [
        'RelayState' => 'https://evil.example/phish',
    ]);

    $response->assertRedirect('/dashboard');
    expect((string) $response->headers->get('Location'))->not->toContain('evil.example');
});

it('prefers the stored return path over a hostile relay state', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection, ['return_to' => '/from-session']);

    $response = postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId)), [
        'RelayState' => 'https://evil.example/phish',
    ]);

    $response->assertRedirect('/from-session');
    expect((string) $response->headers->get('Location'))->not->toContain('evil.example');
});

it('keeps a relative relay state and an allow listed host', function () {
    config()->set('gatekeep.redirect.allowed_hosts', ['trusted.test']);
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId)), [
        'RelayState' => '/welcome',
    ])->assertRedirect('/welcome');

    $second = samlConnection(['name' => 'Acme Two', 'domains' => ['acme.org']]);
    $secondRequest = startSamlLogin($second);

    postSamlAssertion($second, SamlResponseFactory::xml(samlAssertionOptions($second, $secondRequest)), [
        'RelayState' => 'https://trusted.test/welcome',
    ])->assertRedirect('https://trusted.test/welcome');
});

it('drops a protocol relative relay state', function () {
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    $response = postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId)), [
        'RelayState' => '//evil.example/phish',
    ]);

    $response->assertRedirect('/dashboard');
    expect((string) $response->headers->get('Location'))->not->toContain('evil.example');
});

it('returns provisioning denied when no provisioner is bound', function () {
    app()->forgetInstance(UserProvisioner::class);
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    $response = postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId)));

    $response->assertForbidden();
    $response->assertJsonPath('error_code', 'provisioning_denied');
    $this->assertGuest();
    expect(LoginAttempt::query()->where('error_code', 'provisioning_denied')->exists())->toBeTrue();
});

it('records an unknown connection without parsing a response', function () {
    $response = $this->get('/sso/01ARZ3NDEKTSV4RRFFQ69G5FAV/login');

    $response->assertNotFound();
    $response->assertJsonPath('error_code', 'unknown_connection');
    expect(LoginAttempt::query()->where('error_code', 'unknown_connection')->whereNull('sso_connection_id')->exists())->toBeTrue();
});

it('does not start login for a disabled connection', function () {
    $connection = samlConnection(['enabled' => false]);

    $response = $this->get(route('gatekeep.login', $connection, false));

    $response->assertNotFound();
    $response->assertJsonPath('error_code', 'unknown_connection');
});

it('skips the login attempt row when audit is disabled', function () {
    config()->set('gatekeep.audit.enabled', false);
    $connection = samlConnection();
    $requestId = startSamlLogin($connection);

    $response = postSamlAssertion($connection, SamlResponseFactory::xml(samlAssertionOptions($connection, $requestId, [
        'sign' => false,
    ])));

    $response->assertJsonPath('error_code', 'invalid_signature');
    expect(LoginAttempt::query()->count())->toBe(0);
});

/**
 * @param  array<string, mixed>  $query
 */
function startSamlLogin(SsoConnection $connection, array $query = []): string
{
    $response = test()->get(route('gatekeep.login', ['connection' => $connection] + $query, false));
    $response->assertStatus(302);

    $requestId = session(SamlSession::requestId($connection->id));
    expect($requestId)->toBeString()->not->toBe('');

    return $requestId;
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function samlAssertionOptions(SsoConnection $connection, string $requestId, array $overrides = []): array
{
    $acs = route('gatekeep.saml.acs', $connection);

    return array_replace([
        'issuer' => 'https://idp.acme.test/entity',
        'audience' => route('gatekeep.saml.metadata', $connection),
        'destination' => $acs,
        'recipient' => $acs,
        'inResponseTo' => $requestId,
    ], $overrides);
}

/**
 * @param  array<string, mixed>  $fields
 */
function postSamlAssertion(SsoConnection $connection, string $xml, array $fields = []): TestResponse
{
    return test()->post(route('gatekeep.saml.acs', $connection, false), array_merge([
        'SAMLResponse' => base64_encode($xml),
    ], $fields));
}

function assertRejectedSaml(SsoConnection $connection, string $xml, string $errorCode): TestResponse
{
    $response = postSamlAssertion($connection, $xml);

    expect($response->status())->toBeGreaterThanOrEqual(400)
        ->and($response->status())->toBeLessThan(500);

    $response->assertJsonPath('error_code', $errorCode);

    expect(LoginAttempt::query()->where('sso_connection_id', $connection->id)->where('error_code', $errorCode)->exists())->toBeTrue();

    return $response;
}

function queryValue(string $url, string $key): ?string
{
    $query = parse_url($url, PHP_URL_QUERY);
    parse_str(is_string($query) ? $query : '', $parameters);
    $value = $parameters[$key] ?? null;

    return is_string($value) ? $value : null;
}
