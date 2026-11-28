<?php

declare(strict_types=1);

use Gatekeep\Models\LoginAttempt;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Saml\SamlSession;
use Illuminate\Testing\TestResponse;

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
