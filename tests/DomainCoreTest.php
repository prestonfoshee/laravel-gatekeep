<?php

declare(strict_types=1);

use Gatekeep\Exceptions\AudienceMismatch;
use Gatekeep\Exceptions\ExpiredAssertion;
use Gatekeep\Exceptions\InvalidSignature;
use Gatekeep\Exceptions\ProvisioningDenied;
use Gatekeep\Exceptions\ReplayDetected;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Exceptions\UnknownConnection;
use Gatekeep\Support\DomainNormalizer;
use Gatekeep\ValueObjects\LoginIntent;
use Gatekeep\ValueObjects\MappedAttributes;
use Gatekeep\ValueObjects\SsoUser;

it('normalizes domains', function (string $domain, string $expected) {
    expect(DomainNormalizer::normalize($domain))->toBe($expected);
})->with([
    'case' => ['ACME.COM', 'acme.com'],
    'surrounding space and trailing dot' => ['  ACME.COM. ', 'acme.com'],
    'unicode' => ['München.de', 'xn--mnchen-3ya.de'],
    'unicode uppercase' => ['MÜNCHEN.DE', 'xn--mnchen-3ya.de'],
    'punycode' => ['xn--mnchen-3ya.de', 'xn--mnchen-3ya.de'],
]);

it('reads a domain from an email and parses a subdomain', function () {
    expect(DomainNormalizer::fromEmail('Alice@ACME.COM'))->toBe('acme.com')
        ->and(DomainNormalizer::fromEmail('alice@münchen.de'))->toBe('xn--mnchen-3ya.de')
        ->and(DomainNormalizer::fromEmail('not-an-email'))->toBeNull()
        ->and(DomainNormalizer::fromEmail('alice@'))->toBeNull()
        ->and(DomainNormalizer::subdomain('acme.app.test', 'app.test'))->toBe('acme')
        ->and(DomainNormalizer::subdomain('ACME.APP.TEST', 'APP.TEST'))->toBe('acme')
        ->and(DomainNormalizer::subdomain('münchen.app.test', 'app.test'))->toBe('xn--mnchen-3ya')
        ->and(DomainNormalizer::subdomain('acme.app.test:8443', 'app.test'))->toBe('acme')
        ->and(DomainNormalizer::subdomain('foo.bar.app.test', 'app.test'))->toBe('foo.bar')
        ->and(DomainNormalizer::subdomain('app.test', 'app.test'))->toBeNull()
        ->and(DomainNormalizer::subdomain('evilapp.test', 'app.test'))->toBeNull()
        ->and(DomainNormalizer::subdomain('example.com', 'app.test'))->toBeNull();
});

it('exposes stable error codes', function (string $class, string $code) {
    $exception = new $class;

    expect($exception)->toBeInstanceOf(SsoException::class)
        ->and($exception->errorCode())->toBe($code)
        ->and($exception->getMessage())->not->toBe('');
})->with([
    'base' => [SsoException::class, 'sso_error'],
    'signature' => [InvalidSignature::class, 'invalid_signature'],
    'replay' => [ReplayDetected::class, 'replay_detected'],
    'expired' => [ExpiredAssertion::class, 'expired_assertion'],
    'audience' => [AudienceMismatch::class, 'audience_mismatch'],
    'connection' => [UnknownConnection::class, 'unknown_connection'],
    'provisioning' => [ProvisioningDenied::class, 'provisioning_denied'],
]);

it('holds login intent, mapped attributes, and the sso user', function () {
    $intent = new LoginIntent(returnTo: '/dashboard', relayState: '/relay', forceAuthn: true);
    $mapped = new MappedAttributes(
        email: 'alice@acme.com',
        firstName: 'Alice',
        lastName: 'Adams',
        groups: ['employees'],
        attributes: ['department' => 'Security'],
    );
    $user = new SsoUser(
        id: 'name-id-1',
        email: 'alice@acme.com',
        firstName: 'Alice',
        lastName: 'Adams',
        groups: ['employees'],
        raw: ['mail' => 'alice@acme.com'],
    );

    expect($intent->returnTo)->toBe('/dashboard')
        ->and($intent->relayState)->toBe('/relay')
        ->and($intent->forceAuthn)->toBeTrue()
        ->and($mapped->email)->toBe('alice@acme.com')
        ->and($mapped->groups)->toBe(['employees'])
        ->and($mapped->attributes)->toBe(['department' => 'Security'])
        ->and($user->id)->toBe('name-id-1')
        ->and($user->raw)->toBe(['mail' => 'alice@acme.com'])
        ->and((new LoginIntent)->forceAuthn)->toBeFalse();
});
