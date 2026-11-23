<?php

declare(strict_types=1);

use Gatekeep\Contracts\TenantResolver;
use Gatekeep\Resolvers\ChainResolver;
use Gatekeep\Resolvers\EmailDomainResolver;
use Gatekeep\Resolvers\SubdomainResolver;
use Illuminate\Http\Request;

it('resolves a tenant from the email domain', function () {
    ssoConnection();
    ssoConnection([
        'tenant_key' => 'munich',
        'name' => 'Munich',
        'domains' => ['München.de'],
    ]);

    $resolver = app(EmailDomainResolver::class);

    expect($resolver->resolve(Request::create('/sso/discover', 'POST'), 'Alice@ACME.com'))->toBe('acme')
        ->and($resolver->resolve(Request::create('/sso/discover', 'POST', [
            'email' => 'alice@münchen.de',
        ])))->toBe('munich')
        ->and($resolver->resolve(
            Request::create('/sso/discover', 'POST', ['email' => 'other@elsewhere.test']),
            'alice@xn--mnchen-3ya.de',
        ))->toBe('munich');
});

it('returns null for a missing, disabled, or unusable email', function (?string $email) {
    ssoConnection(['enabled' => false]);

    expect(app(EmailDomainResolver::class)->resolve(Request::create('/sso/discover', 'POST'), $email))->toBeNull();
})->with([
    'disabled domain' => 'alice@acme.com',
    'unknown domain' => 'alice@globex.com',
    'missing at sign' => 'alice',
    'empty' => '',
    'null' => null,
]);

it('parses a tenant subdomain against the configured base domain', function () {
    config(['gatekeep.subdomain.base_domain' => 'app.test']);

    $resolver = app(SubdomainResolver::class);

    expect($resolver->resolve(Request::create('http://acme.app.test/sso/login')))->toBe('acme')
        ->and($resolver->resolve(Request::create('http://ACME.APP.TEST/sso/login')))->toBe('acme')
        ->and($resolver->resolve(Request::create('http://xn--mnchen-3ya.app.test/sso/login')))->toBe('xn--mnchen-3ya')
        ->and($resolver->resolve(Request::create('http://app.test/sso/login')))->toBeNull()
        ->and($resolver->resolve(Request::create('http://example.com/sso/login')))->toBeNull()
        ->and($resolver->resolve(Request::create('http://acme.app.test:8443/sso/login')))->toBe('acme');
});

it('returns null from the subdomain resolver when no base domain is configured', function () {
    config(['gatekeep.subdomain.base_domain' => null]);

    expect(app(SubdomainResolver::class)->resolve(Request::create('http://acme.app.test/sso/login')))->toBeNull();
});

it('uses resolver order and falls through when an earlier resolver returns null', function () {
    $skipped = new class implements TenantResolver
    {
        public function resolve(Request $request, ?string $email = null): ?string
        {
            return null;
        }
    };

    $selected = new class implements TenantResolver
    {
        public function resolve(Request $request, ?string $email = null): ?string
        {
            return 'from-second';
        }
    };

    $blocking = new class implements TenantResolver
    {
        public function resolve(Request $request, ?string $email = null): ?string
        {
            throw new RuntimeException('later resolvers must not run');
        }
    };

    expect((new ChainResolver([$skipped, $selected]))->resolve(Request::create('/')))->toBe('from-second')
        ->and((new ChainResolver([
            new class implements TenantResolver
            {
                public function resolve(Request $request, ?string $email = null): ?string
                {
                    return 'from-first';
                }
            },
            $blocking,
        ]))->resolve(Request::create('/')))->toBe('from-first')
        ->and((new ChainResolver([]))->resolve(Request::create('/')))->toBeNull()
        ->and((new ChainResolver([
            new class implements TenantResolver
            {
                public function resolve(Request $request, ?string $email = null): ?string
                {
                    return '';
                }
            },
            $selected,
        ]))->resolve(Request::create('/')))->toBe('from-second');
});

it('prefers the email resolver and falls through to the subdomain', function () {
    config(['gatekeep.subdomain.base_domain' => 'app.test']);
    ssoConnection();

    $resolver = app(TenantResolver::class);

    expect($resolver)->toBeInstanceOf(ChainResolver::class)
        ->and($resolver->resolve(Request::create('http://globex.app.test/sso/discover', 'POST', [
            'email' => 'alice@acme.com',
        ])))->toBe('acme')
        ->and($resolver->resolve(Request::create('http://globex.app.test/sso/discover', 'POST', [
            'email' => 'bob@unknown.test',
        ])))->toBe('globex');
});

it('falls through a disabled email connection to the subdomain', function () {
    config(['gatekeep.subdomain.base_domain' => 'app.test']);
    ssoConnection(['enabled' => false]);

    $tenantKey = app(TenantResolver::class)->resolve(Request::create('http://other.app.test/sso/discover', 'POST', [
        'email' => 'alice@acme.com',
    ]));

    expect($tenantKey)->toBe('other');
});

it('rejects a nested chain resolver in the configured order', function () {
    config(['gatekeep.resolvers' => [ChainResolver::class]]);

    expect(fn () => app(ChainResolver::class))->toThrow(InvalidArgumentException::class);
});
