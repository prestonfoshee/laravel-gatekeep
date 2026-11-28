<?php

declare(strict_types=1);

use Gatekeep\Support\SafeRedirect;

beforeEach(function () {
    config()->set('app.url', 'http://localhost');
    config()->set('gatekeep.redirect.allowed_hosts', ['trusted.test']);
});

it('allows relative paths and allow listed hosts', function (string $target) {
    expect(app(SafeRedirect::class)->sanitize($target))->toBe($target);
})->with([
    '/dashboard',
    '/account?next=1',
    'https://trusted.test/welcome',
    'http://localhost/dashboard',
]);

it('discards open redirects', function (string $target) {
    expect(app(SafeRedirect::class)->sanitize($target))->toBeNull();
})->with([
    'https://evil.example/phish',
    '//evil.example/phish',
    '/\\evil.example',
    '/%2f%2fevil.example',
    'javascript:alert(1)',
    'https://user:pass@localhost/dashboard',
    'https://localhost.evil.example/dashboard',
]);
