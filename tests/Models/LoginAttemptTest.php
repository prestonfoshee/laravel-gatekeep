<?php

declare(strict_types=1);

use Gatekeep\Models\LoginAttempt;

it('records an attempt with an error code and keeps it when the connection is deleted', function () {
    $connection = ssoConnection();

    $attempt = LoginAttempt::query()->create([
        'sso_connection_id' => $connection->id,
        'status' => 'failed',
        'error_code' => 'invalid_signature',
        'ip' => '203.0.113.10',
    ]);

    expect($attempt->connection->is($connection))->toBeTrue()
        ->and($attempt->fresh()->error_code)->toBe('invalid_signature');

    $connection->delete();

    expect($attempt->fresh()->sso_connection_id)->toBeNull()
        ->and($attempt->fresh()->status)->toBe('failed');
});

it('records an attempt that is not tied to a connection', function () {
    $attempt = LoginAttempt::query()->create([
        'status' => 'failed',
        'error_code' => 'unknown_connection',
    ]);

    expect($attempt->connection)->toBeNull()
        ->and($attempt->ip)->toBeNull();
});
