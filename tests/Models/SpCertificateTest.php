<?php

declare(strict_types=1);

use Gatekeep\Enums\CertificateStatus;
use Gatekeep\Models\SpCertificate;
use Illuminate\Support\Facades\DB;

it('encrypts the private key and hides it from array output', function () {
    $connection = ssoConnection();

    $certificate = SpCertificate::query()->create([
        'sso_connection_id' => $connection->id,
        'certificate' => 'public-cert',
        'private_key' => 'BEGIN-PRIVATE-KEY-DO-NOT-LOG',
        'status' => CertificateStatus::Active,
        'not_after' => '2027-01-01 00:00:00',
    ]);

    $raw = DB::table('sso_sp_certificates')->where('id', $certificate->id)->value('private_key');

    expect($raw)->toBeString()
        ->and($raw)->not->toContain('BEGIN-PRIVATE-KEY-DO-NOT-LOG')
        ->and($certificate->fresh()->private_key)->toBe('BEGIN-PRIVATE-KEY-DO-NOT-LOG')
        ->and($certificate->fresh()->status)->toBe(CertificateStatus::Active)
        ->and($certificate->fresh()->certificate)->toBe('public-cert')
        ->and($certificate->toArray())->not->toHaveKey('private_key')
        ->and($certificate->toJson())->not->toContain('BEGIN-PRIVATE-KEY-DO-NOT-LOG')
        ->and($certificate->connection->is($connection))->toBeTrue();
});

it('allows a global certificate and removes connection certificates with the connection', function () {
    $connection = ssoConnection();

    $global = SpCertificate::query()->create([
        'certificate' => 'global-cert',
        'private_key' => 'global-key',
        'status' => CertificateStatus::Next,
        'not_after' => now()->addYear(),
    ]);

    SpCertificate::query()->create([
        'sso_connection_id' => $connection->id,
        'certificate' => 'connection-cert',
        'private_key' => 'connection-key',
        'status' => CertificateStatus::Retiring,
        'not_after' => now()->addMonth(),
    ]);

    $connection->delete();

    expect(SpCertificate::query()->pluck('id')->all())->toBe([$global->id])
        ->and($global->fresh()->status)->toBe(CertificateStatus::Next);
});
