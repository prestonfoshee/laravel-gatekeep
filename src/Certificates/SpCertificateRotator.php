<?php

declare(strict_types=1);

namespace Gatekeep\Certificates;

use Carbon\CarbonImmutable;
use Gatekeep\Enums\CertificateStatus;
use Gatekeep\Exceptions\CertificateRotationException;
use Gatekeep\Models\SpCertificate;
use Gatekeep\Models\SsoConnection;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;

final class SpCertificateRotator
{
    private const VALID_DAYS = 365;

    public function generate(?string $connectionId): SpCertificate
    {
        $this->assertConnection($connectionId);

        if ($this->scoped($connectionId)->where('status', CertificateStatus::Next)->exists()) {
            throw new CertificateRotationException('A next certificate already exists.');
        }

        [$privateKey, $certificate, $notAfter] = $this->issue();

        return SpCertificate::query()->create([
            'sso_connection_id' => $connectionId,
            'certificate' => $certificate,
            'private_key' => $privateKey,
            'status' => CertificateStatus::Next,
            'not_after' => $notAfter,
        ]);
    }

    public function promote(?string $connectionId): SpCertificate
    {
        $this->assertConnection($connectionId);

        return DB::transaction(function () use ($connectionId): SpCertificate {
            $next = $this->scoped($connectionId)
                ->where('status', CertificateStatus::Next)
                ->orderByDesc('id')
                ->first();

            if (! $next instanceof SpCertificate) {
                throw new CertificateRotationException('There is no next certificate to promote.');
            }

            $this->scoped($connectionId)
                ->where('status', CertificateStatus::Active)
                ->update(['status' => CertificateStatus::Retiring->value]);

            $next->status = CertificateStatus::Active;
            $next->save();

            return $next;
        });
    }

    public function retire(?string $connectionId): int
    {
        $this->assertConnection($connectionId);

        $retired = $this->scoped($connectionId)
            ->where('status', CertificateStatus::Retiring)
            ->update(['status' => CertificateStatus::Retired->value]);

        if ($retired === 0) {
            throw new CertificateRotationException('There is no retiring certificate to retire.');
        }

        return $retired;
    }

    private function assertConnection(?string $connectionId): void
    {
        if ($connectionId === null) {
            return;
        }

        if (! SsoConnection::query()->whereKey($connectionId)->exists()) {
            throw new CertificateRotationException('The connection does not exist.');
        }
    }

    /**
     * @return Builder<SpCertificate>
     */
    private function scoped(?string $connectionId): Builder
    {
        $query = SpCertificate::query();

        if ($connectionId === null) {
            return $query->whereNull('sso_connection_id');
        }

        return $query->where('sso_connection_id', $connectionId);
    }

    /**
     * @return array{0: string, 1: string, 2: CarbonImmutable}
     */
    private function issue(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if (! $key instanceof OpenSSLAsymmetricKey) {
            throw new CertificateRotationException('The service provider certificate could not be generated.');
        }

        $privateKey = '';
        $exported = openssl_pkey_export($key, $privateKey);

        if ($exported !== true || ! is_string($privateKey) || $privateKey === '') {
            throw new CertificateRotationException('The service provider certificate could not be generated.');
        }

        $csrKey = $key;
        $csr = openssl_csr_new(['commonName' => 'gatekeep-sp'], $csrKey, ['digest_alg' => 'sha256']);

        if (! $csr instanceof OpenSSLCertificateSigningRequest) {
            throw new CertificateRotationException('The service provider certificate could not be generated.');
        }

        $signed = openssl_csr_sign($csr, null, $key, self::VALID_DAYS, ['digest_alg' => 'sha256']);

        if (! $signed instanceof OpenSSLCertificate) {
            throw new CertificateRotationException('The service provider certificate could not be generated.');
        }

        $certificate = '';
        $exportedCertificate = openssl_x509_export($signed, $certificate);

        if ($exportedCertificate !== true || ! is_string($certificate) || $certificate === '') {
            throw new CertificateRotationException('The service provider certificate could not be generated.');
        }

        $parsed = openssl_x509_parse($signed);
        $validTo = is_array($parsed) ? ($parsed['validTo_time_t'] ?? null) : null;

        if (! is_int($validTo)) {
            throw new CertificateRotationException('The service provider certificate could not be generated.');
        }

        return [$privateKey, $certificate, CarbonImmutable::createFromTimestamp($validTo)];
    }
}
