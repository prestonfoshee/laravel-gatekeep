<?php

declare(strict_types=1);

use Gatekeep\Enums\CertificateStatus;
use Gatekeep\Models\SpCertificate;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\URL;

beforeEach(function () {
    config()->set('app.url', 'http://localhost');
    URL::forceRootUrl('http://localhost');
});

it('generates, promotes, and retires a connection certificate', function () {
    $connection = samlConnection();

    $this->artisan('gatekeep:sp-cert:generate', ['connection' => $connection->id])
        ->expectsOutputToContain('Generated next certificate')
        ->doesntExpectOutputToContain('PRIVATE KEY')
        ->assertSuccessful();

    $next = SpCertificate::query()->where('sso_connection_id', $connection->id)->firstOrFail();
    $rawKey = DB::table('sso_sp_certificates')->where('id', $next->id)->value('private_key');

    expect($next->status)->toBe(CertificateStatus::Next)
        ->and($next->not_after->greaterThan(now()->addDays(360)))->toBeTrue()
        ->and($next->not_after->lessThan(now()->addDays(370)))->toBeTrue()
        ->and($rawKey)->toBeString()
        ->and($rawKey)->not->toContain('PRIVATE KEY')
        ->and($next->private_key)->toContain('PRIVATE KEY')
        ->and($next->toArray())->not->toHaveKey('private_key')
        ->and($next->toJson())->not->toContain('PRIVATE KEY');

    $this->artisan('gatekeep:sp-cert:promote', ['connection' => $connection->id])
        ->expectsOutputToContain('Promoted certificate')
        ->doesntExpectOutputToContain('PRIVATE KEY')
        ->assertSuccessful();

    expect($next->fresh()->status)->toBe(CertificateStatus::Active);

    $this->artisan('gatekeep:sp-cert:generate', ['connection' => $connection->id])->assertSuccessful();
    $this->artisan('gatekeep:sp-cert:promote', ['connection' => $connection->id])->assertSuccessful();
    $this->artisan('gatekeep:sp-cert:generate', ['connection' => $connection->id])->assertSuccessful();

    $active = certificateWithStatus($connection->id, CertificateStatus::Active);
    $retiring = certificateWithStatus($connection->id, CertificateStatus::Retiring);
    $upcoming = certificateWithStatus($connection->id, CertificateStatus::Next);

    $this->artisan('gatekeep:sp-cert:retire', ['connection' => $connection->id])
        ->expectsOutputToContain('Retired 1 certificate(s).')
        ->assertSuccessful();

    expect($retiring->fresh()->status)->toBe(CertificateStatus::Retired)
        ->and($active->fresh()->status)->toBe(CertificateStatus::Active)
        ->and($upcoming->fresh()->status)->toBe(CertificateStatus::Next);

    $xml = $this->get(route('gatekeep.saml.metadata', $connection, false))->assertOk()->getContent();

    expect($xml)->toContain(certificateBodyText($active->certificate))
        ->and($xml)->toContain(certificateBodyText($upcoming->certificate))
        ->and($xml)->not->toContain(certificateBodyText($retiring->certificate))
        ->and($xml)->not->toContain('PRIVATE KEY')
        ->and(signatureCertificateBody($xml))->toBe(certificateBodyText($active->certificate));
});

it('refuses to generate a second next certificate', function () {
    $connection = samlConnection();

    $this->artisan('gatekeep:sp-cert:generate', ['connection' => $connection->id])->assertSuccessful();

    $this->artisan('gatekeep:sp-cert:generate', ['connection' => $connection->id])
        ->expectsOutputToContain('A next certificate already exists.')
        ->assertFailed();

    expect(SpCertificate::query()->where('sso_connection_id', $connection->id)->count())->toBe(1);
});

it('refuses an unknown connection', function () {
    $this->artisan('gatekeep:sp-cert:generate', ['connection' => '01ARZ3NDEKTSV4RRFFQ69G5FAV'])
        ->expectsOutputToContain('The connection does not exist.')
        ->assertFailed();

    expect(SpCertificate::query()->count())->toBe(0);
});

it('refuses to promote or retire when there is no certificate in that state', function () {
    $connection = samlConnection();

    $this->artisan('gatekeep:sp-cert:promote', ['connection' => $connection->id])
        ->expectsOutputToContain('There is no next certificate to promote.')
        ->assertFailed();

    $this->artisan('gatekeep:sp-cert:retire', ['connection' => $connection->id])
        ->expectsOutputToContain('There is no retiring certificate to retire.')
        ->assertFailed();
});

it('rotates the global certificate without retiring it for a connection', function () {
    $connection = samlConnection();

    $this->artisan('gatekeep:sp-cert:generate')->assertSuccessful();
    $this->artisan('gatekeep:sp-cert:promote')->assertSuccessful();
    $this->artisan('gatekeep:sp-cert:generate')->assertSuccessful();

    $globalActive = SpCertificate::query()->whereNull('sso_connection_id')->where('status', CertificateStatus::Active)->firstOrFail();
    $globalNext = SpCertificate::query()->whereNull('sso_connection_id')->where('status', CertificateStatus::Next)->firstOrFail();

    $xml = $this->get(route('gatekeep.saml.metadata', $connection, false))->assertOk()->getContent();

    expect($globalActive->sso_connection_id)->toBeNull()
        ->and($xml)->toContain(certificateBodyText($globalActive->certificate))
        ->and($xml)->toContain(certificateBodyText($globalNext->certificate));

    $this->artisan('gatekeep:sp-cert:generate', ['connection' => $connection->id])->assertSuccessful();
    $this->artisan('gatekeep:sp-cert:promote', ['connection' => $connection->id])->assertSuccessful();

    expect($globalActive->fresh()->status)->toBe(CertificateStatus::Active)
        ->and(certificateWithStatus($connection->id, CertificateStatus::Active))->not->toBeNull();
});

function certificateWithStatus(?string $connectionId, CertificateStatus $status): SpCertificate
{
    $query = SpCertificate::query()->where('status', $status);

    if ($connectionId === null) {
        $query->whereNull('sso_connection_id');
    } else {
        $query->where('sso_connection_id', $connectionId);
    }

    $certificate = $query->first();

    expect($certificate)->toBeInstanceOf(SpCertificate::class);

    return $certificate;
}

function certificateBodyText(string $pem): string
{
    $body = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $pem);

    return is_string($body) ? $body : '';
}

function signatureCertificateBody(string $xml): string
{
    $document = new DOMDocument;
    $document->loadXML($xml);
    $xpath = new DOMXPath($document);
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $node = $xpath->query('//ds:Signature//ds:X509Certificate')->item(0);
    $text = preg_replace('/\s+/', '', $node?->textContent ?? '');

    return is_string($text) ? $text : '';
}
