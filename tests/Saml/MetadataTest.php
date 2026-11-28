<?php

declare(strict_types=1);

use Gatekeep\Enums\CertificateStatus;
use Gatekeep\Models\SpCertificate;
use Gatekeep\Tests\Support\SamlResponseFactory;
use Illuminate\Support\Facades\URL;
use OneLogin\Saml2\Settings;

beforeEach(function () {
    config()->set('app.url', 'http://localhost');
    URL::forceRootUrl('http://localhost');
});

it('publishes unsigned metadata with the entity id and acs url', function () {
    $connection = samlConnection();

    $response = $this->get(route('gatekeep.saml.metadata', $connection, false));

    $response->assertOk();
    $xml = $response->getContent();
    expect($xml)->toContain('entityID="'.route('gatekeep.saml.metadata', $connection).'"')
        ->and($xml)->toContain('Location="'.route('gatekeep.saml.acs', $connection).'"')
        ->and($xml)->toContain('AssertionConsumerService')
        ->and($xml)->not->toContain('X509Certificate')
        ->and($xml)->not->toContain('<ds:Signature');

    expect(metadataErrors($xml))->toBe([]);
});

it('signs metadata with the active service provider certificate', function () {
    $connection = samlConnection();
    $pem = SamlResponseFactory::serviceProviderCertificate();
    spCertificate($connection->id, $pem, SamlResponseFactory::serviceProviderPrivateKey(), CertificateStatus::Active);

    $response = $this->get(route('gatekeep.saml.metadata', $connection, false));
    $xml = $response->getContent();

    $response->assertOk();
    expect($xml)->toContain('<ds:Signature')
        ->and(certificateText($xml))->toBe(certificateBody($pem))
        ->and(metadataErrors($xml))->toBe([]);
});

it('uses a global active certificate when the connection has none', function () {
    $connection = samlConnection();
    $pem = SamlResponseFactory::serviceProviderCertificate();
    spCertificate(null, $pem, SamlResponseFactory::serviceProviderPrivateKey(), CertificateStatus::Active);

    $xml = $this->get(route('gatekeep.saml.metadata', $connection, false))->getContent();

    expect(certificateText($xml))->toBe(certificateBody($pem));
});

it('prefers the connection certificate over the global one and ignores a next certificate', function () {
    $connection = samlConnection();
    $global = SamlResponseFactory::certificate();
    $owned = SamlResponseFactory::serviceProviderCertificate();

    spCertificate(null, $global, SamlResponseFactory::privateKey(), CertificateStatus::Active);
    spCertificate($connection->id, $owned, SamlResponseFactory::serviceProviderPrivateKey(), CertificateStatus::Active);
    spCertificate($connection->id, $global, SamlResponseFactory::privateKey(), CertificateStatus::Next);

    $xml = $this->get(route('gatekeep.saml.metadata', $connection, false))->getContent();

    expect(certificateText($xml))->toBe(certificateBody($owned))
        ->and(certificateText($xml))->not->toBe(certificateBody($global));
});

it('publishes the active certificate and the next certificate', function () {
    $connection = samlConnection();
    $active = SamlResponseFactory::serviceProviderCertificate();
    $next = SamlResponseFactory::secondCertificate();

    spCertificate($connection->id, $active, SamlResponseFactory::serviceProviderPrivateKey(), CertificateStatus::Active);
    spCertificate($connection->id, $next, SamlResponseFactory::secondPrivateKey(), CertificateStatus::Next);

    $response = $this->get(route('gatekeep.saml.metadata', $connection, false));
    $xml = $response->getContent();
    $bodies = certificateBodies($xml);

    $response->assertOk();
    expect($bodies)->toContain(certificateBody($active))
        ->and($bodies)->toContain(certificateBody($next))
        ->and($xml)->toContain('<ds:Signature')
        ->and(metadataErrors($xml))->toBe([]);
});

it('publishes a global next certificate only beside the global active certificate', function () {
    $connection = samlConnection();
    $active = SamlResponseFactory::serviceProviderCertificate();
    $next = SamlResponseFactory::secondCertificate();

    spCertificate(null, $active, SamlResponseFactory::serviceProviderPrivateKey(), CertificateStatus::Active);
    spCertificate(null, $next, SamlResponseFactory::secondPrivateKey(), CertificateStatus::Next);

    $bodies = certificateBodies($this->get(route('gatekeep.saml.metadata', $connection, false))->getContent());

    expect($bodies)->toContain(certificateBody($active))
        ->and($bodies)->toContain(certificateBody($next));
});

it('does not publish a global next certificate beside a connection active certificate', function () {
    $connection = samlConnection();
    $active = SamlResponseFactory::serviceProviderCertificate();
    $next = SamlResponseFactory::secondCertificate();

    spCertificate($connection->id, $active, SamlResponseFactory::serviceProviderPrivateKey(), CertificateStatus::Active);
    spCertificate(null, $next, SamlResponseFactory::secondPrivateKey(), CertificateStatus::Next);

    $xml = $this->get(route('gatekeep.saml.metadata', $connection, false))->getContent();

    expect(certificateBodies($xml))->toContain(certificateBody($active))
        ->and($xml)->not->toContain(certificateBody($next));
});

it('does not publish a certificate that is only next', function () {
    $connection = samlConnection();
    spCertificate(
        $connection->id,
        SamlResponseFactory::serviceProviderCertificate(),
        SamlResponseFactory::serviceProviderPrivateKey(),
        CertificateStatus::Next,
    );

    expect($this->get(route('gatekeep.saml.metadata', $connection, false))->getContent())->not->toContain('X509Certificate');
});

function spCertificate(?string $connectionId, string $certificate, string $privateKey, CertificateStatus $status): void
{
    SpCertificate::query()->create([
        'sso_connection_id' => $connectionId,
        'certificate' => $certificate,
        'private_key' => $privateKey,
        'status' => $status,
        'not_after' => now()->addYear(),
    ]);
}

function certificateBody(string $pem): string
{
    $body = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $pem);

    return is_string($body) ? $body : '';
}

function certificateText(string $xml): string
{
    return certificateBodies($xml)[0] ?? '';
}

/**
 * @return list<string>
 */
function certificateBodies(string $xml): array
{
    $document = new DOMDocument;
    $document->loadXML($xml);
    $bodies = [];

    foreach ($document->getElementsByTagName('X509Certificate') as $node) {
        $text = preg_replace('/\s+/', '', $node->textContent);
        $bodies[] = is_string($text) ? $text : '';
    }

    return $bodies;
}

/**
 * @return list<string>
 */
function metadataErrors(string $xml): array
{
    $settings = new Settings([
        'strict' => true,
        'sp' => [
            'entityId' => 'http://localhost/sp',
            'assertionConsumerService' => [
                'url' => 'http://localhost/acs',
            ],
        ],
        'idp' => [
            'entityId' => 'https://idp.acme.test/entity',
            'singleSignOnService' => [
                'url' => 'https://idp.acme.test/sso',
            ],
            'x509cert' => SamlResponseFactory::certificate(),
        ],
    ]);

    /** @var list<string> $errors */
    $errors = $settings->validateMetadata($xml);

    return $errors;
}
