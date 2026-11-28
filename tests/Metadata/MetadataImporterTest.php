<?php

declare(strict_types=1);

use Gatekeep\Contracts\HostResolver;
use Gatekeep\Events\IdpCertificateChanged;
use Gatekeep\Events\IdpMetadataRefreshed;
use Gatekeep\Exceptions\MetadataImportException;
use Gatekeep\Metadata\MetadataImporter;
use Gatekeep\Metadata\MetadataUrlGuard;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Support\DnsHostResolver;
use Gatekeep\Tests\Support\StaticHostResolver;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Http::preventStrayRequests();
});

it('binds the dns host resolver', function () {
    expect(app(HostResolver::class))->toBeInstanceOf(DnsHostResolver::class);
});

it('imports okta metadata into the connection', function () {
    $xml = fixtureXml('okta-metadata.xml');
    $connection = metadataConnection();

    Event::fake([IdpMetadataRefreshed::class, IdpCertificateChanged::class]);

    app(MetadataImporter::class)->apply($connection, app(MetadataImporter::class)->fromXml($xml), 'https://acme.okta.com/app/metadata');

    $fresh = $connection->fresh();
    $signing = signingCertificateBodies($xml);
    $imported = array_map(importedCertificateBody(...), $fresh->config['x509_certs']);

    expect($fresh->config['idp_entity_id'])->toBe('http://www.okta.com/exk1a2b3c4d5e6f7g8h9')
        ->and($fresh->config['sso_url'])->toBe('https://acme.okta.com/app/acme/exk1a2b3c4d5e6f7g8h9/sso/saml')
        ->and($fresh->config['sso_url'])->not->toContain('/post')
        ->and($fresh->config['allow_idp_initiated'])->toBeTrue()
        ->and($imported)->toBe($signing)
        ->and($imported)->not->toContain(encryptionCertificateBody($xml))
        ->and($fresh->metadata_url)->toBe('https://acme.okta.com/app/metadata')
        ->and($fresh->metadata_refreshed_at)->not->toBeNull();

    Event::assertDispatched(IdpCertificateChanged::class, function (IdpCertificateChanged $event) use ($connection): bool {
        return $event->connectionId === $connection->id && eventPayloadIsSafe($event);
    });
    Event::assertDispatched(IdpMetadataRefreshed::class, function (IdpMetadataRefreshed $event) use ($connection): bool {
        return $event->connectionId === $connection->id
            && $event->metadataUrl === 'https://acme.okta.com/app/metadata'
            && eventPayloadIsSafe($event);
    });
});

it('imports entra metadata and keeps the http redirect endpoint', function () {
    $xml = fixtureXml('entra-metadata.xml');
    $metadata = app(MetadataImporter::class)->fromXml($xml);

    expect($metadata->entityId)->toBe('https://sts.windows.net/11111111-2222-3333-4444-555555555555/')
        ->and($metadata->ssoUrl)->toBe('https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2')
        ->and($metadata->ssoUrl)->not->toContain('/post')
        ->and(array_map(importedCertificateBody(...), $metadata->certificates))->toBe(signingCertificateBodies($xml));
});

it('rejects metadata that only publishes an http post endpoint', function () {
    $xml = <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>MIIB</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;

    expect(fn () => app(MetadataImporter::class)->fromXml($xml))
        ->toThrow(MetadataImportException::class);
});

it('rejects an xxe metadata document', function () {
    $xml = fixtureXml('xxe-metadata.xml');

    expect(fn () => app(MetadataImporter::class)->fromXml($xml))
        ->toThrow(function (MetadataImportException $exception): bool {
            expect($exception->getMessage())->toBe('The identity provider metadata could not be imported.')
                ->and($exception->getMessage())->not->toContain('root:');

            return true;
        });
});

it('rejects an xxe document downloaded from a metadata url', function () {
    $url = 'https://metadata.example.test/xxe';
    fakeMetadataHosts(['metadata.example.test' => ['1.1.1.1']]);
    Http::fake([
        $url => Http::response(fixtureXml('xxe-metadata.xml')),
    ]);
    $connection = metadataConnection();

    expect(fn () => app(MetadataImporter::class)->importFromUrl($connection, $url))
        ->toThrow(function (MetadataImportException $exception): bool {
            expect($exception->getMessage())->not->toContain('root:');

            return true;
        });

    expect($connection->fresh()->config['idp_entity_id'])->toBe('https://old.example/entity');
});

it('rejects metadata urls that are not public https addresses', function (string $url) {
    Http::fake();

    expect(fn () => app(MetadataImporter::class)->importFromUrl(metadataConnection(), $url))
        ->toThrow(MetadataImportException::class, 'The metadata URL is not allowed.');

    Http::assertNothingSent();
})->with([
    'loopback' => 'https://127.0.0.1/metadata',
    'private' => 'https://10.1.2.3/metadata',
    'shared private' => 'https://172.16.0.1/metadata',
    'lan' => 'https://192.168.1.20/metadata',
    'link local' => 'https://169.254.169.254/latest/meta-data',
    'unspecified' => 'https://0.0.0.0/metadata',
    'ipv6 loopback' => 'https://[::1]/metadata',
    'ipv6 unique local' => 'https://[fd00::1]/metadata',
    'ipv6 link local' => 'https://[fe80::1]/metadata',
    'ipv4 mapped link local' => 'https://[::ffff:169.254.169.254]/latest',
    'ipv4 mapped loopback' => 'https://[::ffff:127.0.0.1]/metadata',
    'plain http' => 'http://1.1.1.1/metadata',
    'userinfo' => 'https://user:pass@1.1.1.1/metadata',
    'localhost' => 'https://localhost/metadata',
    'decimal loopback' => 'https://2130706433/latest',
    'short ip' => 'https://127.1/metadata',
]);

it('allows public addresses without fetching them', function (string $url) {
    app(MetadataUrlGuard::class)->assertFetchable($url);

    Http::assertNothingSent();
})->with([
    'https://1.1.1.1/metadata',
    'https://8.8.8.8/metadata',
    'https://172.32.0.1/metadata',
    'https://[2001:4860:4860::8888]/metadata',
    'https://[::ffff:8.8.8.8]/metadata',
]);

it('rejects a hostname that resolves to a blocked address', function (array $addresses) {
    Http::fake();
    fakeMetadataHosts(['metadata.example.test' => $addresses]);

    expect(fn () => app(MetadataImporter::class)->importFromUrl(metadataConnection(), 'https://metadata.example.test/saml'))
        ->toThrow(MetadataImportException::class, 'The metadata URL is not allowed.');

    Http::assertNothingSent();
})->with([
    'private' => [['10.0.0.5']],
    'mixed' => [['1.1.1.1', '10.0.0.5']],
    'unresolved' => [[]],
]);

it('does not follow a redirect onto a blocked address', function (string $location) {
    fakeMetadataHosts(['metadata.example.test' => ['1.1.1.1']]);
    Http::fake([
        'https://metadata.example.test/saml' => Http::response('', 302, ['Location' => $location]),
        'https://169.254.169.254/*' => Http::response('leaked', 200),
        'http://metadata.example.test/*' => Http::response('leaked', 200),
    ]);

    expect(fn () => app(MetadataImporter::class)->importFromUrl(metadataConnection(), 'https://metadata.example.test/saml'))
        ->toThrow(MetadataImportException::class, 'The metadata URL is not allowed.');

    Http::assertNotSent(fn ($request): bool => str_contains($request->url(), '169.254.169.254') || str_starts_with($request->url(), 'http://'));
})->with([
    'link local' => 'https://169.254.169.254/latest/meta-data',
    'plain http' => 'http://metadata.example.test/saml',
]);

it('follows a redirect to another public https url and stores the original metadata url', function () {
    $xml = fixtureXml('entra-metadata.xml');
    fakeMetadataHosts([
        'metadata.example.test' => ['1.1.1.1'],
        'cdn.example.test' => ['8.8.8.8'],
    ]);
    Http::fake([
        'https://metadata.example.test/saml' => Http::response('', 302, ['Location' => 'https://cdn.example.test/metadata']),
        'https://cdn.example.test/metadata' => Http::response($xml),
    ]);
    $connection = metadataConnection(['metadata_url' => 'https://metadata.example.test/saml']);

    app(MetadataImporter::class)->importFromUrl($connection, 'https://metadata.example.test/saml');

    expect($connection->fresh()->metadata_url)->toBe('https://metadata.example.test/saml')
        ->and($connection->fresh()->config['idp_entity_id'])->toBe('https://sts.windows.net/11111111-2222-3333-4444-555555555555/');
});

it('follows a relative redirect on the same host', function () {
    $xml = fixtureXml('entra-metadata.xml');
    fakeMetadataHosts(['metadata.example.test' => ['1.1.1.1']]);
    Http::fake([
        'https://metadata.example.test/saml/descriptor' => Http::response('', 302, ['Location' => '/metadata.xml']),
        'https://metadata.example.test/metadata.xml' => Http::response($xml),
    ]);

    $connection = metadataConnection();
    app(MetadataImporter::class)->importFromUrl($connection, 'https://metadata.example.test/saml/descriptor');

    expect($connection->fresh()->config['sso_url'])->toBe('https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2');
});

it('stops following redirects after three hops', function () {
    fakeMetadataHosts([
        'a.example.test' => ['1.1.1.1'],
        'b.example.test' => ['1.0.0.1'],
        'c.example.test' => ['8.8.4.4'],
        'd.example.test' => ['8.8.8.8'],
        'e.example.test' => ['9.9.9.9'],
    ]);
    Http::fake([
        'https://a.example.test/*' => Http::response('', 302, ['Location' => 'https://b.example.test/m']),
        'https://b.example.test/*' => Http::response('', 302, ['Location' => 'https://c.example.test/m']),
        'https://c.example.test/*' => Http::response('', 302, ['Location' => 'https://d.example.test/m']),
        'https://d.example.test/*' => Http::response('', 302, ['Location' => 'https://e.example.test/m']),
        'https://e.example.test/*' => Http::response('should-not-fetch', 200),
    ]);

    expect(fn () => app(MetadataImporter::class)->importFromUrl(metadataConnection(), 'https://a.example.test/m'))
        ->toThrow(MetadataImportException::class);

    Http::assertNotSent(fn ($request): bool => str_contains($request->url(), 'e.example.test'));
});

it('rejects metadata larger than the configured cap', function () {
    config()->set('gatekeep.metadata.max_bytes', 32);

    expect(fn () => app(MetadataImporter::class)->fromXml(str_repeat('a', 33)))
        ->toThrow(MetadataImportException::class, 'The identity provider metadata is too large.');

    fakeMetadataHosts(['metadata.example.test' => ['1.1.1.1']]);
    Http::fake([
        'https://metadata.example.test/body' => Http::response(str_repeat('x', 40)),
        'https://metadata.example.test/length' => Http::response('<xml/>', 200, ['Content-Length' => '5000']),
    ]);
    $connection = metadataConnection();

    expect(fn () => app(MetadataImporter::class)->importFromUrl($connection, 'https://metadata.example.test/body'))
        ->toThrow(MetadataImportException::class, 'The identity provider metadata is too large.');

    expect(fn () => app(MetadataImporter::class)->importFromUrl($connection, 'https://metadata.example.test/length'))
        ->toThrow(MetadataImportException::class, 'The identity provider metadata is too large.');
});

it('does not fire the certificate event when the certificate set is unchanged', function () {
    $url = 'https://metadata.example.test/saml';
    fakeMetadataHosts(['metadata.example.test' => ['1.1.1.1']]);
    Http::fake([
        $url => Http::response(fixtureXml('entra-metadata.xml')),
    ]);
    $connection = metadataConnection();

    Event::fake([IdpMetadataRefreshed::class, IdpCertificateChanged::class]);
    $importer = app(MetadataImporter::class);
    $importer->importFromUrl($connection, $url);
    $importer->importFromUrl($connection->fresh(), $url);

    Event::assertDispatched(IdpCertificateChanged::class, 1);
    Event::assertDispatched(IdpMetadataRefreshed::class, 2);
});

/**
 * @param  array<string, mixed>  $overrides
 */
function metadataConnection(array $overrides = []): SsoConnection
{
    return samlConnection(array_replace([
        'config' => [
            'idp_entity_id' => 'https://old.example/entity',
            'sso_url' => 'https://old.example/sso',
            'x509_certs' => ['old-cert'],
            'allow_idp_initiated' => true,
        ],
    ], $overrides));
}

/**
 * @param  array<string, list<string>>  $addresses
 */
function fakeMetadataHosts(array $addresses): void
{
    app()->instance(HostResolver::class, new StaticHostResolver($addresses));
}

function fixtureXml(string $name): string
{
    $contents = file_get_contents(dirname(__DIR__).'/fixtures/'.$name);

    expect($contents)->toBeString()->not->toBe('');

    return $contents;
}

function importedCertificateBody(string $certificate): string
{
    $body = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $certificate);

    return is_string($body) ? $body : '';
}

/**
 * @return list<string>
 */
function signingCertificateBodies(string $xml): array
{
    return certificateBodiesForUse($xml, 'signing');
}

function encryptionCertificateBody(string $xml): string
{
    return certificateBodiesForUse($xml, 'encryption')[0] ?? '';
}

/**
 * @return list<string>
 */
function certificateBodiesForUse(string $xml, string $use): array
{
    $document = new DOMDocument;
    $document->loadXML($xml);
    $xpath = new DOMXPath($document);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $nodes = $xpath->query('//md:KeyDescriptor[@use="'.$use.'"]//ds:X509Certificate');
    $bodies = [];

    foreach ($nodes === false ? [] : $nodes as $node) {
        $bodies[] = importedCertificateBody($node->textContent);
    }

    return $bodies;
}

function eventPayloadIsSafe(object $event): bool
{
    $encoded = json_encode($event);

    return is_string($encoded)
        && ! str_contains($encoded, 'BEGIN CERTIFICATE')
        && ! str_contains($encoded, 'PRIVATE KEY')
        && ! str_contains($encoded, 'samlp:Response')
        && ! str_contains($encoded, '<!DOCTYPE');
}
