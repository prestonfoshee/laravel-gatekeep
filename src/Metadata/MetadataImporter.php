<?php

declare(strict_types=1);

namespace Gatekeep\Metadata;

use Gatekeep\Events\IdpCertificateChanged;
use Gatekeep\Events\IdpMetadataRefreshed;
use Gatekeep\Exceptions\MetadataImportException;
use Gatekeep\Models\SsoConnection;
use Gatekeep\ValueObjects\ImportedIdpMetadata;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\IdPMetadataParser;
use Throwable;

/**
 * Imports IdP metadata from an XML document or an HTTPS URL.
 *
 * Remote documents are fetched with the Laravel HTTP client. parseRemoteXML() is not
 * used: it follows redirects, allows plain HTTP, and disables peer verification.
 */
final class MetadataImporter
{
    private const MAX_REDIRECTS = 3;

    public function __construct(private readonly MetadataUrlGuard $urls) {}

    public function fromXml(string $xml): ImportedIdpMetadata
    {
        if ($xml === '') {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }

        if (strlen($xml) > $this->maxBytes()) {
            throw new MetadataImportException('The identity provider metadata is too large.');
        }

        try {
            $parsed = IdPMetadataParser::parseXML($xml);
        } catch (Throwable) {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }

        return $this->metadataFromParsed($parsed);
    }

    public function importFromUrl(SsoConnection $connection, string $url): void
    {
        $this->apply($connection, $this->fromXml($this->fetch($url)), $url);
    }

    public function apply(SsoConnection $connection, ImportedIdpMetadata $metadata, ?string $metadataUrl = null): void
    {
        $previous = $this->certificateBodies($this->configuredCertificates($connection));
        $imported = $this->certificateBodies($metadata->certificates);

        $config = $connection->config;
        $config['idp_entity_id'] = $metadata->entityId;
        $config['sso_url'] = $metadata->ssoUrl;
        $config['x509_certs'] = $metadata->certificates;
        $connection->config = $config;
        $connection->metadata_refreshed_at = now();

        if ($metadataUrl !== null) {
            $connection->metadata_url = $metadataUrl;
        }

        $connection->save();

        if ($previous !== $imported) {
            Event::dispatch(new IdpCertificateChanged($connection->id));
        }

        Event::dispatch(new IdpMetadataRefreshed($connection->id, $connection->metadata_url));
    }

    /**
     * @param  array<mixed>  $parsed
     */
    private function metadataFromParsed(array $parsed): ImportedIdpMetadata
    {
        $idp = $parsed['idp'] ?? null;

        if (! is_array($idp)) {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }

        $entityId = $idp['entityId'] ?? null;
        $service = $idp['singleSignOnService'] ?? null;

        if (! is_string($entityId) || $entityId === '' || ! is_array($service)) {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }

        $url = $service['url'] ?? null;
        $binding = $service['binding'] ?? null;

        if (! is_string($url) || filter_var($url, FILTER_VALIDATE_URL) === false || $binding !== Constants::BINDING_HTTP_REDIRECT) {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }

        return new ImportedIdpMetadata($entityId, $url, $this->certificates($idp));
    }

    /**
     * @param  array<mixed>  $idp
     * @return list<string>
     */
    private function certificates(array $idp): array
    {
        $raw = [];
        $multi = $idp['x509certMulti'] ?? null;

        if (is_array($multi)) {
            $signing = $multi['signing'] ?? null;

            if (is_array($signing)) {
                foreach ($signing as $certificate) {
                    if (is_string($certificate) && trim($certificate) !== '') {
                        $raw[] = $certificate;
                    }
                }
            }
        }

        if ($raw === []) {
            $single = $idp['x509cert'] ?? null;

            if (is_string($single) && trim($single) !== '') {
                $raw[] = $single;
            }
        }

        $certificates = [];

        foreach ($raw as $certificate) {
            $pem = $this->pem($certificate);

            if (! in_array($pem, $certificates, true)) {
                $certificates[] = $pem;
            }
        }

        if ($certificates === []) {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }

        return $certificates;
    }

    private function fetch(string $url): string
    {
        return $this->download($url, self::MAX_REDIRECTS, []);
    }

    /**
     * @param  array<string, true>  $seen
     */
    private function download(string $url, int $redirectsRemaining, array $seen): string
    {
        if (isset($seen[$url]) || $redirectsRemaining < 0) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        $seen[$url] = true;
        $response = $this->request($url);

        if ($response->redirect()) {
            $location = $response->header('Location');

            if ($location === '') {
                throw new MetadataImportException('The metadata URL is not allowed.');
            }

            return $this->download($this->resolveRedirect($url, $location), $redirectsRemaining - 1, $seen);
        }

        if (! $response->successful()) {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }

        return $this->body($response);
    }

    private function request(string $url): Response
    {
        $host = $this->urls->host($url);
        $addresses = $this->urls->addresses($url);
        $maxBytes = $this->maxBytes();
        $options = [
            'timeout' => 10,
            'connect_timeout' => 5,
            'progress' => function (mixed $downloadTotal, mixed $downloaded) use ($maxBytes): void {
                if (is_numeric($downloaded) && (int) $downloaded > $maxBytes) {
                    throw new MetadataImportException('The identity provider metadata is too large.');
                }
            },
        ];

        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            $port = $this->urls->port($url);
            $options['curl'] = [
                CURLOPT_RESOLVE => array_map(
                    fn (string $address): string => $this->resolveEntry($host, $port, $address),
                    $addresses,
                ),
            ];
        }

        try {
            return Http::withOptions($options)
                ->withHeaders(['Accept' => 'application/samlmetadata+xml, application/xml, text/xml'])
                ->withoutRedirecting()
                ->get($url);
        } catch (MetadataImportException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new MetadataImportException('The identity provider metadata could not be imported.');
        }
    }

    private function body(Response $response): string
    {
        $maxBytes = $this->maxBytes();
        $length = $response->header('Content-Length');

        if ($length !== '' && ctype_digit($length) && (int) $length > $maxBytes) {
            throw new MetadataImportException('The identity provider metadata is too large.');
        }

        $body = $response->body();

        if (strlen($body) > $maxBytes) {
            throw new MetadataImportException('The identity provider metadata is too large.');
        }

        return $body;
    }

    private function resolveRedirect(string $current, string $location): string
    {
        $location = trim($location);

        if ($location === '' || preg_match('/[\s\\\\]/', $location) === 1) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        if (str_starts_with($location, 'https://') || str_starts_with($location, 'http://')) {
            return $location;
        }

        if (str_starts_with($location, '//')) {
            return 'https:'.$location;
        }

        $parts = parse_url($current);

        if (! isset($parts['scheme'], $parts['host'])) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        $origin = $parts['scheme'].'://'.$parts['host'];

        if (isset($parts['port'])) {
            $origin .= ':'.$parts['port'];
        }

        if (str_starts_with($location, '/')) {
            return $origin.$location;
        }

        $path = $parts['path'] ?? '/';
        $directory = str_contains($path, '/') ? substr($path, 0, (int) strrpos($path, '/') + 1) : '/';

        return $origin.$directory.$location;
    }

    private function resolveEntry(string $host, int $port, string $address): string
    {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $host.':'.$port.':['.$address.']';
        }

        return $host.':'.$port.':'.$address;
    }

    private function pem(string $certificate): string
    {
        $body = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $certificate);
        $body = is_string($body) ? $body : '';
        $wrapped = trim(chunk_split($body, 64, "\n"));

        return "-----BEGIN CERTIFICATE-----\n".$wrapped."\n-----END CERTIFICATE-----\n";
    }

    /**
     * @return list<string>
     */
    private function configuredCertificates(SsoConnection $connection): array
    {
        $certificates = $connection->config['x509_certs'] ?? null;

        if (! is_array($certificates)) {
            return [];
        }

        $values = [];

        foreach ($certificates as $certificate) {
            if (is_string($certificate)) {
                $values[] = $certificate;
            }
        }

        return $values;
    }

    /**
     * @param  list<string>  $certificates
     * @return list<string>
     */
    private function certificateBodies(array $certificates): array
    {
        $bodies = [];

        foreach ($certificates as $certificate) {
            $body = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $certificate);

            if (is_string($body) && $body !== '') {
                $bodies[] = $body;
            }
        }

        sort($bodies);

        return $bodies;
    }

    private function maxBytes(): int
    {
        $configured = config('gatekeep.metadata.max_bytes', 262144);
        $max = is_numeric($configured) ? (int) $configured : 262144;

        return max(1, $max);
    }
}
