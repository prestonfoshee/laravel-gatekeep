<?php

declare(strict_types=1);

namespace Gatekeep\Saml;

use Gatekeep\Enums\CertificateStatus;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Models\SpCertificate;
use Gatekeep\Models\SsoConnection;
use OneLogin\Saml2\Constants;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

/**
 * Builds a strict onelogin settings array for one connection.
 *
 * Connection config keys: idp_entity_id, sso_url, x509_certs, and an optional sp_entity_id.
 */
final class SamlSettingsFactory
{
    /**
     * @return array<string, mixed>
     */
    public function forConnection(SsoConnection $connection): array
    {
        $config = $connection->config;
        $certificate = $this->activeCertificate($connection);
        $next = $this->nextCertificate($certificate);
        $certs = $this->identityProviderCertificates($config);
        $hasCertificate = $certificate instanceof SpCertificate;
        $serviceProvider = [
            'entityId' => $this->serviceProviderEntityId($connection, $config),
            'assertionConsumerService' => [
                'url' => route('gatekeep.saml.acs', $connection),
                'binding' => Constants::BINDING_HTTP_POST,
            ],
            'NameIDFormat' => Constants::NAMEID_EMAIL_ADDRESS,
            'x509cert' => $hasCertificate ? $certificate->certificate : '',
            'privateKey' => $hasCertificate ? $certificate->private_key : '',
        ];

        if ($next instanceof SpCertificate) {
            $serviceProvider['x509certNew'] = $next->certificate;
        }

        return [
            'strict' => true,
            'debug' => false,
            'sp' => $serviceProvider,
            'idp' => [
                'entityId' => $this->requiredString($config, 'idp_entity_id'),
                'singleSignOnService' => [
                    'url' => $this->ssoUrl($config),
                    'binding' => Constants::BINDING_HTTP_REDIRECT,
                ],
                'x509cert' => $certs[0],
                'x509certMulti' => [
                    'signing' => $certs,
                ],
            ],
            'security' => [
                'authnRequestsSigned' => $hasCertificate,
                'logoutRequestSigned' => false,
                'logoutResponseSigned' => false,
                'signMetadata' => $hasCertificate,
                'wantAssertionsSigned' => $this->flag('gatekeep.saml.want_assertions_signed', true),
                'wantMessagesSigned' => $this->flag('gatekeep.saml.want_messages_signed', false),
                'wantAssertionsEncrypted' => false,
                'wantNameIdEncrypted' => false,
                'wantNameId' => true,
                'wantXMLValidation' => true,
                'relaxDestinationValidation' => false,
                'destinationStrictlyMatches' => true,
                'requireDestination' => true,
                'rejectUnsolicitedResponsesWithInResponseTo' => true,
                'signatureAlgorithm' => $this->signatureAlgorithm(),
                'digestAlgorithm' => XMLSecurityDSig::SHA256,
                'lowercaseUrlencoding' => false,
            ],
        ];
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function serviceProviderEntityId(SsoConnection $connection, array $config): string
    {
        $override = $config['sp_entity_id'] ?? null;

        if (is_string($override) && $override !== '') {
            return $override;
        }

        $configured = config('gatekeep.saml.sp_entity_id');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        return route('gatekeep.saml.metadata', $connection);
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function ssoUrl(array $config): string
    {
        $url = $this->requiredString($config, 'sso_url');

        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new SsoException('The SSO connection is not configured for SAML.');
        }

        return $url;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return list<string>
     */
    private function identityProviderCertificates(array $config): array
    {
        $certs = $config['x509_certs'] ?? null;

        if (! is_array($certs)) {
            throw new SsoException('The SSO connection is not configured for SAML.');
        }

        $normalized = [];

        foreach ($certs as $cert) {
            if (is_string($cert) && trim($cert) !== '') {
                $normalized[] = trim($cert);
            }
        }

        if ($normalized === []) {
            throw new SsoException('The SSO connection is not configured for SAML.');
        }

        return $normalized;
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function requiredString(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw new SsoException('The SSO connection is not configured for SAML.');
        }

        return $value;
    }

    private function activeCertificate(SsoConnection $connection): ?SpCertificate
    {
        $owned = $connection->certificates()
            ->where('status', CertificateStatus::Active)
            ->orderByDesc('id')
            ->first();

        if ($owned instanceof SpCertificate) {
            return $owned;
        }

        $global = SpCertificate::query()
            ->whereNull('sso_connection_id')
            ->where('status', CertificateStatus::Active)
            ->orderByDesc('id')
            ->first();

        return $global instanceof SpCertificate ? $global : null;
    }

    /**
     * The next certificate is published beside the active one, and only from the same scope.
     * A connection active certificate does not pick up the global next certificate.
     */
    private function nextCertificate(?SpCertificate $active): ?SpCertificate
    {
        if (! $active instanceof SpCertificate) {
            return null;
        }

        $query = SpCertificate::query()->where('status', CertificateStatus::Next);

        if ($active->sso_connection_id === null) {
            $query->whereNull('sso_connection_id');
        } else {
            $query->where('sso_connection_id', $active->sso_connection_id);
        }

        $next = $query->orderByDesc('id')->first();

        return $next instanceof SpCertificate ? $next : null;
    }

    private function flag(string $key, bool $default): bool
    {
        $value = config($key);

        return is_bool($value) ? $value : $default;
    }

    private function signatureAlgorithm(): string
    {
        $algorithm = config('gatekeep.saml.signature_algorithm');

        if (! is_string($algorithm) || $algorithm === '') {
            return 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        }

        return $algorithm;
    }
}
