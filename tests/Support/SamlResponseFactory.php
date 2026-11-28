<?php

declare(strict_types=1);

namespace Gatekeep\Tests\Support;

use DOMDocument;
use DOMElement;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

/**
 * Builds signed SAML responses with an in-process test keypair. No network.
 */
final class SamlResponseFactory
{
    private const ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private static ?string $privateKey = null;

    private static ?string $certificate = null;

    private static ?string $wrongPrivateKey = null;

    private static ?string $wrongCertificate = null;

    private static ?string $serviceProviderPrivateKey = null;

    private static ?string $serviceProviderCertificate = null;

    public static function certificate(): string
    {
        return self::identityProvider()['certificate'];
    }

    public static function privateKey(): string
    {
        return self::identityProvider()['private_key'];
    }

    public static function wrongCertificate(): string
    {
        return self::wrongIdentityProvider()['certificate'];
    }

    public static function serviceProviderCertificate(): string
    {
        return self::serviceProvider()['certificate'];
    }

    public static function serviceProviderPrivateKey(): string
    {
        return self::serviceProvider()['private_key'];
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public static function xml(array $options = []): string
    {
        $now = time();
        $nameId = self::stringOption($options, 'nameId', 'alice@acme.com');
        $email = self::stringOption($options, 'email', $nameId);
        $destination = self::stringOption($options, 'destination', 'http://localhost/acs');
        $inResponseTo = array_key_exists('inResponseTo', $options) ? $options['inResponseTo'] : '_request';
        $inResponseTo = is_string($inResponseTo) ? $inResponseTo : null;
        $sign = array_key_exists('sign', $options) ? (bool) $options['sign'] : true;
        $signing = self::stringOption($options, 'signing', 'idp');
        $keypair = $signing === 'wrong' ? self::wrongIdentityProvider() : self::identityProvider();

        $xml = self::document(
            responseId: '_'.bin2hex(random_bytes(16)),
            assertionId: '_'.bin2hex(random_bytes(16)),
            issueInstant: self::samlTime($now),
            destination: $destination,
            recipient: self::stringOption($options, 'recipient', $destination),
            issuer: self::stringOption($options, 'issuer', 'https://idp.acme.test/entity'),
            audience: self::stringOption($options, 'audience', 'http://localhost/sp'),
            nameIdXml: self::nameIdXml($nameId, (bool) ($options['commentInNameId'] ?? false)),
            email: $email,
            firstName: self::stringOption($options, 'firstName', 'Alice'),
            lastName: self::stringOption($options, 'lastName', 'Adams'),
            inResponseTo: $inResponseTo,
            notBefore: self::samlTime(self::intOption($options, 'notBefore', $now - 30)),
            notOnOrAfter: self::samlTime(self::intOption($options, 'notOnOrAfter', $now + 300)),
        );

        if ($sign) {
            $xml = self::signAssertion($xml, $keypair['private_key'], $keypair['certificate']);
        }

        $tamper = $options['tamperNameId'] ?? null;

        if (is_string($tamper)) {
            $xml = self::replaceNameId($xml, $tamper);
        }

        if (($options['wrap'] ?? false) === true) {
            $xml = self::wrapAssertion($xml);
        }

        if (($options['doctype'] ?? false) === true) {
            $xml = self::injectDoctype($xml);
        }

        return $xml;
    }

    /**
     * @return array{private_key: string, certificate: string}
     */
    private static function identityProvider(): array
    {
        if (self::$privateKey === null || self::$certificate === null) {
            [$privateKey, $certificate] = self::generate('gatekeep-test-idp');
            self::$privateKey = $privateKey;
            self::$certificate = $certificate;
        }

        return [
            'private_key' => self::$privateKey,
            'certificate' => self::$certificate,
        ];
    }

    /**
     * @return array{private_key: string, certificate: string}
     */
    private static function wrongIdentityProvider(): array
    {
        if (self::$wrongPrivateKey === null || self::$wrongCertificate === null) {
            [$privateKey, $certificate] = self::generate('gatekeep-test-wrong');
            self::$wrongPrivateKey = $privateKey;
            self::$wrongCertificate = $certificate;
        }

        return [
            'private_key' => self::$wrongPrivateKey,
            'certificate' => self::$wrongCertificate,
        ];
    }

    /**
     * @return array{private_key: string, certificate: string}
     */
    private static function serviceProvider(): array
    {
        if (self::$serviceProviderPrivateKey === null || self::$serviceProviderCertificate === null) {
            [$privateKey, $certificate] = self::generate('gatekeep-test-sp');
            self::$serviceProviderPrivateKey = $privateKey;
            self::$serviceProviderCertificate = $certificate;
        }

        return [
            'private_key' => self::$serviceProviderPrivateKey,
            'certificate' => self::$serviceProviderCertificate,
        ];
    }

    /**
     * @return array{0: string, 1: string}
     */
    private static function generate(string $commonName): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if ($key === false) {
            throw new RuntimeException('Unable to generate a test SAML key.');
        }

        $exported = openssl_pkey_export($key, $privateKey);

        if ($exported !== true || ! is_string($privateKey)) {
            throw new RuntimeException('Unable to export a test SAML key.');
        }

        $csr = openssl_csr_new(['commonName' => $commonName], $key);

        if ($csr === false) {
            throw new RuntimeException('Unable to generate a test SAML certificate request.');
        }

        $signed = openssl_csr_sign($csr, null, $key, 365);

        if ($signed === false) {
            throw new RuntimeException('Unable to sign a test SAML certificate.');
        }

        $exportedCertificate = openssl_x509_export($signed, $certificate);

        if ($exportedCertificate !== true || ! is_string($certificate)) {
            throw new RuntimeException('Unable to export a test SAML certificate.');
        }

        return [$privateKey, $certificate];
    }

    private static function document(
        string $responseId,
        string $assertionId,
        string $issueInstant,
        string $destination,
        string $recipient,
        string $issuer,
        string $audience,
        string $nameIdXml,
        string $email,
        string $firstName,
        string $lastName,
        ?string $inResponseTo,
        string $notBefore,
        string $notOnOrAfter,
    ): string {
        $responseInResponseTo = $inResponseTo === null ? '' : ' InResponseTo="'.self::escape($inResponseTo).'"';
        $subjectInResponseTo = $inResponseTo === null ? '' : ' InResponseTo="'.self::escape($inResponseTo).'"';

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$responseId}" Version="2.0" IssueInstant="{$issueInstant}" Destination="{$destination}"{$responseInResponseTo}>
  <saml:Issuer>{$issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$assertionId}" Version="2.0" IssueInstant="{$issueInstant}">
    <saml:Issuer>{$issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{$nameIdXml}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData{$subjectInResponseTo} Recipient="{$recipient}" NotOnOrAfter="{$notOnOrAfter}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{$notBefore}" NotOnOrAfter="{$notOnOrAfter}">
      <saml:AudienceRestriction>
        <saml:Audience>{$audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{$issueInstant}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{$email}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="first_name">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{$firstName}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="last_name">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{$lastName}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML;
    }

    private static function signAssertion(string $xml, string $privateKey, string $certificate): string
    {
        $dom = self::load($xml);
        $assertion = $dom->getElementsByTagNameNS(self::ASSERTION_NS, 'Assertion')->item(0);

        if (! $assertion instanceof DOMElement) {
            throw new RuntimeException('The test SAML response is missing an assertion.');
        }

        $signature = new XMLSecurityDSig;
        $signature->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $signature->addReferenceList(
            [$assertion],
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false],
        );

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($privateKey, false);
        $signature->sign($key);
        $signature->add509Cert($certificate, true);

        $issuer = null;

        foreach ($assertion->childNodes as $child) {
            if ($child instanceof DOMElement && $child->localName === 'Issuer') {
                $issuer = $child;
                break;
            }
        }

        $signature->insertSignature($assertion, $issuer?->nextSibling);

        $signed = $dom->saveXML();

        if (! is_string($signed)) {
            throw new RuntimeException('Unable to serialize the signed SAML response.');
        }

        return $signed;
    }

    private static function replaceNameId(string $xml, string $nameId): string
    {
        $dom = self::load($xml);
        $node = $dom->getElementsByTagNameNS(self::ASSERTION_NS, 'NameID')->item(0);

        if (! $node instanceof DOMElement) {
            throw new RuntimeException('The test SAML response is missing a NameID.');
        }

        $node->nodeValue = $nameId;
        $serialized = $dom->saveXML();

        if (! is_string($serialized)) {
            throw new RuntimeException('Unable to serialize the tampered SAML response.');
        }

        return $serialized;
    }

    private static function wrapAssertion(string $xml): string
    {
        $dom = self::load($xml);
        $response = $dom->getElementsByTagNameNS(self::PROTOCOL_NS, 'Response')->item(0);
        $original = $dom->getElementsByTagNameNS(self::ASSERTION_NS, 'Assertion')->item(0);

        if (! $response instanceof DOMElement || ! $original instanceof DOMElement) {
            throw new RuntimeException('The test SAML response cannot be wrapped.');
        }

        $wrapped = $original->cloneNode(true);

        if (! $wrapped instanceof DOMElement) {
            throw new RuntimeException('The wrapped assertion could not be cloned.');
        }

        $wrapped->setAttribute('ID', '_'.bin2hex(random_bytes(8)));
        $nameId = $wrapped->getElementsByTagNameNS(self::ASSERTION_NS, 'NameID')->item(0);

        if ($nameId instanceof DOMElement) {
            $nameId->nodeValue = 'attacker@evil.test';
        }

        $response->insertBefore($wrapped, $original);
        $serialized = $dom->saveXML();

        if (! is_string($serialized)) {
            throw new RuntimeException('Unable to serialize the wrapped SAML response.');
        }

        return $serialized;
    }

    private static function injectDoctype(string $xml): string
    {
        $withoutDeclaration = preg_replace('/^<\?xml[^>]*>\s*/', '', $xml);

        if (! is_string($withoutDeclaration)) {
            throw new RuntimeException('Unable to prepare a DOCTYPE SAML payload.');
        }

        return '<?xml version="1.0" encoding="UTF-8"?>'."\n"
            .'<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'."\n"
            .$withoutDeclaration;
    }

    private static function nameIdXml(string $nameId, bool $comment): string
    {
        $escaped = self::escape($nameId);

        if (! $comment) {
            return $escaped;
        }

        return $escaped.'<!--injected-->@evil.test';
    }

    private static function load(string $xml): DOMDocument
    {
        $dom = new DOMDocument;
        $dom->preserveWhiteSpace = false;
        $loaded = $dom->loadXML($xml, LIBXML_NONET);

        if ($loaded !== true) {
            throw new RuntimeException('Unable to parse a test SAML response.');
        }

        return $dom;
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private static function stringOption(array $options, string $key, string $default): string
    {
        $value = $options[$key] ?? $default;

        if (! is_string($value) || $value === '') {
            return $default;
        }

        return self::escape($value);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private static function intOption(array $options, string $key, int $default): int
    {
        $value = $options[$key] ?? $default;

        return is_int($value) ? $value : $default;
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1);
    }

    private static function samlTime(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }
}
