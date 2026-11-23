<?php

declare(strict_types=1);

namespace Gatekeep\Saml;

use Carbon\CarbonImmutable;
use DOMComment;
use DOMDocument;
use Gatekeep\Contracts\ProtocolDriver;
use Gatekeep\Contracts\ReplayGuard;
use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\ExpiredAssertion;
use Gatekeep\Exceptions\InResponseToMismatch;
use Gatekeep\Exceptions\InvalidSignature;
use Gatekeep\Exceptions\ReplayDetected;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Support\SafeRedirect;
use Gatekeep\ValueObjects\LoginIntent;
use Gatekeep\ValueObjects\SsoUser;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\Utils;
use Throwable;

final class SamlDriver implements ProtocolDriver
{
    public function __construct(
        private readonly SamlSettingsFactory $settings,
        private readonly SamlErrorMapper $errors,
        private readonly ReplayGuard $replay,
        private readonly SafeRedirect $redirects,
    ) {}

    public function protocol(): Protocol
    {
        return Protocol::Saml;
    }

    public function redirect(SsoConnection $connection, LoginIntent $intent): RedirectResponse
    {
        $auth = $this->auth($connection);
        $returnTo = $this->redirects->sanitize($intent->returnTo ?? $intent->relayState);
        $relayState = $returnTo ?? $this->home();

        try {
            $url = $auth->login(
                returnTo: $relayState,
                parameters: [],
                forceAuthn: $intent->forceAuthn,
                isPassive: false,
                stay: true,
            );
        } catch (Error $exception) {
            throw $this->errors->map($exception);
        }

        if ($url === '') {
            throw new SsoException('The SSO connection is not configured for SAML.');
        }

        $requestId = $auth->getLastRequestID();

        if ($requestId === '') {
            throw new SsoException('The SSO connection is not configured for SAML.');
        }

        session()->put(SamlSession::requestId($connection->id), $requestId);

        if ($returnTo !== null) {
            session()->put(SamlSession::returnTo($connection->id), $returnTo);
        } else {
            session()->forget(SamlSession::returnTo($connection->id));
        }

        return redirect()->away($url);
    }

    public function handleCallback(SsoConnection $connection, Request $request): SsoUser
    {
        $requestId = session(SamlSession::requestId($connection->id));

        // IdP-initiated responses have no stored AuthnRequest. Phase 3 owns that flow.
        if (! is_string($requestId) || $requestId === '') {
            throw new InResponseToMismatch;
        }

        $payload = $request->input('SAMLResponse');

        if (! is_string($payload) || $payload === '') {
            throw new InvalidSignature;
        }

        $auth = $this->auth($connection);
        $previousPost = $_POST;
        $server = null;

        try {
            $server = $this->alignToolkitUrl($request);
            $_POST['SAMLResponse'] = $payload;

            $relayState = $request->input('RelayState');

            if (is_string($relayState)) {
                $_POST['RelayState'] = $relayState;
            }

            try {
                $auth->processResponse($requestId);
            } catch (Throwable $exception) {
                throw $this->errors->map($exception);
            }

            if (! $auth->isAuthenticated()) {
                $exception = $auth->getLastErrorException();

                throw $this->errors->map($exception ?? new SsoException);
            }

            $xml = $auth->getLastResponseXML();

            if (! is_string($xml) || $xml === '') {
                throw new InvalidSignature;
            }

            $this->rejectUnsafeNameId($xml);
            $this->assertWithinConfiguredSkew($xml, $auth->getLastAssertionNotOnOrAfter());
            $this->claimAssertion($connection, $auth);

            return $this->userFrom($auth);
        } finally {
            $_POST = $previousPost;

            if ($server !== null) {
                $this->restoreServer($server);
            }
        }
    }

    public function metadata(SsoConnection $connection): Response
    {
        $auth = $this->auth($connection);

        try {
            $xml = $auth->getSettings()->getSPMetadata();
            $errors = $auth->getSettings()->validateMetadata($xml);
        } catch (Error $exception) {
            throw $this->errors->map($exception);
        }

        if ($errors !== []) {
            throw new SsoException('Service provider metadata is invalid.');
        }

        return response($xml, 200, ['Content-Type' => 'application/samlmetadata+xml']);
    }

    private function auth(SsoConnection $connection): Auth
    {
        try {
            return new Auth($this->settings->forConnection($connection));
        } catch (Error $exception) {
            throw $this->errors->map($exception);
        }
    }

    private function claimAssertion(SsoConnection $connection, Auth $auth): void
    {
        $assertionId = $auth->getLastAssertionId();

        if ($assertionId === '') {
            throw new InvalidSignature;
        }

        $expiresAt = CarbonImmutable::createFromTimestamp($auth->getLastAssertionNotOnOrAfter());

        if (! $this->replay->claim($connection->id, $assertionId, $expiresAt)) {
            throw new ReplayDetected;
        }
    }

    private function assertWithinConfiguredSkew(string $xml, int $acceptedNotOnOrAfter): void
    {
        $skew = $this->clockSkew();
        $now = time();
        $document = $this->document($xml);

        foreach ($document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Conditions') as $conditions) {
            $this->assertWindow(
                $this->timestamp($conditions->getAttribute('NotBefore')),
                $this->timestamp($conditions->getAttribute('NotOnOrAfter')),
                $now,
                $skew,
            );
        }

        $this->assertWindow(null, $acceptedNotOnOrAfter, $now, $skew);
    }

    private function assertWindow(?int $notBefore, ?int $notOnOrAfter, int $now, int $skew): void
    {
        if ($notBefore !== null && $notBefore > $now + $skew) {
            throw new ExpiredAssertion('The SSO response is not valid yet.');
        }

        if ($notOnOrAfter !== null && $notOnOrAfter + $skew <= $now) {
            throw new ExpiredAssertion;
        }
    }

    private function timestamp(string $value): ?int
    {
        if ($value === '') {
            return null;
        }

        try {
            return Utils::parseSAML2Time($value);
        } catch (Throwable) {
            throw new SsoException;
        }
    }

    private function rejectUnsafeNameId(string $xml): void
    {
        $document = $this->document($xml);

        if ($document->doctype !== null) {
            throw new InvalidSignature;
        }

        foreach ($document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'NameID') as $nameId) {
            foreach ($nameId->childNodes as $child) {
                if ($child instanceof DOMComment) {
                    throw new InvalidSignature;
                }
            }
        }
    }

    private function document(string $xml): DOMDocument
    {
        $document = new DOMDocument;
        $internal = libxml_use_internal_errors(true);
        $loaded = $document->loadXML($xml, LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($internal);

        if ($loaded !== true) {
            throw new InvalidSignature;
        }

        return $document;
    }

    private function userFrom(Auth $auth): SsoUser
    {
        $nameId = $auth->getNameId();

        if ($nameId === '') {
            throw new InvalidSignature;
        }

        /** @var array<array-key, mixed> $attributes */
        $attributes = $auth->getAttributes();
        $email = $this->attribute($attributes, 'email', 'mail', 'Email') ?? $nameId;

        return new SsoUser(
            id: $nameId,
            email: $email,
            firstName: $this->attribute($attributes, 'first_name', 'firstName', 'givenName'),
            lastName: $this->attribute($attributes, 'last_name', 'lastName', 'surname'),
            groups: [],
            raw: $attributes,
        );
    }

    /**
     * @param  array<array-key, mixed>  $attributes
     */
    private function attribute(array $attributes, string ...$names): ?string
    {
        foreach ($names as $name) {
            if (! array_key_exists($name, $attributes)) {
                continue;
            }

            $values = $attributes[$name];

            if (is_string($values) && $values !== '') {
                return $values;
            }

            if (! is_array($values)) {
                continue;
            }

            foreach ($values as $value) {
                if (is_string($value) && $value !== '') {
                    return $value;
                }
            }
        }

        return null;
    }

    /**
     * php-saml compares Destination to the PHP request URL, not the Laravel request.
     *
     * @return array<string, string|null>
     */
    private function alignToolkitUrl(Request $request): array
    {
        $backup = [];

        foreach (['HTTP_HOST', 'SERVER_NAME', 'SERVER_PORT', 'HTTPS', 'REQUEST_URI', 'QUERY_STRING'] as $key) {
            $current = $_SERVER[$key] ?? null;
            $backup[$key] = is_string($current) ? $current : null;
        }

        $port = $request->getPort();
        Utils::setSelfProtocol($request->getScheme());
        Utils::setSelfHost($request->getHost());
        Utils::setSelfPort($port);

        $_SERVER['HTTP_HOST'] = $request->getHttpHost();
        $_SERVER['SERVER_NAME'] = $request->getHost();
        $_SERVER['SERVER_PORT'] = (string) $port;
        $_SERVER['HTTPS'] = $request->isSecure() ? 'on' : 'off';
        $_SERVER['REQUEST_URI'] = $request->getRequestUri();
        $_SERVER['QUERY_STRING'] = (string) ($request->getQueryString() ?? '');

        return $backup;
    }

    /**
     * @param  array<string, string|null>  $backup
     */
    private function restoreServer(array $backup): void
    {
        foreach ($backup as $key => $value) {
            if ($value === null) {
                unset($_SERVER[$key]);

                continue;
            }

            $_SERVER[$key] = $value;
        }
    }

    private function clockSkew(): int
    {
        $skew = config('gatekeep.saml.clock_skew_seconds', 120);
        $skew = is_numeric($skew) ? (int) $skew : 120;

        return max(0, $skew);
    }

    private function home(): string
    {
        $home = config('gatekeep.home', '/dashboard');
        $safe = $this->redirects->sanitize(is_string($home) ? $home : null);

        return $safe ?? '/';
    }
}
