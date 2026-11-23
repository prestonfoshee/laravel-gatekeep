<?php

declare(strict_types=1);

namespace Gatekeep\Saml;

use Gatekeep\Exceptions\AudienceMismatch;
use Gatekeep\Exceptions\DestinationMismatch;
use Gatekeep\Exceptions\ExpiredAssertion;
use Gatekeep\Exceptions\InResponseToMismatch;
use Gatekeep\Exceptions\InvalidSignature;
use Gatekeep\Exceptions\IssuerMismatch;
use Gatekeep\Exceptions\SsoException;
use OneLogin\Saml2\ValidationError;
use Throwable;

final class SamlErrorMapper
{
    public function map(Throwable $exception): SsoException
    {
        $code = $exception instanceof ValidationError ? $exception->getCode() : null;
        $message = $exception->getMessage();

        if ($this->isSignatureFailure($code, $message)) {
            return new InvalidSignature;
        }

        if ($code === ValidationError::WRONG_AUDIENCE) {
            return new AudienceMismatch;
        }

        if ($this->isExpired($code)) {
            return new ExpiredAssertion;
        }

        if ($this->isDestination($code)) {
            return new DestinationMismatch;
        }

        if ($code === ValidationError::WRONG_INRESPONSETO) {
            return new InResponseToMismatch;
        }

        if ($this->isIssuer($code)) {
            return new IssuerMismatch;
        }

        return new SsoException;
    }

    private function isSignatureFailure(?int $code, string $message): bool
    {
        $signatureCodes = [
            ValidationError::WRONG_NUMBER_OF_ASSERTIONS,
            ValidationError::WRONG_SIGNED_ELEMENT,
            ValidationError::ID_NOT_FOUND_IN_SIGNED_ELEMENT,
            ValidationError::DUPLICATED_ID_IN_SIGNED_ELEMENTS,
            ValidationError::INVALID_SIGNED_ELEMENT,
            ValidationError::DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS,
            ValidationError::UNEXPECTED_SIGNED_ELEMENTS,
            ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE,
            ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION,
            ValidationError::NO_SIGNED_MESSAGE,
            ValidationError::NO_SIGNED_ASSERTION,
            ValidationError::NO_SIGNATURE_FOUND,
            ValidationError::INVALID_SIGNATURE,
            ValidationError::WRONG_NUMBER_OF_SIGNATURES,
            ValidationError::UNEXPECTED_REFERENCE,
        ];

        if ($code !== null && in_array($code, $signatureCodes, true)) {
            return true;
        }

        return str_contains($message, 'Signature')
            || str_contains($message, 'Reference validation failed')
            || str_contains($message, 'DOCTYPE');
    }

    private function isExpired(?int $code): bool
    {
        return in_array($code, [
            ValidationError::ASSERTION_TOO_EARLY,
            ValidationError::ASSERTION_EXPIRED,
            ValidationError::SESSION_EXPIRED,
            ValidationError::RESPONSE_EXPIRED,
        ], true);
    }

    private function isDestination(?int $code): bool
    {
        return in_array($code, [
            ValidationError::WRONG_DESTINATION,
            ValidationError::EMPTY_DESTINATION,
            ValidationError::MISSING_DESTINATION,
            ValidationError::WRONG_SUBJECTCONFIRMATION,
        ], true);
    }

    private function isIssuer(?int $code): bool
    {
        return in_array($code, [
            ValidationError::ISSUER_MULTIPLE_IN_RESPONSE,
            ValidationError::ISSUER_NOT_FOUND_IN_ASSERTION,
            ValidationError::WRONG_ISSUER,
        ], true);
    }
}
