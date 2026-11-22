<?php

declare(strict_types=1);

namespace Gatekeep\Support;

use InvalidArgumentException;
use RuntimeException;

final class DomainNormalizer
{
    public static function normalize(string $domain): string
    {
        $domain = mb_strtolower(trim($domain), 'UTF-8');
        $domain = rtrim($domain, '.');

        if ($domain === '') {
            throw new InvalidArgumentException('SSO domain cannot be empty.');
        }

        if (str_contains($domain, '@')) {
            throw new InvalidArgumentException('SSO domain must not contain @.');
        }

        if (preg_match('/\s/u', $domain) === 1) {
            throw new InvalidArgumentException('SSO domain cannot contain whitespace.');
        }

        if (preg_match('/[^\x20-\x7E]/', $domain) !== 1) {
            return $domain;
        }

        if (! function_exists('idn_to_ascii')) {
            throw new RuntimeException('The intl extension is required to normalize internationalized domain names.');
        }

        $ascii = idn_to_ascii($domain, IDNA_DEFAULT);

        if (! is_string($ascii) || $ascii === '') {
            throw new InvalidArgumentException('SSO domain could not be normalized.');
        }

        return strtolower($ascii);
    }

    /**
     * @param  array<mixed>  $domains
     * @return list<string>
     */
    public static function normalizeMany(array $domains): array
    {
        $normalized = [];

        foreach ($domains as $domain) {
            if (! is_string($domain)) {
                throw new InvalidArgumentException('SSO domains must be strings.');
            }

            $normalized[] = self::normalize($domain);
        }

        return array_values(array_unique($normalized));
    }

    public static function fromEmail(string $email): ?string
    {
        $email = trim($email);
        $separator = strrpos($email, '@');

        if ($separator === false) {
            return null;
        }

        $domain = substr($email, $separator + 1);

        if ($domain === '') {
            return null;
        }

        try {
            return self::normalize($domain);
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    public static function subdomain(string $host, string $baseDomain): ?string
    {
        $host = self::stripPort(trim($host));

        if ($host === '' || trim($baseDomain) === '') {
            return null;
        }

        try {
            $host = self::normalize($host);
            $baseDomain = self::normalize($baseDomain);
        } catch (InvalidArgumentException) {
            return null;
        }

        if ($host === $baseDomain || ! str_ends_with($host, '.'.$baseDomain)) {
            return null;
        }

        $subdomain = substr($host, 0, -strlen('.'.$baseDomain));

        return $subdomain === '' ? null : $subdomain;
    }

    private static function stripPort(string $host): string
    {
        if (str_starts_with($host, '[')) {
            return $host;
        }

        $stripped = preg_replace('/:\d+$/', '', $host);

        return is_string($stripped) ? $stripped : $host;
    }
}
