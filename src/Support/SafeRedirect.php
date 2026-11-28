<?php

declare(strict_types=1);

namespace Gatekeep\Support;

final class SafeRedirect
{
    /**
     * Return a relative path or an allow-listed absolute URL. Anything else is discarded.
     */
    public function sanitize(?string $target): ?string
    {
        if ($target === null) {
            return null;
        }

        $target = trim($target);

        if ($target === '') {
            return null;
        }

        if ($this->isSafeRelative($target)) {
            return $target;
        }

        return $this->safeAbsolute($target);
    }

    private function isSafeRelative(string $target): bool
    {
        if (! str_starts_with($target, '/') || str_starts_with($target, '//') || str_starts_with($target, '/\\')) {
            return false;
        }

        if (preg_match('/[\x00-\x1F\x7F\\\\]/', $target) === 1) {
            return false;
        }

        $decoded = rawurldecode($target);

        if ($decoded !== $target) {
            return $this->isSafeRelative($decoded);
        }

        return true;
    }

    private function safeAbsolute(string $target): ?string
    {
        if (preg_match('/[\x00-\x1F\x7F\\\\]/', $target) === 1) {
            return null;
        }

        $parts = parse_url($target);

        if (! is_array($parts)) {
            return null;
        }

        $scheme = $parts['scheme'] ?? null;
        $host = $parts['host'] ?? null;

        if (! is_string($scheme) || ! is_string($host)) {
            return null;
        }

        if (! in_array(strtolower($scheme), ['http', 'https'], true)) {
            return null;
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }

        if (! $this->hostAllowed(strtolower($host))) {
            return null;
        }

        return $target;
    }

    private function hostAllowed(string $host): bool
    {
        return in_array($host, $this->allowedHosts(), true);
    }

    /**
     * @return list<string>
     */
    private function allowedHosts(): array
    {
        $hosts = [];
        $appUrl = config('app.url');

        if (is_string($appUrl)) {
            $appHost = parse_url($appUrl, PHP_URL_HOST);

            if (is_string($appHost) && $appHost !== '') {
                $hosts[] = strtolower($appHost);
            }
        }

        $configured = config('gatekeep.redirect.allowed_hosts', []);

        if (is_array($configured)) {
            foreach ($configured as $configuredHost) {
                if (is_string($configuredHost) && $configuredHost !== '') {
                    $hosts[] = strtolower($configuredHost);
                }
            }
        }

        return array_values(array_unique($hosts));
    }
}
