<?php

declare(strict_types=1);

namespace Gatekeep\Metadata;

use Gatekeep\Contracts\HostResolver;
use Gatekeep\Exceptions\MetadataImportException;

/**
 * Rejects metadata URLs that are not HTTPS or that resolve to a non-public address.
 *
 * Blocked ranges are loopback, private, link-local (including 169.254.169.254),
 * and IPv6 unique-local. A name that resolves to any blocked address is rejected.
 */
final class MetadataUrlGuard
{
    public function __construct(private readonly HostResolver $hosts) {}

    public function assertFetchable(string $url): void
    {
        $this->addresses($url);
    }

    /**
     * Public addresses for one HTTPS URL. Resolves the host a single time.
     *
     * @return list<string>
     */
    public function addresses(string $url): array
    {
        $addresses = $this->hosts->addresses($this->host($url));

        if ($addresses === []) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        foreach ($addresses as $address) {
            if ($this->isBlocked($address)) {
                throw new MetadataImportException('The metadata URL is not allowed.');
            }
        }

        return $addresses;
    }

    public function host(string $url): string
    {
        $url = trim($url);

        if ($url === '' || preg_match('/[\s\\\\]/', $url) === 1) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        $parts = parse_url($url);

        if (! is_array($parts)) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        $scheme = $parts['scheme'] ?? null;
        $host = $parts['host'] ?? null;

        if (! is_string($scheme) || strtolower($scheme) !== 'https' || ! is_string($host) || $host === '') {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }

        if ($host === '' || str_contains($host, '%')) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        $this->assertHostShape($host);

        return $host;
    }

    public function port(string $url): int
    {
        $parts = parse_url(trim($url));
        $port = is_array($parts) ? ($parts['port'] ?? null) : null;

        if (is_int($port)) {
            return $port;
        }

        return 443;
    }

    private function assertHostShape(string $host): void
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return;
        }

        if (in_array(strtolower($host), ['localhost', 'localhost.localdomain'], true)) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        if (preg_match('/[a-z]/i', $host) !== 1) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }

        if (preg_match('/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i', $host) !== 1) {
            throw new MetadataImportException('The metadata URL is not allowed.');
        }
    }

    private function isBlocked(string $address): bool
    {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $number = $this->ipv4Number($address);

            return $number === null || $this->ipv4Blocked($number);
        }

        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $this->ipv6Blocked($address);
        }

        return true;
    }

    private function ipv4Blocked(int $ip): bool
    {
        return $this->inCidr($ip, '0.0.0.0', 8)
            || $this->inCidr($ip, '10.0.0.0', 8)
            || $this->inCidr($ip, '127.0.0.0', 8)
            || $this->inCidr($ip, '169.254.0.0', 16)
            || $this->inCidr($ip, '172.16.0.0', 12)
            || $this->inCidr($ip, '192.168.0.0', 16);
    }

    private function ipv6Blocked(string $address): bool
    {
        $packed = inet_pton($address);

        if ($packed === false || strlen($packed) !== 16) {
            return true;
        }

        $mapped = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";

        if (str_starts_with($packed, $mapped)) {
            $ipv4 = inet_ntop(substr($packed, 12));

            if (! is_string($ipv4)) {
                return true;
            }

            $number = $this->ipv4Number($ipv4);

            return $number === null || $this->ipv4Blocked($number);
        }

        if ($packed === inet_pton('::') || $packed === inet_pton('::1')) {
            return true;
        }

        $first = ord($packed[0]);
        $second = ord($packed[1]);

        if (($first & 0xFE) === 0xFC) {
            return true;
        }

        return $first === 0xFE && ($second & 0xC0) === 0x80;
    }

    private function inCidr(int $ip, string $network, int $bits): bool
    {
        $base = $this->ipv4Number($network);

        if ($base === null) {
            return true;
        }

        $mask = $this->mask($bits);

        return ($ip & $mask) === ($base & $mask);
    }

    private function mask(int $bits): int
    {
        if ($bits <= 0) {
            return 0;
        }

        if ($bits >= 32) {
            return 0xFFFFFFFF;
        }

        return (~((1 << (32 - $bits)) - 1)) & 0xFFFFFFFF;
    }

    private function ipv4Number(string $ip): ?int
    {
        $packed = inet_pton($ip);

        if ($packed === false || strlen($packed) !== 4) {
            return null;
        }

        $unpacked = unpack('N', $packed);

        if ($unpacked === false || ! isset($unpacked[1]) || ! is_int($unpacked[1])) {
            return null;
        }

        return $unpacked[1];
    }
}
