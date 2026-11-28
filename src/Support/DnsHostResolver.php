<?php

declare(strict_types=1);

namespace Gatekeep\Support;

use Gatekeep\Contracts\HostResolver;

final class DnsHostResolver implements HostResolver
{
    public function addresses(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $records = dns_get_record($host, DNS_A + DNS_AAAA);

        if ($records === false) {
            return [];
        }

        $addresses = [];

        foreach ($records as $record) {
            if (isset($record['ip']) && is_string($record['ip']) && $record['ip'] !== '') {
                $addresses[] = $record['ip'];
            }

            if (isset($record['ipv6']) && is_string($record['ipv6']) && $record['ipv6'] !== '') {
                $addresses[] = $record['ipv6'];
            }
        }

        return $addresses;
    }
}
