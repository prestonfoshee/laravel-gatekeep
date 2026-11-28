<?php

declare(strict_types=1);

namespace Gatekeep\Console;

use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\MetadataImportException;
use Gatekeep\Metadata\MetadataImporter;
use Gatekeep\Models\SsoConnection;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

final class RefreshMetadataCommand extends Command
{
    protected $signature = 'gatekeep:refresh-metadata {connection? : Only refresh this connection}';

    protected $description = 'Refresh identity-provider metadata for SAML connections that publish a metadata URL.';

    public function handle(MetadataImporter $importer): int
    {
        $refreshed = 0;
        $failed = 0;

        foreach ($this->connections() as $connection) {
            $url = $connection->metadata_url;

            if (! is_string($url) || trim($url) === '') {
                continue;
            }

            try {
                $importer->importFromUrl($connection, trim($url));
                $refreshed++;
            } catch (MetadataImportException) {
                $failed++;
                Log::warning('SSO metadata refresh failed.', [
                    'connection_id' => $connection->id,
                ]);
                $this->error('Metadata refresh failed for connection '.$connection->id.'.');
            }
        }

        $this->info('Refreshed '.$refreshed.' identity provider metadata document(s).');

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @return list<SsoConnection>
     */
    private function connections(): array
    {
        $query = SsoConnection::query()
            ->where('protocol', Protocol::Saml)
            ->whereNotNull('metadata_url')
            ->where('metadata_url', '!=', '')
            ->orderBy('id');

        $only = $this->argument('connection');

        if (is_string($only) && $only !== '') {
            $query->whereKey($only);
        }

        return array_values($query->get()->all());
    }
}
