<?php

declare(strict_types=1);

namespace Gatekeep\Console;

use Gatekeep\Certificates\SpCertificateRotator;
use Gatekeep\Exceptions\CertificateRotationException;
use Illuminate\Console\Command;

final class PromoteSpCertificateCommand extends Command
{
    protected $signature = 'gatekeep:sp-cert:promote {connection? : Connection id, or omit for the global certificate}';

    protected $description = 'Promote the next service-provider certificate and move the previous active certificate to retiring.';

    public function handle(SpCertificateRotator $rotator): int
    {
        try {
            $certificate = $rotator->promote($this->connectionId());
        } catch (CertificateRotationException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $scope = $certificate->sso_connection_id ?? 'global';
        $this->info('Promoted certificate '.$certificate->id.' to active for '.$scope.'.');

        return self::SUCCESS;
    }

    private function connectionId(): ?string
    {
        $argument = $this->argument('connection');

        return is_string($argument) && $argument !== '' ? $argument : null;
    }
}
