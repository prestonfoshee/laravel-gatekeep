<?php

declare(strict_types=1);

namespace Gatekeep\Console;

use Gatekeep\Certificates\SpCertificateRotator;
use Gatekeep\Exceptions\CertificateRotationException;
use Illuminate\Console\Command;

final class GenerateSpCertificateCommand extends Command
{
    protected $signature = 'gatekeep:sp-cert:generate {connection? : Connection id, or omit for the global certificate}';

    protected $description = 'Generate the next service-provider signing certificate.';

    public function handle(SpCertificateRotator $rotator): int
    {
        try {
            $certificate = $rotator->generate($this->connectionId());
        } catch (CertificateRotationException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $scope = $certificate->sso_connection_id ?? 'global';
        $this->info('Generated next certificate '.$certificate->id.' for '.$scope.'.');

        return self::SUCCESS;
    }

    private function connectionId(): ?string
    {
        $argument = $this->argument('connection');

        return is_string($argument) && $argument !== '' ? $argument : null;
    }
}
