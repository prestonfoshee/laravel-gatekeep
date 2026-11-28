<?php

declare(strict_types=1);

namespace Gatekeep\Console;

use Gatekeep\Certificates\SpCertificateRotator;
use Gatekeep\Exceptions\CertificateRotationException;
use Illuminate\Console\Command;

final class RetireSpCertificateCommand extends Command
{
    protected $signature = 'gatekeep:sp-cert:retire {connection? : Connection id, or omit for the global certificate}';

    protected $description = 'Mark retiring service-provider certificates as retired.';

    public function handle(SpCertificateRotator $rotator): int
    {
        try {
            $retired = $rotator->retire($this->connectionId());
        } catch (CertificateRotationException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info('Retired '.$retired.' certificate(s).');

        return self::SUCCESS;
    }

    private function connectionId(): ?string
    {
        $argument = $this->argument('connection');

        return is_string($argument) && $argument !== '' ? $argument : null;
    }
}
