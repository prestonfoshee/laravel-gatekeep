<?php

declare(strict_types=1);

namespace Gatekeep;

use Illuminate\Support\Manager;

final class DriverManager extends Manager
{
    public function getDefaultDriver(): string
    {
        return 'saml';
    }
}
