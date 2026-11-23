<?php

declare(strict_types=1);

namespace Gatekeep\Contracts;

use Gatekeep\Models\SsoConnection;
use Gatekeep\ValueObjects\SsoUser;
use Illuminate\Contracts\Auth\Authenticatable;

interface UserProvisioner
{
    public function provision(SsoConnection $connection, SsoUser $user): Authenticatable;
}
