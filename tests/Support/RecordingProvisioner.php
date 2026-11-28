<?php

declare(strict_types=1);

namespace Gatekeep\Tests\Support;

use Gatekeep\Contracts\UserProvisioner;
use Gatekeep\Models\SsoConnection;
use Gatekeep\Tests\Fixtures\User;
use Gatekeep\ValueObjects\SsoUser;
use Illuminate\Contracts\Auth\Authenticatable;

final class RecordingProvisioner implements UserProvisioner
{
    public ?SsoConnection $connection = null;

    public ?SsoUser $user = null;

    public function provision(SsoConnection $connection, SsoUser $user): Authenticatable
    {
        $this->connection = $connection;
        $this->user = $user;

        return User::query()->create([
            'email' => $user->email,
        ]);
    }
}
