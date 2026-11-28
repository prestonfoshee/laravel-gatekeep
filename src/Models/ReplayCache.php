<?php

declare(strict_types=1);

namespace Gatekeep\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;

/**
 * One consumed SAML message id. The primary key is sha256(connectionId|messageId).
 *
 * @property string $key
 * @property CarbonImmutable $expires_at
 */
final class ReplayCache extends Model
{
    public $timestamps = false;

    public $incrementing = false;

    protected $table = 'sso_replay_cache';

    protected $primaryKey = 'key';

    protected $keyType = 'string';

    protected $fillable = [
        'key',
        'expires_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'immutable_datetime',
        ];
    }
}
