<?php

declare(strict_types=1);

namespace Gatekeep\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;

/**
 * Link from an IdP subject to a local user.
 *
 * @property int $id
 * @property string $sso_connection_id
 * @property string $subject
 * @property string $user_type
 * @property int|string $user_id
 * @property Carbon|null $last_login_at
 */
final class SsoIdentity extends Model
{
    public $timestamps = false;

    protected $table = 'sso_identities';

    protected $fillable = [
        'sso_connection_id',
        'subject',
        'user_type',
        'user_id',
        'last_login_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'last_login_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<SsoConnection, $this>
     */
    public function connection(): BelongsTo
    {
        return $this->belongsTo(SsoConnection::class, 'sso_connection_id');
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function user(): MorphTo
    {
        return $this->morphTo();
    }
}
