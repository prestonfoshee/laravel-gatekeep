<?php

declare(strict_types=1);

namespace Gatekeep\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * Unique domain lookup row for an SSO connection.
 *
 * @property string $domain
 * @property string $sso_connection_id
 * @property Carbon|null $verified_at
 */
final class SsoConnectionDomain extends Model
{
    public $incrementing = false;

    public $timestamps = false;

    protected $table = 'sso_connection_domains';

    protected $primaryKey = 'domain';

    protected $keyType = 'string';

    protected $fillable = [
        'domain',
        'sso_connection_id',
        'verified_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'verified_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<SsoConnection, $this>
     */
    public function connection(): BelongsTo
    {
        return $this->belongsTo(SsoConnection::class, 'sso_connection_id');
    }
}
