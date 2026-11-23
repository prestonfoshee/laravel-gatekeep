<?php

declare(strict_types=1);

namespace Gatekeep\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * Audit row for an SSO login attempt. The error code is safe to store; raw protocol payloads are not.
 *
 * @property int $id
 * @property string|null $sso_connection_id
 * @property string $status
 * @property string|null $error_code
 * @property string|null $ip
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
final class LoginAttempt extends Model
{
    protected $table = 'sso_login_attempts';

    protected $fillable = [
        'sso_connection_id',
        'status',
        'error_code',
        'ip',
    ];

    /**
     * @return BelongsTo<SsoConnection, $this>
     */
    public function connection(): BelongsTo
    {
        return $this->belongsTo(SsoConnection::class, 'sso_connection_id');
    }
}
