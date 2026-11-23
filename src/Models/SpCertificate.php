<?php

declare(strict_types=1);

namespace Gatekeep\Models;

use Gatekeep\Enums\CertificateStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * Service-provider signing certificate.
 *
 * `private_key` is encrypted at rest and omitted from array and JSON output.
 * A null connection id is the global certificate.
 *
 * @property int $id
 * @property string|null $sso_connection_id
 * @property string $certificate
 * @property string $private_key
 * @property CertificateStatus $status
 * @property Carbon $not_after
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
final class SpCertificate extends Model
{
    protected $table = 'sso_sp_certificates';

    protected $hidden = [
        'private_key',
    ];

    protected $fillable = [
        'sso_connection_id',
        'certificate',
        'private_key',
        'status',
        'not_after',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'private_key' => 'encrypted',
            'status' => CertificateStatus::class,
            'not_after' => 'datetime',
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
