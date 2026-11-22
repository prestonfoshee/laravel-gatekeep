<?php

declare(strict_types=1);

namespace Gatekeep\Models;

use Gatekeep\Enums\Protocol;
use Gatekeep\Exceptions\DuplicateDomainException;
use Gatekeep\Support\DomainNormalizer;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;

/**
 * An identity-provider connection owned by one tenant.
 *
 * `config` is encrypted at rest and omitted from array and JSON output.
 *
 * @property string $id
 * @property string $tenant_key
 * @property string $name
 * @property Protocol $protocol
 * @property bool $enabled
 * @property list<string> $domains
 * @property array<string, mixed> $config
 * @property array<string, mixed>|null $attribute_map
 * @property array<string, mixed>|null $provisioning
 * @property string|null $metadata_url
 * @property Carbon|null $metadata_refreshed_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
final class SsoConnection extends Model
{
    use HasUlids;

    protected $table = 'sso_connections';

    protected $hidden = [
        'config',
    ];

    protected $attributes = [
        'domains' => '[]',
    ];

    protected $fillable = [
        'tenant_key',
        'name',
        'protocol',
        'enabled',
        'domains',
        'config',
        'attribute_map',
        'provisioning',
        'metadata_url',
        'metadata_refreshed_at',
    ];

    protected static function booted(): void
    {
        self::saving(function (SsoConnection $connection): void {
            $connection->normalizeAndGuardDomains();
        });

        self::saved(function (SsoConnection $connection): void {
            $connection->syncDomains();
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'protocol' => Protocol::class,
            'enabled' => 'boolean',
            'domains' => 'array',
            'config' => 'encrypted:array',
            'attribute_map' => 'array',
            'provisioning' => 'array',
            'metadata_refreshed_at' => 'datetime',
        ];
    }

    /**
     * Keep the connection row and its domain index in one transaction.
     *
     * @param  array{touch?: bool|null}  $options
     */
    public function save(array $options = []): bool
    {
        return $this->getConnection()->transaction(fn (): bool => parent::save($options));
    }

    /**
     * @return HasMany<SsoConnectionDomain, $this>
     */
    public function connectionDomains(): HasMany
    {
        return $this->hasMany(SsoConnectionDomain::class, 'sso_connection_id');
    }

    /**
     * @return HasMany<SsoIdentity, $this>
     */
    public function identities(): HasMany
    {
        return $this->hasMany(SsoIdentity::class, 'sso_connection_id');
    }

    /**
     * @return HasMany<SpCertificate, $this>
     */
    public function certificates(): HasMany
    {
        return $this->hasMany(SpCertificate::class, 'sso_connection_id');
    }

    /**
     * @return HasMany<LoginAttempt, $this>
     */
    public function loginAttempts(): HasMany
    {
        return $this->hasMany(LoginAttempt::class, 'sso_connection_id');
    }

    private function normalizeAndGuardDomains(): void
    {
        $normalized = DomainNormalizer::normalizeMany($this->domains);
        $this->domains = $normalized;
        $this->assertDomainsAvailable($normalized);
    }

    /**
     * @param  list<string>  $domains
     */
    private function assertDomainsAvailable(array $domains): void
    {
        if ($domains === []) {
            return;
        }

        $query = SsoConnectionDomain::query()->whereIn('domain', $domains);

        if ($this->exists) {
            $query->where('sso_connection_id', '!=', $this->getKey());
        }

        $claimed = [];

        foreach ($query->pluck('domain') as $domain) {
            if (is_string($domain) && $domain !== '') {
                $claimed[] = $domain;
            }
        }

        if ($claimed !== []) {
            throw new DuplicateDomainException($claimed);
        }
    }

    private function syncDomains(): void
    {
        $normalized = $this->domains;

        if ($normalized === []) {
            $this->connectionDomains()->delete();

            return;
        }

        $this->connectionDomains()->whereNotIn('domain', $normalized)->delete();

        $owned = [];

        foreach ($this->connectionDomains()->pluck('domain') as $domain) {
            if (is_string($domain)) {
                $owned[] = $domain;
            }
        }

        foreach (array_diff($normalized, $owned) as $domain) {
            try {
                $this->connectionDomains()->create([
                    'domain' => $domain,
                ]);
            } catch (UniqueConstraintViolationException $exception) {
                throw new DuplicateDomainException([$domain], $exception);
            }
        }
    }
}
