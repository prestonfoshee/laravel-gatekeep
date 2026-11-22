<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;

it('creates the gatekeep tables', function () {
    expect(Schema::getColumnListing('sso_connections'))->toBe([
        'id',
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
        'created_at',
        'updated_at',
    ])->and(Schema::getColumnListing('sso_connection_domains'))->toBe([
        'domain',
        'sso_connection_id',
        'verified_at',
    ])->and(Schema::getColumnListing('sso_identities'))->toBe([
        'id',
        'sso_connection_id',
        'subject',
        'user_type',
        'user_id',
        'last_login_at',
    ])->and(Schema::getColumnListing('sso_replay_cache'))->toBe([
        'key',
        'expires_at',
    ])->and(Schema::getColumnListing('sso_sp_certificates'))->toBe([
        'id',
        'sso_connection_id',
        'certificate',
        'private_key',
        'status',
        'not_after',
        'created_at',
        'updated_at',
    ])->and(Schema::getColumnListing('sso_login_attempts'))->toBe([
        'id',
        'sso_connection_id',
        'status',
        'error_code',
        'ip',
        'created_at',
        'updated_at',
    ]);
});
