<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sso_connections', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('tenant_key')->index();
            $table->string('name');
            $table->string('protocol');
            $table->boolean('enabled')->default(true);
            $table->json('domains');
            $table->text('config');
            $table->json('attribute_map')->nullable();
            $table->json('provisioning')->nullable();
            $table->string('metadata_url')->nullable();
            $table->timestamp('metadata_refreshed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sso_connections');
    }
};
