<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sso_connection_domains', function (Blueprint $table): void {
            $table->string('domain')->primary();
            $table->foreignUlid('sso_connection_id')->constrained('sso_connections')->cascadeOnDelete();
            $table->timestamp('verified_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sso_connection_domains');
    }
};
