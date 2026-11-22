<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sso_identities', function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('sso_connection_id')->constrained('sso_connections')->cascadeOnDelete();
            $table->string('subject');
            $table->morphs('user');
            $table->timestamp('last_login_at')->nullable();
            $table->unique(['sso_connection_id', 'subject']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sso_identities');
    }
};
