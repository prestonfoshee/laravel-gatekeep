<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sso_login_attempts', function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('sso_connection_id')->nullable()->constrained('sso_connections')->nullOnDelete();
            $table->string('status');
            $table->string('error_code')->nullable();
            $table->string('ip', 45)->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sso_login_attempts');
    }
};
