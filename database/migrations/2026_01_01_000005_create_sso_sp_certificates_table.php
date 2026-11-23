<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sso_sp_certificates', function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('sso_connection_id')->nullable()->constrained('sso_connections')->cascadeOnDelete();
            $table->text('certificate');
            $table->text('private_key');
            $table->string('status');
            $table->timestamp('not_after');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sso_sp_certificates');
    }
};
