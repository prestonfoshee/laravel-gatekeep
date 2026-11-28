<?php

declare(strict_types=1);

use Gatekeep\Contracts\HostResolver;
use Gatekeep\Enums\Protocol;
use Gatekeep\Events\IdpCertificateChanged;
use Gatekeep\Events\IdpMetadataRefreshed;
use Gatekeep\Tests\Support\StaticHostResolver;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Http::preventStrayRequests();
    app()->instance(HostResolver::class, new StaticHostResolver([
        'metadata.example.test' => ['1.1.1.1'],
        'bad.example.test' => ['8.8.8.8'],
        'good.example.test' => ['1.0.0.1'],
    ]));
});

it('refreshes saml connections that publish a metadata url', function () {
    Http::fake([
        'https://metadata.example.test/*' => Http::response(file_get_contents(dirname(__DIR__).'/fixtures/okta-metadata.xml')),
    ]);

    $withUrl = samlConnection([
        'name' => 'With URL',
        'domains' => ['with.example'],
        'metadata_url' => 'https://metadata.example.test/saml',
    ]);
    $without = samlConnection([
        'name' => 'Without URL',
        'domains' => ['without.example'],
    ]);
    $disabled = samlConnection([
        'name' => 'Disabled',
        'domains' => ['disabled.example'],
        'enabled' => false,
        'metadata_url' => 'https://metadata.example.test/disabled',
    ]);
    ssoConnection([
        'name' => 'Oidc',
        'domains' => ['oidc.example'],
        'protocol' => Protocol::Oidc,
        'metadata_url' => 'https://metadata.example.test/oidc',
    ]);

    Event::fake([IdpMetadataRefreshed::class, IdpCertificateChanged::class]);

    $this->artisan('gatekeep:refresh-metadata')
        ->expectsOutputToContain('Refreshed 2 identity provider metadata document(s).')
        ->assertSuccessful();

    expect($withUrl->fresh()->config['idp_entity_id'])->toBe('http://www.okta.com/exk1a2b3c4d5e6f7g8h9')
        ->and($withUrl->fresh()->metadata_url)->toBe('https://metadata.example.test/saml')
        ->and($withUrl->fresh()->metadata_refreshed_at)->not->toBeNull()
        ->and($disabled->fresh()->metadata_refreshed_at)->not->toBeNull()
        ->and($without->fresh()->metadata_refreshed_at)->toBeNull();

    Event::assertDispatched(IdpMetadataRefreshed::class, 2);
    Event::assertDispatched(IdpCertificateChanged::class, 2);

    $this->artisan('gatekeep:refresh-metadata')->assertSuccessful();

    Event::assertDispatched(IdpCertificateChanged::class, 2);
    Event::assertDispatched(IdpMetadataRefreshed::class, 4);
});

it('refreshes one connection when an id is given', function () {
    Http::fake([
        'https://metadata.example.test/*' => Http::response(file_get_contents(dirname(__DIR__).'/fixtures/entra-metadata.xml')),
    ]);
    $selected = samlConnection([
        'name' => 'Selected',
        'domains' => ['selected.example'],
        'metadata_url' => 'https://metadata.example.test/selected',
    ]);
    $other = samlConnection([
        'name' => 'Other',
        'domains' => ['other.example'],
        'metadata_url' => 'https://metadata.example.test/other',
    ]);

    $this->artisan('gatekeep:refresh-metadata', ['connection' => $selected->id])
        ->expectsOutputToContain('Refreshed 1 identity provider metadata document(s).')
        ->assertSuccessful();

    expect($selected->fresh()->metadata_refreshed_at)->not->toBeNull()
        ->and($other->fresh()->metadata_refreshed_at)->toBeNull();
});

it('keeps refreshing the remaining connections when one fetch fails', function () {
    Http::fake([
        'https://bad.example.test/*' => Http::response('BEGIN PRIVATE KEY samlp:Response', 500),
        'https://good.example.test/*' => Http::response(file_get_contents(dirname(__DIR__).'/fixtures/entra-metadata.xml')),
    ]);
    $bad = samlConnection([
        'name' => 'Bad',
        'domains' => ['bad.example'],
        'metadata_url' => 'https://bad.example.test/saml',
    ]);
    $good = samlConnection([
        'name' => 'Good',
        'domains' => ['good.example'],
        'metadata_url' => 'https://good.example.test/saml',
    ]);

    Event::fake([MessageLogged::class]);

    $this->artisan('gatekeep:refresh-metadata')
        ->expectsOutputToContain('Metadata refresh failed for connection '.$bad->id.'.')
        ->expectsOutputToContain('Refreshed 1 identity provider metadata document(s).')
        ->assertFailed();

    expect($good->fresh()->config['idp_entity_id'])->toBe('https://sts.windows.net/11111111-2222-3333-4444-555555555555/')
        ->and($bad->fresh()->metadata_refreshed_at)->toBeNull();

    Event::assertDispatched(MessageLogged::class, function (MessageLogged $event) use ($bad): bool {
        $encoded = json_encode($event);

        return $event->context === ['connection_id' => $bad->id]
            && is_string($encoded)
            && ! str_contains($encoded, 'BEGIN PRIVATE KEY')
            && ! str_contains($encoded, 'samlp:Response');
    });
});

it('schedules metadata refresh daily', function () {
    $event = scheduledRefresh();

    expect($event)->not->toBeNull()
        ->and($event->expression)->toBe('0 0 * * *');
});

it('schedules an hourly metadata refresh when configured', function () {
    config()->set('gatekeep.metadata_refresh.schedule', 'hourly');

    expect(scheduledRefresh()?->expression)->toBe('0 * * * *');
});

it('falls back to a daily metadata refresh for an unknown frequency', function () {
    config()->set('gatekeep.metadata_refresh.schedule', 'whenever');

    expect(scheduledRefresh()?->expression)->toBe('0 0 * * *');
});

it('does not schedule metadata refresh when it is disabled', function () {
    config()->set('gatekeep.metadata_refresh.enabled', false);

    $commands = collect(app(Schedule::class)->events())
        ->map(fn (object $event): string => property_exists($event, 'command') && is_string($event->command) ? $event->command : '')
        ->implode(' ');

    expect($commands)->not->toContain('gatekeep:refresh-metadata')
        ->and($commands)->toContain('gatekeep:prune');
});

function scheduledRefresh(): ?object
{
    foreach (app(Schedule::class)->events() as $event) {
        $command = property_exists($event, 'command') && is_string($event->command) ? $event->command : '';

        if (str_contains($command, 'gatekeep:refresh-metadata')) {
            return $event;
        }
    }

    return null;
}
