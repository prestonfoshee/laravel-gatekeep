<?php

declare(strict_types=1);

use Gatekeep\Contracts\ConnectionRepository;
use Gatekeep\Contracts\ProtocolDriver;
use Gatekeep\Contracts\ReplayGuard;
use Gatekeep\Contracts\TenantResolver;
use Gatekeep\DriverManager;
use Gatekeep\Exceptions\SsoException;
use Gatekeep\Facades\Gatekeep as GatekeepFacade;
use Gatekeep\Gatekeep;
use Gatekeep\GatekeepServiceProvider;
use Illuminate\Database\Eloquent\Model;

arch()->expect('Gatekeep')->toUseStrictTypes();

arch('debugging functions are not used')
    ->expect(['dd', 'dump'])
    ->not->toBeUsed();

arch('contracts are interfaces')
    ->expect('Gatekeep\Contracts')
    ->toBeInterfaces();

arch('models are final eloquent models')
    ->expect('Gatekeep\Models')
    ->toBeFinal()
    ->toExtend(Model::class);

arch('resolvers are final')
    ->expect('Gatekeep\Resolvers')
    ->toBeFinal()
    ->toImplement(TenantResolver::class);

arch('repositories are final')
    ->expect('Gatekeep\Repositories')
    ->toBeFinal()
    ->toImplement(ConnectionRepository::class);

arch('value objects are final readonly classes')
    ->expect('Gatekeep\ValueObjects')
    ->toBeFinal()
    ->toBeReadonly();

arch('support classes are final')
    ->expect('Gatekeep\Support')
    ->toBeFinal();

arch('enums are string backed')
    ->expect('Gatekeep\Enums')
    ->toBeStringBackedEnums();

arch('sso exceptions are final')
    ->expect('Gatekeep\Exceptions')
    ->toBeFinal()
    ->ignoring(SsoException::class);

arch('saml classes are final')
    ->expect('Gatekeep\Saml')
    ->toBeFinal();

arch('the saml driver implements the protocol contract')
    ->expect('Gatekeep\Saml\SamlDriver')
    ->toImplement(ProtocolDriver::class);

arch('replay guards are final')
    ->expect('Gatekeep\Replay')
    ->toBeFinal()
    ->toImplement(ReplayGuard::class);

arch('http classes are final')
    ->expect('Gatekeep\Http')
    ->toBeFinal();

arch('console commands are final')
    ->expect('Gatekeep\Console')
    ->toBeFinal();

arch('package entry points are final')
    ->expect([
        Gatekeep::class,
        DriverManager::class,
        GatekeepServiceProvider::class,
        GatekeepFacade::class,
    ])
    ->toBeFinal();
