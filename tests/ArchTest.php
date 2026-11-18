<?php

declare(strict_types=1);

arch()->expect('Gatekeep')->toUseStrictTypes();

arch('debugging functions are not used')
    ->expect(['dd', 'dump'])
    ->not->toBeUsed();
